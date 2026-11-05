import os
import re
import base64
import sqlite3
import json
import secrets
import time
import copy
import concurrent.futures
import requests
import logging
from functools import wraps
from urllib.parse import urljoin
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import urllib3

# 禁用不安全请求警告（针对 verify=False）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Initialization & Logging ---
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration & Constants ---
APP_VERSION = "v1.0.45"
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-starlink-clone-key')
DATABASE = os.environ.get('DB_PATH', '/app/data/database.db')
REG_CODE = os.environ.get('REG_CODE', '888888')
BASE_URL = os.environ.get('BASE_URL', '').rstrip('/')
HTTP_TIMEOUT = 10
# 远端配置缓存（30 分钟），避免每次订阅请求都实时拉取上游
CONFIG_CACHE_TTL = int(os.environ.get('CONFIG_CACHE_TTL', 1800))
_config_cache = {}

# 服务端拉取上游时的身份：必须模拟 TVBox 客户端（okhttp）。
# 多数源站按 UA 区分流量——浏览器 UA 会收到 HTML/挑战页，okhttp 才返回纯 JSON 配置。
UA_TVBOX = 'okhttp/3.15.0'
UA_BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# 全局 HTTP 会话
http_session = requests.Session()
http_session.headers.update({'User-Agent': UA_TVBOX})

@app.errorhandler(Exception)
def handle_exception(e):
    """全局意外错误处理"""
    logger.error(f"Unhandled Exception: {str(e)}", exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': '服务器内部错误'}), 500
    return "系统异常，请稍后再试", 500

# --- Database Layer ---
def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """初始化数据库并建立索引"""
    with get_db() as db:
        # 用户表
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        
        # 接口数据表
        db.execute('''
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                type TEXT DEFAULT 'site',
                status TEXT DEFAULT 'unknown',
                order_index INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # 系统设置表
        db.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # 建立索引以提升大规模数据下的性能
        db.execute('CREATE INDEX IF NOT EXISTS idx_sources_user ON sources(user_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_sources_url ON sources(url)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_sources_order ON sources(order_index)')

        # 初始化默认配置
        db.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('invite_code', REG_CODE))
        db.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('webhook_token', secrets.token_hex(16)))
        
        db.commit()

# Ensure DB is initialized
init_db()

# --- Helpers & Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': '需要管理员权限'}), 403
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def jsonify_success(message='操作成功', **kwargs):
    return jsonify({'status': 'success', 'message': message, **kwargs})

def jsonify_error(message='操作失败', code=200):
    return jsonify({'status': 'error', 'message': message}), code

def _cache_put(url, kind, data):
    if len(_config_cache) > 500:
        _config_cache.clear()
    _config_cache[url] = (time.time() + CONFIG_CACHE_TTL, kind, data)
    return kind, data

# --- TVBox 配置拉取（宽松解析 + 图片伪装支持） ---
_JPEG_SOI = b'\xff\xd8\xff'
_PNG_SIG = b'\x89PNG\r\n\x1a\n'

def _loads_lenient(text):
    """宽松 JSON 解析：容忍 // 整行注释与尾随逗号（TVBox 生态配置常见写法）。
    返回解析结果，无法解析时返回 None。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    t = text
    if '//' in t:
        # 只剔除行首注释行（字符串内的 https:// 不受影响）
        t = '\n'.join([l for l in t.split('\n') if not l.strip().startswith('//')])
    for candidate in (t, re.sub(r',\s*(\}|\])', r'\1', t)):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None

def _extract_image_hidden(raw):
    """提取藏在图片文件尾部的 base64 JSON。

    TVBox 生态流行的伪装分发方式（如饭太硬）：JPEG/PNG 图片数据 + Base64 编码的
    配置 JSON 拼接存放。TVBox 客户端会识别，服务端拆包同样需要支持。
    """
    if raw[:3] == _JPEG_SOI:
        marker = raw.rfind(b'\xff\xd9')            # JPEG EOI
        tail = raw[marker + 2:] if marker >= 0 else b''
    elif raw[:8] == _PNG_SIG:
        marker = raw.rfind(b'IEND')                # PNG IEND 块（+4 字节 CRC）
        tail = raw[marker + 8:] if marker >= 0 else b''
    else:
        return None
    # 清洗干扰字符后按 base64 解码
    b64 = re.sub(rb'[^A-Za-z0-9+/=]', b'', tail)
    if len(b64) < 100:
        return None
    try:
        decoded = base64.b64decode(b64 + b'=' * (-len(b64) % 4), validate=False)
        text = decoded.decode('utf-8', errors='ignore')
    except Exception:
        return None
    pos = text.find('{')
    if pos < 0:
        return None
    return _loads_lenient(text[pos:])

def fetch_tv_config(url):
    """拉取远端配置并识别类型（带缓存）。

    返回 (kind, data):
      kind = 'multi'  多仓 JSON：{"urls": [...]}
             'single' 单仓 JSON：含 "sites" 数组
             'api'    合法 JSON 但非配置结构（大概率是 CMS vod 接口，可直接当 site api）
             'raw'    非 JSON（HTML/挑战页）/ 请求失败（data 恒为 None）

    兼容三种真实生态形态：纯 JSON、带 // 注释的 JSON、图片伪装（JPEG/PNG 尾藏 base64 JSON）。
    UA 策略：先以 TVBox 客户端身份（okhttp）请求——源站对浏览器 UA 常返回
    HTML/挑战页；若 okhttp 得到非 JSON，再用浏览器 UA 兜底一次。
    """
    hit = _config_cache.get(url)
    if hit and hit[0] > time.time():
        return hit[1], hit[2]

    for ua in (UA_TVBOX, UA_BROWSER):
        try:
            r = http_session.get(url, timeout=HTTP_TIMEOUT, verify=False, headers={'User-Agent': ua})
            if r.status_code != 200:
                continue  # 非 200 换 UA 再试（403 可能是 WAF 按 UA 拦截）
            raw = r.content
            # 强制 UTF-8 解码（utf-8-sig 兼容带 BOM 的响应）：
            # 上游源站响应头普遍不带 charset，requests 会退回 ISO-8859-1，
            # UTF-8 中文站点名被解码成乱码（JSON 结构仍是合法的，但 name 全花）
            content = raw.decode('utf-8-sig', errors='replace').strip()
            if content.startswith('//'):
                content = '\n'.join([l for l in content.split('\n') if not l.strip().startswith('//')])
            data = _loads_lenient(content)
            if data is None:
                # 图片伪装：JPEG/PNG 尾部藏 base64(JSON)
                data = _extract_image_hidden(raw)
            if data is None:
                continue  # 当前 UA 拿到的是 HTML/无隐藏内容的图片 → 换下一个 UA 重试
        except Exception:
            continue  # 连接异常 → 换 UA 重试一次

        if isinstance(data, dict):
            if isinstance(data.get('urls'), list) and data['urls']:
                return _cache_put(url, 'multi', data)
            if isinstance(data.get('sites'), list):
                return _cache_put(url, 'single', data)
            return _cache_put(url, 'api', data)
        return _cache_put(url, 'api', data)

    # 两种 UA 均失败：不缓存，避免上游抖动后被长时间记为坏源
    _config_cache.pop(url, None)
    return 'raw', None

@app.context_processor
def inject_version():
    return dict(version=APP_VERSION)

# --- Frontend Routes ---
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login')
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    is_admin = session.get('is_admin', False)
    host_url = BASE_URL if BASE_URL else request.host_url.rstrip('/')
    sub_url = host_url + url_for('get_tvbox_json', username=username)
    return render_template('dashboard.html', username=username, sub_url=sub_url, is_admin=is_admin)

@app.route('/admin')
@admin_required
def admin_dashboard():
    with get_db() as db:
        invite_code = db.execute("SELECT value FROM settings WHERE key = 'invite_code'").fetchone()['value']
        webhook_token = db.execute("SELECT value FROM settings WHERE key = 'webhook_token'").fetchone()['value']
    return render_template('admin.html', is_admin=True, invite_code=invite_code, webhook_token=webhook_token)

# --- Auth APIs ---
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    username, password, invite_code = data.get('username', '').strip(), data.get('password', ''), data.get('invite_code', '').strip()

    if not username or not password: return jsonify_error('用户名和密码不能为空')

    with get_db() as db:
        expected_code = db.execute("SELECT value FROM settings WHERE key = 'invite_code'").fetchone()['value']
        if invite_code != expected_code: return jsonify_error('邀请码错误')

        try:
            user_count = db.execute("SELECT COUNT(id) as c FROM users").fetchone()['c']
            is_admin = 1 if user_count == 0 else 0
            db.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', 
                       (username, generate_password_hash(password, method='pbkdf2:sha256'), is_admin))
            db.commit()
            return jsonify_success('注册成功')
        except sqlite3.IntegrityError:
            return jsonify_error('用户名已存在')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    username, password = data.get('username', '').strip(), data.get('password', '')

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
    if user and check_password_hash(user['password_hash'], password):
        session.update({'user_id': user['id'], 'username': user['username'], 'is_admin': user['is_admin'] == 1})
        return jsonify_success('登录成功')
    return jsonify_error('用户名或密码错误')

@app.route('/api/auth/logout')
def api_logout():
    session.clear()
    return redirect(url_for('login'))

# --- Source Management APIs ---
@app.route('/api/source/list')
@login_required
def api_source_list():
    with get_db() as db:
        sources = db.execute('SELECT * FROM sources WHERE user_id = ? ORDER BY order_index ASC, id ASC', (session['user_id'],)).fetchall()
        return jsonify_success(data=[dict(row) for row in sources])

@app.route('/api/source/add', methods=['POST'])
@login_required
def api_source_add():
    user_id = session['user_id']
    data = request.json
    name, url, stype = data.get('name', '').strip(), data.get('url', '').strip(), data.get('type', 'site')

    if not name or not url: return jsonify_error('名称和 URL 不能为空')

    # 1. 尝试作为多仓 JSON 解析（按响应内容判断，不再依赖 .json 后缀）
    kind, remote = fetch_tv_config(url)
    if kind == 'multi' and remote:
        added = 0
        with get_db() as db:
            existens = {row['url'] for row in db.execute('SELECT url FROM sources WHERE user_id = ?', (user_id,)).fetchall()}
            for entry in remote.get('urls', []):
                if not isinstance(entry, dict): continue
                e_url = str(entry.get('url') or '').strip()
                if e_url and e_url not in existens:
                    db.execute('INSERT INTO sources (user_id, name, url, type) VALUES (?, ?, ?, ?)', 
                               (user_id, entry.get('name', '未命名'), e_url, stype))
                    existens.add(e_url)
                    added += 1
            db.commit()
        return jsonify_success(f'成功导入 {added} 个聚合接口')

    # 2. 单个添加模式
    with get_db() as db:
        if db.execute('SELECT id FROM sources WHERE user_id = ? AND url = ?', (user_id, url)).fetchone():
            return jsonify_error('该接口已在您的列表中')
        db.execute('INSERT INTO sources (user_id, name, url, type) VALUES (?, ?, ?, ?)', (user_id, name, url, stype))
        db.commit()
    return jsonify_success('添加成功')

@app.route('/api/source/batch_add', methods=['POST'])
@login_required
def api_source_batch_add():
    user_id, items = session['user_id'], request.json.get('items', [])
    if not items: return jsonify_error('未选择任何接口')
    
    with get_db() as db:
        max_order = (db.execute('SELECT MAX(order_index) FROM sources WHERE user_id = ?', (user_id,)).fetchone()[0] or 0)
        for i, item in enumerate(items):
            link = item.get('link') or item.get('url')
            if link:
                db.execute('INSERT INTO sources (user_id, name, url, type, order_index) VALUES (?, ?, ?, ?, ?)', 
                           (user_id, item.get('name', '未命名'), link, 'site', max_order + i + 1))
        db.commit()
    return jsonify_success(f'成功批量添加 {len(items)} 个接口')

@app.route('/api/source/update', methods=['POST'])
@login_required
def api_source_update():
    data = request.json
    sid, name, url, stype = data.get('id'), data.get('name', '').strip(), data.get('url', '').strip(), data.get('type', 'site')
    if not sid or not name or not url: return jsonify_error('参数不全')

    with get_db() as db:
        db.execute('UPDATE sources SET name = ?, url = ?, type = ? WHERE id = ? AND user_id = ?', 
                   (name, url, stype, sid, session['user_id']))
        db.commit()
    return jsonify_success('保存成功')

@app.route('/api/source/delete', methods=['POST'])
@login_required
def api_source_delete():
    source_id = request.json.get('id')
    with get_db() as db:
        db.execute('DELETE FROM sources WHERE id = ? AND user_id = ?', (source_id, session['user_id']))
        db.commit()
    return jsonify_success('删除成功')

@app.route('/api/source/reorder', methods=['POST'])
@login_required
def api_source_reorder():
    order_data = request.json.get('order', [])
    with get_db() as db:
        for idx, sid in enumerate(order_data):
            db.execute('UPDATE sources SET order_index = ? WHERE id = ? AND user_id = ?', (idx, sid, session['user_id']))
        db.commit()
    return jsonify_success('排序已保存')

@app.route('/api/source/check', methods=['POST'])
@login_required
def api_source_check():
    url, sid = request.json.get('url'), request.json.get('id')
    if not url: return jsonify_error('URL missing')
    
    headers = {
        # 检测身份与 TVBox 客户端保持一致，避免源站对浏览器 UA 返回 HTML 导致误判 offline
        'User-Agent': UA_TVBOX
    }
    
    try:
        # 重归原生 requests.get 以提升对海量异构站点的兼容性，增加超时至 10s
        r = requests.get(url, timeout=10, stream=True, verify=False, headers=headers)
        r.close()
        status = 'online' if r.status_code < 400 else 'offline'
        if sid:
            with get_db() as db:
                db.execute('UPDATE sources SET status = ? WHERE id = ? AND user_id = ?', (status, sid, session['user_id']))
                db.commit()
        return jsonify_success(status_val=status, code=r.status_code)
    except Exception as e:
        logger.error(f"Check failed for {url}: {str(e)}")
        if sid:
            with get_db() as db:
                db.execute('UPDATE sources SET status = ? WHERE id = ? AND user_id = ?', ('offline', sid, session['user_id']))
                db.commit()
        return jsonify_error(str(e))

# --- Recommendation & External APIs ---
@app.route('/api/external/aipan')
@login_required
def api_external_aipan():
    combined_list = []
    # 1. 本地推荐 (Webhook 注入)
    for path in ['/app/data/recommended.json', 'data/recommended.json']:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    combined_list.extend(json.load(f).get('list', []))
            except: pass
            break
    
    # 2. 爱盼接口推荐（网页 API，需浏览器 UA）
    try:
        r = http_session.get('https://www.aipan.me/api/tvbox', timeout=5, verify=False, headers={'User-Agent': UA_BROWSER})
        if r.status_code == 200: combined_list.extend(r.json().get('list', []))
    except: pass

    # 3. 兜底列表（2026-08 实测可用；饭太硬已迁移到 .net 域名）
    if not combined_list:
        combined_list = [
            {"name": "🌟 饭太硬", "link": "http://www.饭太硬.net/tv"},
            {"name": "🐱 肥猫", "link": "http://肥猫.net/"},
            {"name": "🐟 摸鱼儿", "link": "http://摸鱼儿.cc"},
            {"name": "🚀 小盒子多仓", "link": "http://xhztv.top/dc"},
            {"name": "🎬 小盒子单仓", "link": "http://xhztv.top/xhz"},
            {"name": "🧓 老刘备", "link": "https://raw.liucn.cc/box/m.json"},
            {"name": "🐴 小马", "link": "https://szyyds.cn/tv/x.json"},
            {"name": "📦 VOX", "link": "http://rihou.cc:88/demo.php"},
        ]

    # 去重处理
    with get_db() as db:
        existens = {row['url'] for row in db.execute('SELECT url FROM sources WHERE user_id = ?', (session['user_id'],)).fetchall()}
    
    final_list, seen = [], set()
    for item in combined_list:
        link = item.get('link') or item.get('url')
        if link and link not in seen and link not in existens:
            final_list.append(item)
            seen.add(link)
    
    return jsonify_success(data=final_list[:40])

# --- Admin & Webhook APIs ---
@app.route('/api/admin/settings/code', methods=['POST'])
@admin_required
def api_admin_update_code():
    new_code = request.json.get('code', '').strip()
    if not new_code: return jsonify_error('不能为空')
    with get_db() as db:
        db.execute("UPDATE settings SET value = ? WHERE key = 'invite_code'", (new_code,))
        db.commit()
    return jsonify_success('已更新')

@app.route('/api/admin/settings/token', methods=['POST'])
@admin_required
def api_admin_update_token():
    new_token = secrets.token_hex(16)
    with get_db() as db:
        db.execute("UPDATE settings SET value = ? WHERE key = 'webhook_token'", (new_token,))
        db.commit()
    return jsonify_success('已重置', token=new_token)

@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    with get_db() as db:
        users = db.execute('''
            SELECT u.id, u.username, u.created_at, COUNT(s.id) as source_count
            FROM users u LEFT JOIN sources s ON u.id = s.user_id
            GROUP BY u.id ORDER BY u.id DESC
        ''').fetchall()
    return jsonify_success(data=[dict(row) for row in users])

@app.route('/api/admin/users/delete', methods=['POST'])
@admin_required
def api_admin_users_delete():
    uid = request.json.get('id')
    with get_db() as db:
        db.execute('DELETE FROM sources WHERE user_id = ?', (uid,))
        db.execute('DELETE FROM users WHERE id = ?', (uid,))
        db.commit()
    return jsonify_success('已删除')

@app.route('/api/admin/recommendations/push', methods=['POST'])
def api_admin_push_recommendations():
    data = request.json
    pwd = data.get('password') or data.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    with get_db() as db:
        expected = db.execute("SELECT value FROM settings WHERE key = 'webhook_token'").fetchone()['value']
    if not expected or pwd != expected: return jsonify_error('未授权', 401)
        
    items = data.get('list', [])
    normalized = []
    for it in items:
        link = it if isinstance(it, str) else (it.get('link') or it.get('url'))
        name = "推荐源" if isinstance(it, str) else it.get('name', '推荐源')
        if link: normalized.append({"name": name, "link": link})
    
    try:
        save_path = '/app/data/recommended.json' if os.path.exists('/app/data') else 'data/recommended.json'
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump({'list': normalized}, f, ensure_ascii=False)
        return jsonify_success(f'成功更新 {len(normalized)} 条推荐源')
    except Exception as e: return jsonify_error(str(e))

# --- TVBox Single-Config Builder ---
def _absolutize(cfg, base_url):
    """把仓内相对路径转为基于源仓地址的绝对 URL。

    TVBox 按配置文件地址解析相对路径（ext/jar/spider/wallpaper）。
    拆包合并后配置地址变成了本服务的订阅 URL，相对路径必然失效，必须转绝对。
    """
    if not base_url or not isinstance(cfg, dict):
        return cfg

    def fix(v):
        if isinstance(v, str) and v.startswith(('./', '../')):
            return urljoin(base_url, v)
        return v

    def fix_in(d, *keys):
        """仅当字段存在且为相对路径时改写，避免引入 null 字段"""
        for k in keys:
            v = d.get(k)
            if isinstance(v, str):
                d[k] = fix(v)

    # spider 支持 "jar路径;md5;加密key" 复合格式，只转路径段
    spider = cfg.get('spider')
    if isinstance(spider, str) and spider.split(';')[0].startswith(('./', '../')):
        parts = spider.split(';')
        parts[0] = urljoin(base_url, parts[0])
        cfg['spider'] = ';'.join(parts)

    fix_in(cfg, 'wallpaper')
    for site in (cfg.get('sites') or []):
        if not isinstance(site, dict):
            continue
        ext = site.get('ext')
        if isinstance(ext, str):
            site['ext'] = fix(ext)
        elif isinstance(ext, dict):
            fix_in(ext, 'jar', 'url')
        fix_in(site, 'jar', 'wallpaper')
    for live in (cfg.get('lives') or []):
        if isinstance(live, dict):
            fix_in(live, 'url')
    return cfg


def _build_single_config(sources):
    """把用户源列表构建为 TVBox 单仓配置。

    核心改进：
    1. 任何 URL 先拉取内容判断类型（多仓/单仓/裸接口），不再按后缀猜测；
    2. 拆包时透传 site 原有 type / ext / jar 等字段，不再统一强制 type:1；
    3. 仓级 spider 下沉为站点级 jar（多仓合并后爬虫源不丢 jar），同时保留全局 spider；
    4. 合并 lives / parses / wallpaper；
    5. 并发拉取上游 + 30 分钟缓存。
    """
    out = {'sites': [], 'lives': [], 'parses': [], 'wallpaper': ''}
    state = {'spider': '', 'seen_keys': set(), 'seen_apis': set(), 'seen_parses': set()}

    def add_site(site, fallback_name='', spider=''):
        if not isinstance(site, dict):
            return
        api = str(site.get('api') or site.get('url') or '').strip()
        if not api or api in state['seen_apis']:
            return
        state['seen_apis'].add(api)
        s = copy.deepcopy(site)
        key = s.get('key')
        if not isinstance(key, str) or not key or key in state['seen_keys']:
            key = f"s{len(out['sites'])}"
        s['key'] = key
        state['seen_keys'].add(key)
        if not s.get('name'):
            s['name'] = fallback_name or key
        if s.get('type') in (None, ''):
            s['type'] = 1
        # 爬虫/聚合类源依赖仓级 spider jar：合并多仓后统一下沉为站点级 jar，防止丢失
        if spider and not s.get('jar') and s.get('type') in (3, 4):
            s['jar'] = spider
        out['sites'].append(s)

    def add_live(live, fallback_name=''):
        if isinstance(live, dict) and str(live.get('url') or '').strip():
            l = copy.deepcopy(live)
            if not l.get('name'):
                l['name'] = fallback_name or 'live'
            if l.get('type') in (None, ''):
                l['type'] = 0
            out['lives'].append(l)

    def merge_config(cfg, fallback_name, base_url=''):
        """把一个单仓 dict 合并进输出（先把相对路径绝对化）"""
        cfg = _absolutize(cfg, base_url)
        spider = str(cfg.get('spider') or '').strip()
        if spider and not state['spider']:
            state['spider'] = spider
        for site in (cfg.get('sites') or []):
            add_site(site, fallback_name, spider)
        for live in (cfg.get('lives') or []):
            add_live(live, fallback_name)
        for p in (cfg.get('parses') or []):
            if isinstance(p, dict):
                pkey = str(p.get('url') or p.get('name') or '')
                if pkey and pkey not in state['seen_parses']:
                    state['seen_parses'].add(pkey)
                    out['parses'].append(copy.deepcopy(p))
        if not out['wallpaper'] and cfg.get('wallpaper'):
            out['wallpaper'] = cfg['wallpaper']

    def collect(url, name, depth, seen_urls):
        """递归收集：返回 True 表示该 URL 已按可用形式并入"""
        if not url or url in seen_urls:
            return True
        seen_urls.add(url)
        kind, data = fetch_tv_config(url)
        if kind == 'single':
            merge_config(data, name, url)
            return True
        if kind == 'multi' and depth < 2:
            entries = []
            for entry in (data.get('urls') or []):
                if isinstance(entry, dict):
                    e_url = str(entry.get('url') or '').strip()
                    e_name = str(entry.get('name') or '').strip() or name
                    if e_url:
                        entries.append((e_url, e_name))
            if entries:
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                    futures = [ex.submit(collect, u, n, depth + 1, seen_urls) for u, n in entries]
                    for f in futures:
                        f.result()
                return True
        if kind == 'api':
            # 合法 JSON 但非配置结构：大概率是 CMS vod 接口，直接作为站点 api 输出
            add_site({'api': url, 'name': name, 'type': 1}, name)
            return True
        # raw：HTML/挑战页/网络失败——输出壳地址 TVBox 也无法使用，跳过（宁缺毋滥）
        logger.warning(f"single 模式跳过不可解析的源: [{name}] {url}")
        return False

    site_rows = [r for r in sources if (r['type'] or 'site') == 'site']
    live_rows = [r for r in sources if (r['type'] or 'site') != 'site']

    # 并发拆包所有 site 类源（不可解析的源已在 collect 内跳过并记日志，不再输出壳地址）
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(collect, r['url'], r['name'], 0, set()): r['url'] for r in site_rows}
        for f in futures:
            f.result()

    # 用户自建的直播源：每组独立输出，格式更规范
    for r in live_rows:
        add_live({'url': r['url'], 'name': r['name'], 'type': 0, 'playerType': 1}, r['name'])

    config = {'sites': out['sites']}
    if out['lives']:
        config['lives'] = out['lives']
    if state['spider']:
        config['spider'] = state['spider']
    if out['parses']:
        config['parses'] = out['parses']
    if out['wallpaper']:
        config['wallpaper'] = out['wallpaper']
    return config

# --- Public Subscription API ---
@app.route('/api/subscribe/<username>.json')
def get_tvbox_json(username):
    etype, only_online = request.args.get('type', 'multi'), request.args.get('only_online') == 'true'

    with get_db() as db:
        user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            return jsonify_error('用户不存在', 404)
        sql = 'SELECT * FROM sources WHERE user_id = ?' + (' AND status = "online"' if only_online else '') + ' ORDER BY order_index ASC, id ASC'
        sources = db.execute(sql, (user['id'],)).fetchall()

    if etype == 'single':
        config = _build_single_config(sources)
    else:
        config = {"urls": [{"url": r['url'], "name": r['name']} for r in sources]}

    json_str = json.dumps(config, indent=4, ensure_ascii=False)
    if request.args.get('comment') == 'true':
        tag = "多仓" if etype == "multi" else "单仓"
        json_str = "//TVBox 专属配置 - " + tag + "\n" + json_str

    res = Response(json_str, mimetype='application/json; charset=utf-8')
    res.headers.add('Access-Control-Allow-Origin', '*')
    return res

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8089)
