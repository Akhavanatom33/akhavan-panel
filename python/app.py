#!/usr/bin/env python3
"""Akhavan Panel - Python backend (standard library only). Same API/behaviour as node/server.js."""
import copy
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import core
from core import ApiError

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.environ.get('DATA_DIR') or os.path.join(HERE, '..', 'data'))
WEB_DIR = os.path.abspath(os.environ.get('WEB_DIR') or os.path.join(HERE, '..', 'web'))
PORT = int(os.environ.get('PANEL_PORT') or 8443)
BIND = os.environ.get('PANEL_BIND') or '0.0.0.0'
TLS_MODE = (os.environ.get('PANEL_TLS') or 'auto').lower()
XRAY_BIN = os.environ.get('XRAY_BIN') or 'xray'
API_PORT = int(os.environ.get('XRAY_API_PORT') or 10085)
TRUST_PROXY = os.environ.get('TRUST_PROXY') == '1'

store = core.Store(DATA_DIR)
xray = core.XrayManager(XRAY_BIN, API_PORT, DATA_DIR)
state = None
tls_ctx = None
tls_on = False
cert_fingerprint = ''
lock = threading.RLock()
sessions = {}
fails = {}
DUMMY_HASH = core.hash_password('dummy-password-for-timing')

SEC_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
}
MIME = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
        '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon'}


# ---------- state helpers ----------
def collect_stats():
    delta = xray.stats_delta()
    changed = False
    for c in state['clients']:
        d = delta.get(c['id'])
        if d and (d['up'] or d['down']):
            c['up'] += d['up']
            c['down'] += d['down']
            changed = True
    if changed:
        store.save(state)


def commit(mutator):
    """Mutate a draft copy, validate with xray, then persist and apply."""
    global state
    with lock:
        collect_stats()
        draft = copy.deepcopy(state)
        result = mutator(draft)
        cfg = core.build_xray_config(draft, API_PORT)
        t = xray.test(cfg)
        if not t['ok']:
            raise ApiError(400, 'پیکربندی Xray نامعتبر است: %s' % t.get('error', ''))
        state = draft
        store.save(state)
        xray.apply(cfg)
        return result


def fetch_text(url, timeout=4):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read(200).decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def detect_public_ip():
    for u in ('https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com'):
        t = fetch_text(u)
        if re.match(r'^[0-9a-fA-F.:]{3,45}$', t):
            return t
    return ''


def url_host(h):
    return '[%s]' % h if (':' in h and not h.startswith('[')) else h


def bootstrap():
    global state
    if store.exists():
        state = store.load()
        return False, None
    username = str(os.environ.get('ADMIN_USER') or 'admin')[:40]
    password = os.environ.get('ADMIN_PASS') or core.rand_alnum(16)
    env_path = re.sub(r'[^A-Za-z0-9_-]', '', str(os.environ.get('PANEL_PATH') or ''))
    panel_path = '/' + (env_path if len(env_path) >= 4 else 'p-' + core.rand_alnum(10))
    host = os.environ.get('PUBLIC_HOST') or detect_public_ip() or 'YOUR_SERVER_IP'
    state = {
        'version': 1,
        'admin': {'username': username, 'hash': core.hash_password(password)},
        'panel': {'path': panel_path},
        'settings': {'host': host, 'extraLinks': []},
        'inbounds': [],
        'clients': [],
    }
    if xray.available:
        state['inbounds'].append(core.new_inbound(XRAY_BIN, {
            'name': os.environ.get('SERVER_NAME') or 'Akhavan',
            'port': os.environ.get('REALITY_PORT') or 443,
            'sni': os.environ.get('REALITY_SNI') or 'www.microsoft.com',
            'country': os.environ.get('COUNTRY') or '',
        }))
    state['clients'].append(core.new_client('default'))
    store.save(state)
    return True, password


# ---------- TLS ----------
def is_ipv4(s):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s) is not None


def generate_self_signed(directory, host):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    san = ['DNS:localhost', 'IP:127.0.0.1']
    if is_ipv4(host):
        san.append('IP:%s' % host)
    elif re.match(r'^[A-Za-z0-9.-]+$', host):
        san.append('DNS:%s' % host)
    key = os.path.join(directory, 'key.pem')
    cert = os.path.join(directory, 'cert.pem')
    r = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-keyout', key, '-out', cert, '-days', '3650', '-subj', '/CN=akhavan-panel',
                        '-addext', 'subjectAltName=' + ','.join(san)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl failed: %s' % r.stderr)
    os.chmod(key, 0o600)


def load_tls():
    global cert_fingerprint
    if TLS_MODE == 'off':
        return None
    cert_path = os.environ.get('TLS_CERT')
    key_path = os.environ.get('TLS_KEY')
    if not (cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path)):
        d = os.path.join(DATA_DIR, 'tls')
        cert_path = os.path.join(d, 'cert.pem')
        key_path = os.path.join(d, 'key.pem')
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            generate_self_signed(d, state['settings']['host'])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    with open(cert_path, 'r') as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    h = hashlib.sha256(der).hexdigest().upper()
    cert_fingerprint = ':'.join(h[i:i + 2] for i in range(0, len(h), 2))
    return ctx


# ---------- auth helpers ----------
def parse_cookies(header):
    out = {}
    for part in (header or '').split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def safe_equal(a, b):
    return hmac.compare_digest(hashlib.sha256(str(a).encode()).digest(), hashlib.sha256(str(b).encode()).digest())


# ---------- views ----------
def view():
    s = state
    scheme = 'https' if tls_on else 'http'
    base = '%s://%s:%d%s' % (scheme, url_host(s['settings']['host']), PORT, s['panel']['path'])
    return {
        'ok': True,
        'panel': {'version': core.VERSION, 'backend': 'python', 'tls': tls_on, 'certFingerprint': cert_fingerprint,
                  'port': PORT, 'path': s['panel']['path']},
        'xray': xray.status(),
        'settings': {'host': s['settings']['host'], 'extraLinks': s['settings']['extraLinks']},
        'inbounds': [{k: v for k, v in i.items() if k != 'privateKey'} for i in s['inbounds']],
        'clients': [{
            'id': c['id'], 'name': c['name'], 'uuid': c['uuid'], 'enabled': c['enabled'], 'createdAt': c['createdAt'],
            'up': c['up'], 'down': c['down'], 'subUrl': '%s/sub/%s' % (base, c['sub']), 'links': core.client_links(s, c),
        } for c in s['clients']],
    }


def find_client(d, cid):
    for c in d['clients']:
        if c['id'] == cid:
            return c
    raise ApiError(404, 'کانفیگ پیدا نشد.')


def find_inbound(d, iid):
    for i in d['inbounds']:
        if i['id'] == iid:
            return i
    raise ApiError(404, 'سرور پیدا نشد.')


def check_port_free(d, port, except_id=None):
    if port == PORT or port == API_PORT:
        raise ApiError(400, 'این پورت برای خود پنل رزرو است.')
    if any(i['port'] == port and i['id'] != except_id for i in d['inbounds']):
        raise ApiError(400, 'این پورت قبلاً استفاده شده است.')


def check_dest(dest):
    m = re.match(r'^([A-Za-z0-9.-]+):(\d{1,5})$', str(dest or '').strip())
    if not m:
        return {'ok': False, 'error': 'فرمت host:port نامعتبر است.'}
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((m.group(1), int(m.group(2))), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=m.group(1)) as s:
                return {'ok': True, 'tls13': s.version() == 'TLSv1.3', 'h2': s.selected_alpn_protocol() == 'h2',
                        'ms': int((time.time() - t0) * 1000)}
    except socket.timeout:
        return {'ok': False, 'error': 'timeout'}
    except (OSError, ssl.SSLError) as e:
        return {'ok': False, 'error': getattr(e, 'strerror', None) or e.__class__.__name__}


# ---------- request handler ----------
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'akhavan'
    sys_version = ''

    def setup(self):
        self.request.settimeout(20)
        if tls_ctx is not None:
            self.request = tls_ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def log_message(self, fmt, *args):  # keep logs quiet (no URLs with tokens)
        pass

    # --- response helpers ---
    def send_out(self, status, body='', headers=None, ctype='text/plain; charset=utf-8'):
        if isinstance(body, (dict, list)):
            payload = json.dumps(body, ensure_ascii=False).encode('utf-8')
            ctype = 'application/json; charset=utf-8'
        elif isinstance(body, bytes):
            payload = body
        else:
            payload = str(body).encode('utf-8')
        self.send_response(status)
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(payload)

    def client_ip(self):
        if TRUST_PROXY:
            xf = (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
            if xf:
                return xf
        return self.client_address[0]

    def read_body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 65536:
            raise ApiError(413, 'درخواست خیلی بزرگ است.')
        if n == 0:
            return {}
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise ApiError(400, 'JSON نامعتبر است.')
        if not isinstance(data, dict):
            raise ApiError(400, 'JSON نامعتبر است.')
        return data

    def is_authed(self):
        sid = parse_cookies(self.headers.get('Cookie')).get('akh')
        exp = sessions.get(sid) if sid else None
        if not exp:
            return False
        if exp < time.time():
            sessions.pop(sid, None)
            return False
        return True

    # --- dispatch ---
    def do_GET(self): self.dispatch()
    def do_HEAD(self): self.dispatch()
    def do_POST(self): self.dispatch()
    def do_PUT(self): self.dispatch()
    def do_PATCH(self): self.dispatch()
    def do_DELETE(self): self.dispatch()

    def dispatch(self):
        try:
            p = urlparse(self.path).path
            base = state['panel']['path']
            if p != base and not p.startswith(base + '/'):
                return self.send_out(404, '')
            rel = p[len(base):]
            if rel == '':
                self.send_response(301)
                self.send_header('Location', base + '/')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return None
            if rel.startswith('/api/'):
                body = {} if self.command in ('GET', 'HEAD') else self.read_body()
                return self.api(rel, body)
            m = re.match(r'^/sub/([A-Za-z0-9]{10,64})$', rel)
            if m and self.command == 'GET':
                return self.handle_sub(m.group(1))
            if self.command not in ('GET', 'HEAD'):
                return self.send_out(405, '')
            return self.serve_static(rel)
        except ApiError as e:
            return self.send_out(e.status, {'ok': False, 'error': e.message})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, socket.timeout):
            return None
        except Exception as e:  # noqa: BLE001
            print('[panel] error:', repr(e), file=sys.stderr)
            return self.send_out(500, {'ok': False, 'error': 'خطای داخلی سرور.'})

    def serve_static(self, rel):
        name = 'index.html' if rel in ('', '/') else rel.lstrip('/')
        file = os.path.realpath(os.path.join(WEB_DIR, name))
        if not file.startswith(WEB_DIR + os.sep) or not os.path.isfile(file):
            return self.send_out(404, '')
        ext = os.path.splitext(file)[1].lower()
        with open(file, 'rb') as f:
            data = f.read()
        cache = 'no-cache' if ext == '.html' else 'public, max-age=3600'
        return self.send_out(200, data, {'Cache-Control': cache}, MIME.get(ext) or mimetypes.guess_type(file)[0] or 'application/octet-stream')

    def handle_sub(self, token):
        c = next((x for x in state['clients'] if safe_equal(x['sub'], token)), None)
        if not c:
            return self.send_out(404, '')
        if not c['enabled']:
            return self.send_out(403, 'disabled')
        return self.send_out(200, core.subscription_body(state, c), {
            'Profile-Update-Interval': '6',
            'Subscription-Userinfo': 'upload=%d; download=%d; total=0; expire=0' % (c['up'], c['down']),
        })

    # --- API ---
    def api(self, rel, body):
        global state
        method = self.command
        if method not in ('GET', 'HEAD') and self.headers.get('X-Akh') != '1':
            raise ApiError(403, 'درخواست نامعتبر است.')
        secure = '; Secure' if tls_on else ''
        base = state['panel']['path']

        if rel == '/api/login' and method == 'POST':
            ip = self.client_ip()
            f = fails.get(ip)
            if f and f['until'] > time.time():
                raise ApiError(429, 'تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کن.')
            ok_user = safe_equal(body.get('username') or '', state['admin']['username'])
            ok_pass = core.verify_password(str(body.get('password') or ''), state['admin']['hash'] if ok_user else DUMMY_HASH)
            if not (ok_user and ok_pass):
                e = fails.setdefault(ip, {'n': 0, 'until': 0})
                e['n'] += 1
                if e['n'] >= 5:
                    e['until'] = time.time() + 15 * 60
                    e['n'] = 0
                time.sleep(0.5)
                raise ApiError(401, 'نام کاربری یا رمز اشتباه است.')
            fails.pop(ip, None)
            sid = secrets.token_hex(32)
            sessions[sid] = time.time() + 12 * 3600
            return self.send_out(200, {'ok': True}, {
                'Set-Cookie': 'akh=%s; Path=%s/; HttpOnly; SameSite=Strict; Max-Age=43200%s' % (sid, base, secure)})
        if rel == '/api/logout' and method == 'POST':
            sessions.pop(parse_cookies(self.headers.get('Cookie')).get('akh'), None)
            return self.send_out(200, {'ok': True}, {'Set-Cookie': 'akh=; Path=%s/; HttpOnly; SameSite=Strict; Max-Age=0' % base})
        if not self.is_authed():
            raise ApiError(401, 'ابتدا وارد شوید.')

        if rel == '/api/state' and method == 'GET':
            with lock:
                return self.send_out(200, view())

        # ----- clients -----
        if rel == '/api/clients' and method == 'POST':
            def add(d):
                if len(d['clients']) >= 200:
                    raise ApiError(400, 'حداکثر ۲۰۰ کانفیگ مجاز است.')
                d['clients'].append(core.new_client(body.get('name')))
            commit(add)
            return self.send_view()
        m = re.match(r'^/api/clients/([A-Za-z0-9]+)(?:/(regen-uuid|regen-sub))?$', rel)
        if m:
            cid, action = m.group(1), m.group(2)
            if method == 'PATCH' and not action:
                def patch(d):
                    c = find_client(d, cid)
                    if 'name' in body:
                        c['name'] = core.clean_name(body['name'], 'نام کانفیگ')
                    if 'enabled' in body:
                        c['enabled'] = bool(body['enabled'])
                commit(patch)
                return self.send_view()
            if method == 'POST' and action == 'regen-uuid':
                commit(lambda d: find_client(d, cid).__setitem__('uuid', str(core.uuidlib.uuid4())))
                return self.send_view()
            if method == 'POST' and action == 'regen-sub':
                commit(lambda d: find_client(d, cid).__setitem__('sub', core.rand_alnum(24)))
                return self.send_view()
            if method == 'DELETE' and not action:
                def delete(d):
                    find_client(d, cid)
                    d['clients'] = [c for c in d['clients'] if c['id'] != cid]
                commit(delete)
                return self.send_view()

        # ----- inbounds -----
        if rel == '/api/inbounds' and method == 'POST':
            def add_ib(d):
                if len(d['inbounds']) >= 20:
                    raise ApiError(400, 'حداکثر ۲۰ سرور مجاز است.')
                ib = core.new_inbound(XRAY_BIN, body)
                check_port_free(d, ib['port'])
                d['inbounds'].append(ib)
            commit(add_ib)
            return self.send_view()
        m = re.match(r'^/api/inbounds/([a-f0-9]+)(?:/(regen-keys))?$', rel)
        if m:
            iid, action = m.group(1), m.group(2)
            if method == 'PATCH' and not action:
                def patch_ib(d):
                    ib = find_inbound(d, iid)
                    if 'name' in body:
                        ib['name'] = core.clean_name(body['name'], 'نام سرور')
                    if 'enabled' in body:
                        ib['enabled'] = bool(body['enabled'])
                    if 'country' in body:
                        ib['country'] = core.clean_country(body['country'])
                    if 'fp' in body:
                        ib['fp'] = core.clean_fp(body['fp'])
                    if 'port' in body:
                        ib['port'] = core.clean_port(body['port'])
                        check_port_free(d, ib['port'], iid)
                    if 'sni' in body:
                        ib['sni'] = core.clean_sni(body['sni'])
                        ib['dest'] = core.clean_dest(body.get('dest'), ib['sni'])
                    elif 'dest' in body:
                        ib['dest'] = core.clean_dest(body['dest'], ib['sni'])
                commit(patch_ib)
                return self.send_view()
            if method == 'POST' and action == 'regen-keys':
                def regen(d):
                    ib = find_inbound(d, iid)
                    k = core.gen_reality_keys(XRAY_BIN)
                    ib['privateKey'] = k['privateKey']
                    ib['publicKey'] = k['publicKey']
                    ib['shortId'] = core.rid(8)
                commit(regen)
                return self.send_view()
            if method == 'DELETE' and not action:
                def del_ib(d):
                    find_inbound(d, iid)
                    d['inbounds'] = [i for i in d['inbounds'] if i['id'] != iid]
                commit(del_ib)
                return self.send_view()
        if rel == '/api/check-dest' and method == 'POST':
            return self.send_out(200, check_dest(body.get('dest')))

        # ----- settings -----
        if rel == '/api/settings' and method == 'PUT':
            def put(d):
                if 'host' in body:
                    d['settings']['host'] = core.clean_host(body['host'])
                if 'extraLinks' in body:
                    d['settings']['extraLinks'] = core.clean_extra_links(body['extraLinks'])
            commit(put)
            return self.send_view()
        if rel == '/api/password' and method == 'POST':
            if not core.verify_password(str(body.get('current') or ''), state['admin']['hash']):
                raise ApiError(400, 'رمز فعلی اشتباه است.')
            nxt = str(body.get('next') or '')
            if len(nxt) < 10 or len(nxt) > 128:
                raise ApiError(400, 'رمز جدید باید حداقل ۱۰ نویسه باشد.')
            commit(lambda d: d['admin'].__setitem__('hash', core.hash_password(nxt)))
            sessions.clear()
            return self.send_out(200, {'ok': True}, {'Set-Cookie': 'akh=; Path=%s/; HttpOnly; SameSite=Strict; Max-Age=0' % base})

        # ----- xray -----
        if rel == '/api/xray/restart' and method == 'POST':
            if not xray.available:
                raise ApiError(400, 'فایل xray پیدا نشد.')
            with lock:
                collect_stats()
                xray.restart()
            return self.send_view()
        if rel == '/api/xray/logs' and method == 'GET':
            return self.send_out(200, {'ok': True, 'logs': list(xray.logs)[-200:]})

        raise ApiError(404, 'یافت نشد.')

    def send_view(self):
        with lock:
            return self.send_out(200, view())


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        pass  # TLS handshake failures from scanners are expected


# ---------- main ----------
def print_banner(first, password):
    scheme = 'https' if tls_on else 'http'
    url = '%s://%s:%d%s/' % (scheme, url_host(state['settings']['host']), PORT, state['panel']['path'])
    lines = ['=' * 62, ' Akhavan Panel is running', ' Panel URL : %s' % url]
    if first:
        lines += [' Username  : %s' % state['admin']['username'], ' Password  : %s   (shown once - save it)' % password]
        links = core.client_links(state, state['clients'][0])
        if links:
            lines += ['', ' First config (also in the panel):', ' %s' % links[0]['url']]
        fd = os.open(os.path.join(DATA_DIR, 'CREDENTIALS.txt'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n\nDelete this file after saving the password.\n')
    else:
        lines.append(' (credentials were shown at first start; see data/CREDENTIALS.txt or run --reset-password)')
    if cert_fingerprint:
        lines.append(' TLS SHA-256 fingerprint: %s' % cert_fingerprint)
    lines.append('=' * 62)
    print('\n'.join(lines), flush=True)


def main():
    global state, tls_ctx, tls_on
    argv = sys.argv[1:]
    if argv and argv[0] == '--reset-password':
        if not store.exists():
            print('No state yet; start the panel once first.', file=sys.stderr)
            sys.exit(1)
        state = store.load()
        pw = argv[1] if len(argv) > 1 else core.rand_alnum(16)
        state['admin']['hash'] = core.hash_password(pw)
        store.save(state)
        print('New password for "%s": %s' % (state['admin']['username'], pw))
        return
    first, password = bootstrap()
    tls_ctx = load_tls()
    tls_on = tls_ctx is not None
    srv = PanelServer((BIND, PORT), Handler)
    if not tls_on and BIND not in ('127.0.0.1', 'localhost'):
        print('[panel] WARNING: TLS is off and the panel is not bound to localhost.', file=sys.stderr)
    xray.apply(core.build_xray_config(state, API_PORT))
    if not xray.available:
        print('[panel] WARNING: xray binary not found; only the panel is running.', file=sys.stderr)
    print_banner(first, password)

    def stats_loop():
        while True:
            time.sleep(20)
            try:
                with lock:
                    collect_stats()
            except Exception:  # noqa: BLE001
                pass
            now = time.time()
            for k in [k for k, v in sessions.items() if v < now]:
                sessions.pop(k, None)
    threading.Thread(target=stats_loop, daemon=True).start()

    def shutdown(*_):
        try:
            with lock:
                collect_stats()
        except Exception:  # noqa: BLE001
            pass
        xray.stop()
        os._exit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    srv.serve_forever()


if __name__ == '__main__':
    main()
