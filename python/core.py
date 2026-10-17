"""Akhavan Panel - core logic (state, validation, Xray config, links, process manager).

Standard library only. Mirrors node/core.js: both backends read/write the same state.json
and generate the same Xray configuration, so you can switch between them.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid as uuidlib
from collections import deque

VERSION = '1.0.0'
FP_LIST = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized']
PRIVATE_CIDRS = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
]
EXTRA_SCHEMES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://')


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# ---------- helpers ----------
def rid(nbytes=4):
    return secrets.token_hex(nbytes)


def rand_alnum(n):
    alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def enc(v):
    # identical to JavaScript encodeURIComponent
    return urllib.parse.quote(str(v), safe="-_.!~*'()")


def hash_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return 'scrypt$16384$8$1$%s$%s' % (base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def verify_password(pw, stored):
    try:
        alg, n, r, p, salt, h = str(stored).split('$')
        if alg != 'scrypt':
            return False
        want = base64.b64decode(h)
        got = hashlib.scrypt(pw.encode('utf-8'), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got, want)
    except Exception:
        return False


# ---------- validation ----------
NAME_RE = re.compile(r'^[^\x00-\x1f\x7f]{1,40}$')
HOST_RE = re.compile(r'^[A-Za-z0-9.\-:\[\]]{1,253}$')
SNI_RE = re.compile(r'^(?=.{3,253}$)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$')
DEST_RE = re.compile(r'^([a-z0-9.-]+):(\d{1,5})$')


def clean_name(v, what='نام'):
    s = str('' if v is None else v).strip()
    if not NAME_RE.match(s):
        raise ApiError(400, '%s باید بین ۱ تا ۴۰ نویسه باشد.' % what)
    return s


def clean_port(v):
    try:
        if isinstance(v, bool):
            raise ValueError
        f = float(v)
        n = int(f)
        if f != n:
            raise ValueError
    except (TypeError, ValueError):
        raise ApiError(400, 'پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.')
    if n < 1 or n > 65535:
        raise ApiError(400, 'پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.')
    return n


def clean_sni(v):
    s = str('' if v is None else v).strip().lower()
    if not SNI_RE.match(s):
        raise ApiError(400, 'SNI نامعتبر است (مثلاً www.microsoft.com).')
    return s


def clean_dest(v, sni):
    s = str(v or ('%s:443' % sni)).strip().lower()
    m = DEST_RE.match(s)
    if not m or int(m.group(2)) < 1 or int(m.group(2)) > 65535:
        raise ApiError(400, 'مقصد (dest) باید به شکل host:port باشد.')
    return s


def clean_country(v):
    s = str('' if v is None else v).strip().upper()
    if s and not re.match(r'^[A-Z]{2}$', s):
        raise ApiError(400, 'کد کشور باید دو حرف باشد (مثلاً NL).')
    return s


def clean_fp(v):
    s = str(v or 'chrome').lower()
    if s not in FP_LIST:
        raise ApiError(400, 'fingerprint نامعتبر است.')
    return s


def clean_host(v):
    s = str('' if v is None else v).strip()
    if not HOST_RE.match(s):
        raise ApiError(400, 'آدرس سرور (IP یا دامنه) نامعتبر است.')
    return s


def clean_extra_links(v):
    if not isinstance(v, list):
        raise ApiError(400, 'لیست لینک‌ها نامعتبر است.')
    out = []
    for raw in v:
        s = str(raw or '').strip()
        if not s:
            continue
        if len(s) > 2000 or not s.lower().startswith(EXTRA_SCHEMES):
            raise ApiError(400, 'هر خط باید یک لینک معتبر باشد (vless://، vmess://، trojan:// ...).')
        out.append(s)
    if len(out) > 50:
        raise ApiError(400, 'حداکثر ۵۰ لینک اضافه مجاز است.')
    return out


# ---------- x25519 keys via the xray binary ----------
def gen_reality_keys(xray_bin):
    try:
        r = subprocess.run([xray_bin, 'x25519'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise ApiError(500, 'ساخت کلید Reality ناموفق بود (xray پیدا نشد؟).')
    if r.returncode != 0:
        raise ApiError(500, 'ساخت کلید Reality ناموفق بود (xray پیدا نشد؟).')
    priv = pub = ''
    for line in r.stdout.splitlines():
        m = re.match(r'^\s*([^:]+):\s*(\S+)\s*$', line)
        if not m:
            continue
        k = m.group(1).lower()
        if k.startswith('private'):
            priv = m.group(2)
        elif 'public' in k or k.startswith('password'):
            pub = m.group(2)
    if not priv or not pub:
        raise ApiError(500, 'خروجی xray x25519 قابل خواندن نبود.')
    return {'privateKey': priv, 'publicKey': pub}


# ---------- Xray config ----------
def build_xray_config(state, api_port):
    inbounds = [{
        'tag': 'api-in', 'listen': '127.0.0.1', 'port': api_port, 'protocol': 'dokodemo-door',
        'settings': {'address': '127.0.0.1'},
    }]
    active = [c for c in state['clients'] if c['enabled']]
    for ib in state['inbounds']:
        if not ib['enabled']:
            continue
        inbounds.append({
            'tag': 'in-%s' % ib['id'],
            'listen': '0.0.0.0',
            'port': ib['port'],
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': c['uuid'], 'email': c['id'], 'flow': 'xtls-rprx-vision', 'level': 0} for c in active],
                'decryption': 'none',
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'show': False, 'dest': ib['dest'], 'xver': 0, 'serverNames': [ib['sni']],
                    'privateKey': ib['privateKey'], 'shortIds': [ib['shortId']],
                },
            },
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True},
        })
    return {
        'log': {'loglevel': 'warning', 'access': 'none'},
        'stats': {},
        'dns': {'servers': ['localhost'], 'queryStrategy': 'UseIPv4'},
        'api': {'tag': 'api', 'services': ['StatsService']},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
        'inbounds': inbounds,
        'outbounds': [
            {'tag': 'direct', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
            {'tag': 'block', 'protocol': 'blackhole'},
        ],
        'routing': {
            'domainStrategy': 'IPIfNonMatch',
            'rules': [
                {'type': 'field', 'inboundTag': ['api-in'], 'outboundTag': 'api'},
                {'type': 'field', 'ip': PRIVATE_CIDRS, 'outboundTag': 'block'},
                {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'block'},
            ],
        },
    }


def dump_config(config):
    return json.dumps(config, indent=2, ensure_ascii=False)


# ---------- links ----------
def build_link(host, ib, client):
    h = '[%s]' % host if (':' in host and not host.startswith('[')) else host
    q = [
        ('encryption', 'none'), ('flow', 'xtls-rprx-vision'), ('security', 'reality'), ('sni', ib['sni']),
        ('fp', ib['fp']), ('pbk', ib['publicKey']), ('sid', ib['shortId']), ('type', 'tcp'), ('headerType', 'none'),
    ]
    if ib.get('country'):
        q.append(('cc', ib['country']))
    qs = '&'.join('%s=%s' % (k, enc(v)) for k, v in q)
    return 'vless://%s@%s:%d?%s#%s' % (client['uuid'], h, ib['port'], qs, enc('%s-%s' % (ib['name'], client['name'])))


def client_links(state, client):
    return [{'inboundId': ib['id'], 'name': ib['name'], 'url': build_link(state['settings']['host'], ib, client)}
            for ib in state['inbounds'] if ib['enabled']]


def subscription_body(state, client):
    lines = [l['url'] for l in client_links(state, client)] + list(state['settings'].get('extraLinks') or [])
    return base64.b64encode('\n'.join(lines).encode('utf-8')).decode()


# ---------- state store ----------
class Store:
    def __init__(self, directory):
        self.dir = directory
        self.file = os.path.join(directory, 'state.json')
        os.makedirs(directory, mode=0o700, exist_ok=True)

    def exists(self):
        return os.path.exists(self.file)

    def load(self):
        with open(self.file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def save(self, state):
        tmp = self.file + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.file)


def new_inbound(xray_bin, body):
    s = clean_sni(body.get('sni'))
    ib = {
        'id': rid(4), 'name': clean_name(body.get('name'), 'نام سرور'), 'type': 'reality', 'enabled': True,
        'port': clean_port(body.get('port')), 'sni': s, 'dest': clean_dest(body.get('dest'), s),
        'fp': clean_fp(body.get('fp')), 'country': clean_country(body.get('country')),
        'privateKey': '', 'publicKey': '', 'shortId': rid(8),
    }
    keys = gen_reality_keys(xray_bin)
    ib['privateKey'] = keys['privateKey']
    ib['publicKey'] = keys['publicKey']
    return ib


def new_client(name):
    return {
        'id': 'c' + rid(4), 'uuid': str(uuidlib.uuid4()), 'name': clean_name(name, 'نام کانفیگ'),
        'enabled': True, 'sub': rand_alnum(24), 'createdAt': int(time.time() * 1000), 'up': 0, 'down': 0,
    }


# ---------- Xray process manager ----------
class XrayManager:
    def __init__(self, binary, api_port, data_dir):
        self.bin = binary
        self.api_port = api_port
        self.dir = data_dir
        self.proc = None
        self.stopping = False
        self.started_at = 0.0
        self.last_error = ''
        self.logs = deque(maxlen=300)
        self.backoff = 2.0
        self.timer = None
        self.version = ''
        self.config_path = os.path.join(data_dir, 'xray.json')
        self.last_config_text = ''
        self._lock = threading.RLock()
        try:
            r = subprocess.run([binary, 'version'], capture_output=True, text=True, timeout=8)
            self.available = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            self.available = False
        if self.available:
            m = re.search(r'Xray\s+([\d.]+)', r.stdout)
            self.version = m.group(1) if m else ''
        else:
            self.last_error = 'فایل xray پیدا نشد.'

    def log(self, line):
        self.logs.append(line)

    def status(self):
        running = self.proc is not None and self.proc.poll() is None
        return {
            'available': self.available, 'running': running, 'version': self.version,
            'uptime': int(time.time() - self.started_at) if running else 0, 'lastError': self.last_error,
        }

    def test(self, config):
        if not self.available:
            return {'ok': True}
        fd, tmp = tempfile.mkstemp(prefix='xray.test.', suffix='.json', dir=self.dir)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(json.dumps(config))
            r = subprocess.run([self.bin, 'run', '-test', '-c', tmp], capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': 'timeout'}
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        if r.returncode == 0:
            return {'ok': True}
        msg = ' '.join([l for l in (r.stderr or r.stdout).splitlines() if l][-2:])
        return {'ok': False, 'error': msg[:300]}

    def apply(self, config):
        if not self.available:
            return False
        text = dump_config(config)
        with self._lock:
            if text == self.last_config_text and self.proc is not None and self.proc.poll() is None:
                return False
            fd = os.open(self.config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(text)
            self.last_config_text = text
            self.restart()
        return True

    def stop(self):
        with self._lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None
            p = self.proc
            if p is None:
                return
            self.stopping = True
            try:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
            except OSError:
                pass
            self.proc = None
            self.stopping = False

    def restart(self):
        self.stop()
        self.start()

    def start(self):
        with self._lock:
            if not self.available or (self.proc is not None and self.proc.poll() is None):
                return
            p = subprocess.Popen([self.bin, 'run', '-c', self.config_path], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.proc = p
            self.started_at = time.time()
            self.last_error = ''
            threading.Thread(target=self._pump, args=(p,), daemon=True).start()

    def _pump(self, p):
        for line in p.stdout:
            line = line.rstrip('\r\n')
            if not line:
                continue
            self.log(line)
            if re.search(r'error|fail', line, re.I):
                self.last_error = line[:300]
        code = p.wait()
        with self._lock:
            if self.proc is not p:
                return  # replaced or stopped on purpose
            self.proc = None
            if self.stopping:
                return
            self.last_error = self.last_error or 'xray exited (code %s)' % code
            self.log('[panel] xray exited with code %s; restarting in %ds' % (code, int(self.backoff)))
            self.timer = threading.Timer(self.backoff, self.start)
            self.timer.daemon = True
            self.timer.start()
            self.backoff = min(self.backoff * 2, 30)
            threading.Timer(10, self._reset_backoff, args=(self.started_at,)).start()

    def _reset_backoff(self, started):
        if self.proc is not None and self.started_at != started:
            self.backoff = 2.0

    def stats_delta(self):
        """Returns {clientId: {'up': n, 'down': n}} and resets the counters inside xray."""
        if self.proc is None or self.proc.poll() is not None:
            return {}
        try:
            r = subprocess.run([self.bin, 'api', 'statsquery', '--server=127.0.0.1:%d' % self.api_port,
                                '-pattern', 'user>>>', '-reset'], capture_output=True, text=True, timeout=6)
            if r.returncode != 0:
                return {}
            data = json.loads(r.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return {}
        out = {}
        for s in data.get('stat') or []:
            m = re.match(r'^user>>>(.+?)>>>traffic>>>(uplink|downlink)$', str(s.get('name')))
            if not m:
                continue
            e = out.setdefault(m.group(1), {'up': 0, 'down': 0})
            e['up' if m.group(2) == 'uplink' else 'down'] += int(s.get('value') or 0)
        return out
