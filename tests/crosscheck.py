#!/usr/bin/env python3
"""Starts the Node and the Python backend on the same fixture state and checks they behave identically
(same Xray config, same /api/state, password hashes verify in both). Needs xray + node + python3."""
import json, os, shutil, subprocess, sys, tempfile, time, urllib.request, urllib.error
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRAY = os.environ.get('XRAY_BIN', 'xray')
sys.path.insert(0, os.path.join(ROOT, 'python'))
import core  # noqa: E402

def x25519():
    return core.gen_reality_keys(XRAY)

def fixture(pw_hash):
    k1, k2 = x25519(), x25519()
    return {
        'version': 1, 'admin': {'username': 'admin', 'hash': pw_hash}, 'panel': {'path': '/fixpath'},
        'settings': {'host': '198.51.100.7', 'extraLinks': ['vless://11111111-2222-4333-8444-555555555555@other.example:443?security=reality&type=tcp&sni=x.com&pbk=abc&sid=01#Other']},
        'inbounds': [
            {'id': 'aaaa1111', 'name': 'Akhavan-NL', 'type': 'reality', 'enabled': True, 'port': 24451, 'sni': 'github.com', 'dest': 'github.com:443', 'fp': 'chrome', 'country': 'NL', 'privateKey': k1['privateKey'], 'publicKey': k1['publicKey'], 'shortId': '0123456789abcdef'},
            {'id': 'bbbb2222', 'name': 'نام فارسی', 'type': 'reality', 'enabled': True, 'port': 24452, 'sni': 'www.cloudflare.com', 'dest': 'www.cloudflare.com:443', 'fp': 'firefox', 'country': '', 'privateKey': k2['privateKey'], 'publicKey': k2['publicKey'], 'shortId': 'fedcba9876543210'},
            {'id': 'cccc3333', 'name': 'Off', 'type': 'reality', 'enabled': False, 'port': 24453, 'sni': 'www.apple.com', 'dest': 'www.apple.com:443', 'fp': 'chrome', 'country': 'US', 'privateKey': k2['privateKey'], 'publicKey': k2['publicKey'], 'shortId': '1111222233334444'},
        ],
        'clients': [
            {'id': 'c0000001', 'uuid': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'name': 'phone', 'enabled': True, 'sub': 'SubTokenPhone1234567890ab', 'createdAt': 1700000000000, 'up': 5, 'down': 9},
            {'id': 'c0000002', 'uuid': '11111111-2222-4333-8444-666666666666', 'name': 'لپ‌تاپ & test #1', 'enabled': True, 'sub': 'SubTokenLaptop1234567890ab', 'createdAt': 1700000000001, 'up': 0, 'down': 0},
            {'id': 'c0000003', 'uuid': '22222222-3333-4444-8555-777777777777', 'name': 'off', 'enabled': False, 'sub': 'SubTokenOff12345678901234', 'createdAt': 1700000000002, 'up': 0, 'down': 0},
        ],
    }

def http(base, method, path, body=None, cookie=None):
    req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={'content-type': 'application/json', 'x-akh': '1', **({'cookie': cookie} if cookie else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers

def run_backend(kind, state, port):
    d = tempfile.mkdtemp(prefix='akh-%s-' % kind)
    with open(os.path.join(d, 'state.json'), 'w') as f:
        json.dump(state, f)
    env = dict(os.environ, DATA_DIR=d, PANEL_TLS='off', PANEL_PORT=str(port), PANEL_BIND='127.0.0.1', XRAY_BIN=XRAY, XRAY_API_PORT=str(port + 1000))
    cmd = ['node', os.path.join(ROOT, 'node', 'server.js')] if kind == 'node' else [sys.executable, os.path.join(ROOT, 'python', 'app.py')]
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = 'http://127.0.0.1:%d/fixpath' % port
    for _ in range(50):
        try:
            http(base, 'GET', '/api/state'); break
        except Exception:
            time.sleep(0.2)
    return p, base, d

def collect(kind, state, port, password):
    p, base, d = run_backend(kind, state, port)
    try:
        st, _, hdr = http(base, 'POST', '/api/login', {'username': 'admin', 'password': password})
        assert st == 200, '%s: login failed (%s) - password hash not compatible?' % (kind, st)
        cookie = hdr['Set-Cookie'].split(';')[0]
        time.sleep(1.0)
        _, body, _ = http(base, 'GET', '/api/state', cookie=cookie)
        view = json.loads(body)
        subs = {}
        for c in view['clients']:
            code, text, _ = http(base, 'GET', '/sub/' + c['subUrl'].rsplit('/', 1)[1])
            subs[c['id']] = (code, text)
        xconf = json.load(open(os.path.join(d, 'xray.json')))
        return view, subs, xconf
    finally:
        p.terminate(); p.wait(timeout=10); shutil.rmtree(d, ignore_errors=True)

def norm(view):
    v = json.loads(json.dumps(view))
    v['panel'].pop('backend'); v['xray'].pop('uptime', None)
    return v

def diff(a, b, path=''):
    out = []
    if type(a) != type(b):
        return ['%s: type %s vs %s (%r vs %r)' % (path, type(a).__name__, type(b).__name__, a, b)]
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a: out.append('%s/%s: only in python' % (path, k))
            elif k not in b: out.append('%s/%s: only in node' % (path, k))
            else: out += diff(a[k], b[k], '%s/%s' % (path, k))
    elif isinstance(a, list):
        if len(a) != len(b): out.append('%s: list length %d vs %d' % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)): out += diff(x, y, '%s[%d]' % (path, i))
    elif a != b:
        out.append('%s: %r vs %r' % (path, a, b))
    return out

ok = True
for round_name, maker in (('python-made password hash', core.hash_password), ('node-made password hash', None)):
    pw = 'CrossCheckPass123'
    if maker is None:
        h = subprocess.run(['node', '-e', "console.log(require('%s/node/core.js').hashPassword('%s'))" % (ROOT, pw)], capture_output=True, text=True).stdout.strip()
    else:
        h = maker(pw)
    st = fixture(h)
    vn, sn, xn = collect('node', st, 19451, pw)
    vp, sp, xp = collect('python', st, 19451, pw)
    checks = [('xray config identical', xn == xp), ('/api/state identical', norm(vn) == norm(vp)), ('subscriptions identical', sn == sp),
              ('xray running in both', vn['xray']['running'] and vp['xray']['running'])]
    print('round:', round_name)
    for name, res in checks:
        print('  %s %s' % ('ok  ' if res else 'FAIL', name)); ok &= res
    if xn != xp: print('   xray diff (node vs python):', diff(xn, xp)[:6])
    if norm(vn) != norm(vp): print('   state diff (node vs python):', diff(norm(vn), norm(vp))[:6])
sys.exit(0 if ok else 1)
