'use strict';
// Akhavan Panel - Node.js backend (no npm dependencies).
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const core = require('./core');

const { ApiError } = core;

// ---------- configuration ----------
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
const WEB_DIR = path.resolve(process.env.WEB_DIR || path.join(__dirname, '..', 'web'));
const PORT = Number(process.env.PANEL_PORT || 8443);
const BIND = process.env.PANEL_BIND || '0.0.0.0';
const TLS_MODE = (process.env.PANEL_TLS || 'auto').toLowerCase(); // auto | off
const XRAY_BIN = process.env.XRAY_BIN || 'xray';
const API_PORT = Number(process.env.XRAY_API_PORT || 10085);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const store = new core.Store(DATA_DIR);
const xray = new core.XrayManager({ bin: XRAY_BIN, apiPort: API_PORT, dataDir: DATA_DIR });
let state = null;
let tlsOn = false;
let certFingerprint = '';
let queue = Promise.resolve();

// run state-touching work one at a time
function serial(fn) {
  const run = queue.then(fn);
  queue = run.catch(() => {});
  return run;
}

async function collectStats() {
  const delta = await xray.statsDelta();
  let changed = false;
  for (const c of state.clients) {
    const d = delta[c.id];
    if (d && (d.up || d.down)) { c.up += d.up; c.down += d.down; changed = true; }
  }
  if (changed) store.save(state);
}

// mutate a draft copy, validate with xray, then persist and apply
function commit(mutator) {
  return serial(async () => {
    await collectStats();
    const draft = structuredClone(state);
    const result = mutator(draft);
    const cfg = core.buildXrayConfig(draft, API_PORT);
    const t = await xray.test(cfg);
    if (!t.ok) throw new ApiError(400, `پیکربندی Xray نامعتبر است: ${t.error}`);
    state = draft;
    store.save(state);
    await xray.apply(cfg);
    return result;
  });
}

// ---------- bootstrap ----------
function fetchText(url, timeout = 4000) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; if (b.length > 200) req.destroy(); });
      res.on('end', () => resolve(b.trim()));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(''));
  });
}
async function detectPublicIp() {
  for (const u of ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com']) {
    const t = await fetchText(u);
    if (/^[0-9a-fA-F.:]{3,45}$/.test(t)) return t;
  }
  return '';
}

async function bootstrap() {
  if (store.exists()) { state = store.load(); return { first: false }; }
  const username = String(process.env.ADMIN_USER || 'admin').slice(0, 40);
  const password = process.env.ADMIN_PASS || core.randAlnum(16);
  const envPath = String(process.env.PANEL_PATH || '').replace(/[^A-Za-z0-9_-]/g, '');
  const panelPath = `/${envPath.length >= 4 ? envPath : `p-${core.randAlnum(10)}`}`;
  const host = process.env.PUBLIC_HOST || (await detectPublicIp()) || 'YOUR_SERVER_IP';
  state = {
    version: 1,
    admin: { username, hash: core.hashPassword(password) },
    panel: { path: panelPath },
    settings: { host, extraLinks: [] },
    inbounds: [],
    clients: [],
  };
  if (xray.available) {
    state.inbounds.push(core.newInbound(XRAY_BIN, {
      name: process.env.SERVER_NAME || 'Akhavan',
      port: process.env.REALITY_PORT || 443,
      sni: process.env.REALITY_SNI || 'www.microsoft.com',
      country: process.env.COUNTRY || '',
    }));
  }
  state.clients.push(core.newClient('default'));
  store.save(state);
  return { first: true, password };
}

// ---------- TLS ----------
function isIPv4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }
function generateSelfSigned(dir, host) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const san = ['DNS:localhost', 'IP:127.0.0.1'];
  if (isIPv4(host)) san.push(`IP:${host}`);
  else if (/^[A-Za-z0-9.-]+$/.test(host)) san.push(`DNS:${host}`);
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', key, '-out', cert, '-days', '3650', '-subj', '/CN=akhavan-panel', '-addext', `subjectAltName=${san.join(',')}`],
  { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`openssl failed: ${r.stderr || r.error}`);
  fs.chmodSync(key, 0o600);
}
function loadTls() {
  if (TLS_MODE === 'off') return null;
  let certPath = process.env.TLS_CERT;
  let keyPath = process.env.TLS_KEY;
  if (!(certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath))) {
    const dir = path.join(DATA_DIR, 'tls');
    certPath = path.join(dir, 'cert.pem');
    keyPath = path.join(dir, 'key.pem');
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) generateSelfSigned(dir, state.settings.host);
  }
  const cert = fs.readFileSync(certPath);
  certFingerprint = new crypto.X509Certificate(cert).fingerprint256;
  return { cert, key: fs.readFileSync(keyPath) };
}

// ---------- auth ----------
const sessions = new Map();
const fails = new Map();
const DUMMY_HASH = core.hashPassword('dummy-password-for-timing');

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function isAuthed(req) {
  const sid = parseCookies(req).akh;
  const exp = sid && sessions.get(sid);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(sid); return false; }
  return true;
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xf) return xf;
  }
  return req.socket.remoteAddress || '?';
}
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

// ---------- http helpers ----------
const SEC_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
};
function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body);
  const payload = isObj ? JSON.stringify(body) : (body ?? '');
  res.writeHead(status, {
    ...SEC_HEADERS,
    'Cache-Control': 'no-store',
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    ...headers,
  });
  res.end(payload);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 65536) { reject(new ApiError(413, 'درخواست خیلی بزرگ است.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new ApiError(400, 'JSON نامعتبر است.')); }
    });
    req.on('error', reject);
  });
}
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};
function serveStatic(res, rel) {
  let name = rel === '/' || rel === '' ? '/index.html' : rel;
  name = path.normalize(name).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(WEB_DIR, name);
  if (!file.startsWith(WEB_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, '');
  const ext = path.extname(file).toLowerCase();
  const cache = ext === '.html' ? 'no-cache' : 'public, max-age=3600';
  res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': cache });
  fs.createReadStream(file).pipe(res);
  return undefined;
}

// ---------- views ----------
function urlHost(h) { return h.includes(':') && !h.startsWith('[') ? `[${h}]` : h; }
function view() {
  const s = state;
  const scheme = tlsOn ? 'https' : 'http';
  const base = `${scheme}://${urlHost(s.settings.host)}:${PORT}${s.panel.path}`;
  return {
    ok: true,
    panel: { version: core.VERSION, backend: 'node', tls: tlsOn, certFingerprint, port: PORT, path: s.panel.path },
    xray: xray.status(),
    settings: { host: s.settings.host, extraLinks: s.settings.extraLinks },
    inbounds: s.inbounds.map(({ privateKey, ...rest }) => rest), // eslint-disable-line no-unused-vars
    clients: s.clients.map((c) => ({
      id: c.id, name: c.name, uuid: c.uuid, enabled: c.enabled, createdAt: c.createdAt, up: c.up, down: c.down,
      subUrl: `${base}/sub/${c.sub}`, links: core.clientLinks(s, c),
    })),
  };
}
function findClient(d, id) {
  const c = d.clients.find((x) => x.id === id);
  if (!c) throw new ApiError(404, 'کانفیگ پیدا نشد.');
  return c;
}
function findInbound(d, id) {
  const i = d.inbounds.find((x) => x.id === id);
  if (!i) throw new ApiError(404, 'سرور پیدا نشد.');
  return i;
}
function checkPortFree(d, port, exceptId) {
  if (port === PORT || port === API_PORT) throw new ApiError(400, 'این پورت برای خود پنل رزرو است.');
  if (d.inbounds.some((i) => i.port === port && i.id !== exceptId)) throw new ApiError(400, 'این پورت قبلاً استفاده شده است.');
}

function checkDest(dest) {
  return new Promise((resolve) => {
    const m = String(dest || '').trim().match(/^([A-Za-z0-9.-]+):(\d{1,5})$/);
    if (!m) return resolve({ ok: false, error: 'فرمت host:port نامعتبر است.' });
    const t0 = Date.now();
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const sock = tls.connect({ host: m[1], port: Number(m[2]), servername: m[1], ALPNProtocols: ['h2', 'http/1.1'], minVersion: 'TLSv1.3', timeout: 6000 }, () => {
      const r = { ok: true, tls13: sock.getProtocol() === 'TLSv1.3', h2: sock.alpnProtocol === 'h2', ms: Date.now() - t0 };
      sock.end();
      finish(r);
    });
    sock.on('timeout', () => { sock.destroy(); finish({ ok: false, error: 'timeout' }); });
    sock.on('error', (e) => finish({ ok: false, error: e.code || e.message }));
  });
}

// ---------- API ----------
async function api(req, res, rel, body, ip) {
  const method = req.method;
  if (method !== 'GET' && method !== 'HEAD' && req.headers['x-akh'] !== '1') throw new ApiError(403, 'درخواست نامعتبر است.');

  if (rel === '/api/login' && method === 'POST') {
    const f = fails.get(ip);
    if (f && f.until > Date.now()) throw new ApiError(429, 'تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کن.');
    const okUser = safeEqual(body.username || '', state.admin.username);
    const okPass = core.verifyPassword(String(body.password || ''), okUser ? state.admin.hash : DUMMY_HASH);
    if (!(okUser && okPass)) {
      const e = fails.get(ip) || { n: 0, until: 0 };
      e.n += 1;
      if (e.n >= 5) { e.until = Date.now() + 15 * 60 * 1000; e.n = 0; }
      fails.set(ip, e);
      await new Promise((r) => setTimeout(r, 500));
      throw new ApiError(401, 'نام کاربری یا رمز اشتباه است.');
    }
    fails.delete(ip);
    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, Date.now() + 12 * 3600 * 1000);
    return send(res, 200, { ok: true }, {
      'Set-Cookie': `akh=${sid}; Path=${state.panel.path}/; HttpOnly; SameSite=Strict; Max-Age=43200${tlsOn ? '; Secure' : ''}`,
    });
  }
  if (rel === '/api/logout' && method === 'POST') {
    sessions.delete(parseCookies(req).akh);
    return send(res, 200, { ok: true }, { 'Set-Cookie': `akh=; Path=${state.panel.path}/; HttpOnly; SameSite=Strict; Max-Age=0` });
  }
  if (!isAuthed(req)) throw new ApiError(401, 'ابتدا وارد شوید.');

  if (rel === '/api/state' && method === 'GET') return send(res, 200, view());

  // ----- clients -----
  if (rel === '/api/clients' && method === 'POST') {
    await commit((d) => {
      if (d.clients.length >= 200) throw new ApiError(400, 'حداکثر ۲۰۰ کانفیگ مجاز است.');
      d.clients.push(core.newClient(body.name));
    });
    return send(res, 200, view());
  }
  let m = rel.match(/^\/api\/clients\/([A-Za-z0-9]+)(?:\/(regen-uuid|regen-sub))?$/);
  if (m) {
    const [, id, action] = m;
    if (method === 'PATCH' && !action) {
      await commit((d) => {
        const c = findClient(d, id);
        if (body.name !== undefined) c.name = core.cleanName(body.name, 'نام کانفیگ');
        if (body.enabled !== undefined) c.enabled = !!body.enabled;
      });
      return send(res, 200, view());
    }
    if (method === 'POST' && action === 'regen-uuid') {
      await commit((d) => { findClient(d, id).uuid = crypto.randomUUID(); });
      return send(res, 200, view());
    }
    if (method === 'POST' && action === 'regen-sub') {
      await commit((d) => { findClient(d, id).sub = core.randAlnum(24); });
      return send(res, 200, view());
    }
    if (method === 'DELETE' && !action) {
      await commit((d) => { findClient(d, id); d.clients = d.clients.filter((c) => c.id !== id); });
      return send(res, 200, view());
    }
  }

  // ----- inbounds (servers) -----
  if (rel === '/api/inbounds' && method === 'POST') {
    await commit((d) => {
      if (d.inbounds.length >= 20) throw new ApiError(400, 'حداکثر ۲۰ سرور مجاز است.');
      const ib = core.newInbound(XRAY_BIN, body);
      checkPortFree(d, ib.port);
      d.inbounds.push(ib);
    });
    return send(res, 200, view());
  }
  m = rel.match(/^\/api\/inbounds\/([a-f0-9]+)(?:\/(regen-keys))?$/);
  if (m) {
    const [, id, action] = m;
    if (method === 'PATCH' && !action) {
      await commit((d) => {
        const ib = findInbound(d, id);
        if (body.name !== undefined) ib.name = core.cleanName(body.name, 'نام سرور');
        if (body.enabled !== undefined) ib.enabled = !!body.enabled;
        if (body.country !== undefined) ib.country = core.cleanCountry(body.country);
        if (body.fp !== undefined) ib.fp = core.cleanFp(body.fp);
        if (body.port !== undefined) { ib.port = core.cleanPort(body.port); checkPortFree(d, ib.port, id); }
        if (body.sni !== undefined) {
          ib.sni = core.cleanSni(body.sni);
          ib.dest = core.cleanDest(body.dest, ib.sni);
        } else if (body.dest !== undefined) ib.dest = core.cleanDest(body.dest, ib.sni);
      });
      return send(res, 200, view());
    }
    if (method === 'POST' && action === 'regen-keys') {
      await commit((d) => {
        const ib = findInbound(d, id);
        const k = core.genRealityKeys(XRAY_BIN);
        ib.privateKey = k.privateKey; ib.publicKey = k.publicKey; ib.shortId = core.rid(8);
      });
      return send(res, 200, view());
    }
    if (method === 'DELETE' && !action) {
      await commit((d) => { findInbound(d, id); d.inbounds = d.inbounds.filter((i) => i.id !== id); });
      return send(res, 200, view());
    }
  }
  if (rel === '/api/check-dest' && method === 'POST') return send(res, 200, await checkDest(body.dest));

  // ----- settings -----
  if (rel === '/api/settings' && method === 'PUT') {
    await commit((d) => {
      if (body.host !== undefined) d.settings.host = core.cleanHost(body.host);
      if (body.extraLinks !== undefined) d.settings.extraLinks = core.cleanExtraLinks(body.extraLinks);
    });
    return send(res, 200, view());
  }
  if (rel === '/api/password' && method === 'POST') {
    if (!core.verifyPassword(String(body.current || ''), state.admin.hash)) throw new ApiError(400, 'رمز فعلی اشتباه است.');
    const next = String(body.next || '');
    if (next.length < 10 || next.length > 128) throw new ApiError(400, 'رمز جدید باید حداقل ۱۰ نویسه باشد.');
    await commit((d) => { d.admin.hash = core.hashPassword(next); });
    sessions.clear();
    return send(res, 200, { ok: true }, { 'Set-Cookie': `akh=; Path=${state.panel.path}/; HttpOnly; SameSite=Strict; Max-Age=0` });
  }

  // ----- xray -----
  if (rel === '/api/xray/restart' && method === 'POST') {
    if (!xray.available) throw new ApiError(400, 'فایل xray پیدا نشد.');
    await serial(async () => { await collectStats(); await xray.restart(); });
    return send(res, 200, view());
  }
  if (rel === '/api/xray/logs' && method === 'GET') return send(res, 200, { ok: true, logs: xray.logs.slice(-200) });

  throw new ApiError(404, 'یافت نشد.');
}

function handleSub(res, token) {
  const c = state.clients.find((x) => safeEqual(x.sub, token));
  if (!c) return send(res, 404, '');
  if (!c.enabled) return send(res, 403, 'disabled');
  return send(res, 200, core.subscriptionBody(state, c), {
    'Profile-Update-Interval': '6',
    'Subscription-Userinfo': `upload=${c.up}; download=${c.down}; total=0; expire=0`,
  });
}

async function handler(req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const base = state.panel.path;
    const p = url.pathname;
    if (p !== base && !p.startsWith(`${base}/`)) return send(res, 404, '');
    const rel = p.slice(base.length);
    if (rel === '') { res.writeHead(301, { Location: `${base}/` }); return res.end(); }
    if (rel.startsWith('/api/')) {
      const body = req.method === 'GET' || req.method === 'HEAD' ? {} : await readBody(req);
      return await api(req, res, rel, body, clientIp(req));
    }
    const sub = rel.match(/^\/sub\/([A-Za-z0-9]{10,64})$/);
    if (sub && req.method === 'GET') return handleSub(res, sub[1]);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, '');
    return serveStatic(res, rel);
  } catch (e) {
    if (e instanceof ApiError) return send(res, e.status, { ok: false, error: e.message });
    console.error('[panel] error:', e);
    return send(res, 500, { ok: false, error: 'خطای داخلی سرور.' });
  }
}

// ---------- CLI + main ----------
function printBanner(first, password) {
  const scheme = tlsOn ? 'https' : 'http';
  const url = `${scheme}://${urlHost(state.settings.host)}:${PORT}${state.panel.path}/`;
  const lines = ['='.repeat(62), ' Akhavan Panel is running', ` Panel URL : ${url}`];
  if (first) {
    lines.push(` Username  : ${state.admin.username}`, ` Password  : ${password}   (shown once - save it)`);
    const c = state.clients[0];
    const links = core.clientLinks(state, c);
    if (links.length) lines.push('', ' First config (also in the panel):', ` ${links[0].url}`);
    fs.writeFileSync(path.join(DATA_DIR, 'CREDENTIALS.txt'), `${lines.join('\n')}\n\nDelete this file after saving the password.\n`, { mode: 0o600 });
  } else {
    lines.push(' (credentials were shown at first start; see data/CREDENTIALS.txt or run --reset-password)');
  }
  if (certFingerprint) lines.push(` TLS SHA-256 fingerprint: ${certFingerprint}`);
  lines.push('='.repeat(62));
  console.log(lines.join('\n'));
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === '--reset-password') {
    if (!store.exists()) { console.error('No state yet; start the panel once first.'); process.exit(1); }
    state = store.load();
    const pw = argv[1] || core.randAlnum(16);
    state.admin.hash = core.hashPassword(pw);
    store.save(state);
    console.log(`New password for "${state.admin.username}": ${pw}`);
    return;
  }
  const { first, password } = await bootstrap();
  const tlsOpts = loadTls();
  tlsOn = !!tlsOpts;
  const server = tlsOn ? https.createServer({ ...tlsOpts, minVersion: 'TLSv1.2' }, handler) : http.createServer(handler);
  server.keepAliveTimeout = 5000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(PORT, BIND, resolve); });
  if (!tlsOn && BIND !== '127.0.0.1' && BIND !== 'localhost') console.warn('[panel] WARNING: TLS is off and the panel is not bound to localhost.');
  await xray.apply(core.buildXrayConfig(state, API_PORT));
  if (!xray.available) console.warn('[panel] WARNING: xray binary not found; only the panel is running.');
  printBanner(first, password);

  setInterval(() => { serial(collectStats).catch(() => {}); }, 20000).unref();
  setInterval(() => { const now = Date.now(); for (const [k, v] of sessions) if (v < now) sessions.delete(k); }, 600000).unref();
  const shutdown = async () => {
    try { await serial(collectStats); } catch { /* ignore */ }
    await xray.stop();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => { console.error('[panel] fatal:', e.message); process.exit(1); });
