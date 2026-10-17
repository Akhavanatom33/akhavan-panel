'use strict';
// Akhavan Panel - core logic (state, validation, Xray config, links, process manager).
// Zero npm dependencies. The Python backend (python/core.py) implements the same behaviour.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync, execFile } = require('child_process');

const VERSION = '1.0.0';
const FP_LIST = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'];
const PRIVATE_CIDRS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
];
const EXTRA_SCHEMES = ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://'];

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ---------- helpers ----------
const rid = (bytes = 4) => crypto.randomBytes(bytes).toString('hex');
function randAlnum(n) {
  const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < n; i++) s += a[crypto.randomInt(a.length)];
  return s;
}
const enc = (v) => encodeURIComponent(v);

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('base64')}$${h.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const want = Buffer.from(hash, 'base64');
    const got = crypto.scryptSync(pw, Buffer.from(salt, 'base64'), want.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(got, want);
  } catch { return false; }
}

// ---------- validation ----------
const NAME_RE = /^[^\u0000-\u001f\u007f]{1,40}$/u;
const HOST_RE = /^[A-Za-z0-9.\-:[\]]{1,253}$/;
const SNI_RE = /^(?=.{3,253}$)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/;

function cleanName(v, what = 'نام') {
  const s = String(v ?? '').trim();
  if (!NAME_RE.test(s)) throw new ApiError(400, `${what} باید بین ۱ تا ۴۰ نویسه باشد.`);
  return s;
}
function cleanPort(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new ApiError(400, 'پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.');
  return n;
}
function cleanSni(v) {
  const s = String(v ?? '').trim().toLowerCase();
  if (!SNI_RE.test(s)) throw new ApiError(400, 'SNI نامعتبر است (مثلاً www.microsoft.com).');
  return s;
}
function cleanDest(v, sni) {
  const s = String(v || `${sni}:443`).trim().toLowerCase();
  const m = s.match(/^([a-z0-9.-]+):(\d{1,5})$/);
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) throw new ApiError(400, 'مقصد (dest) باید به شکل host:port باشد.');
  return s;
}
function cleanCountry(v) {
  const s = String(v ?? '').trim().toUpperCase();
  if (s && !/^[A-Z]{2}$/.test(s)) throw new ApiError(400, 'کد کشور باید دو حرف باشد (مثلاً NL).');
  return s;
}
function cleanFp(v) {
  const s = String(v || 'chrome').toLowerCase();
  if (!FP_LIST.includes(s)) throw new ApiError(400, 'fingerprint نامعتبر است.');
  return s;
}
function cleanHost(v) {
  const s = String(v ?? '').trim();
  if (!HOST_RE.test(s)) throw new ApiError(400, 'آدرس سرور (IP یا دامنه) نامعتبر است.');
  return s;
}
function cleanExtraLinks(v) {
  if (!Array.isArray(v)) throw new ApiError(400, 'لیست لینک‌ها نامعتبر است.');
  const out = [];
  for (const raw of v) {
    const s = String(raw || '').trim();
    if (!s) continue;
    if (s.length > 2000 || !EXTRA_SCHEMES.some((p) => s.toLowerCase().startsWith(p))) {
      throw new ApiError(400, 'هر خط باید یک لینک معتبر باشد (vless://، vmess://، trojan:// ...).');
    }
    out.push(s);
  }
  if (out.length > 50) throw new ApiError(400, 'حداکثر ۵۰ لینک اضافه مجاز است.');
  return out;
}

// ---------- x25519 keys via the xray binary ----------
function genRealityKeys(xrayBin) {
  const r = spawnSync(xrayBin, ['x25519'], { encoding: 'utf8', timeout: 10000 });
  if (r.error || r.status !== 0) throw new ApiError(500, 'ساخت کلید Reality ناموفق بود (xray پیدا نشد؟).');
  let priv = ''; let pub = '';
  for (const line of String(r.stdout).split(/\r?\n/)) {
    const m = line.match(/^\s*([^:]+):\s*(\S+)\s*$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k.startsWith('private')) priv = m[2];
    else if (k.includes('public') || k.startsWith('password')) pub = m[2];
  }
  if (!priv || !pub) throw new ApiError(500, 'خروجی xray x25519 قابل خواندن نبود.');
  return { privateKey: priv, publicKey: pub };
}

// ---------- Xray config ----------
function buildXrayConfig(state, apiPort) {
  const inbounds = [{
    tag: 'api-in', listen: '127.0.0.1', port: apiPort, protocol: 'dokodemo-door', settings: { address: '127.0.0.1' },
  }];
  const active = state.clients.filter((c) => c.enabled);
  for (const ib of state.inbounds) {
    if (!ib.enabled) continue;
    inbounds.push({
      tag: `in-${ib.id}`,
      listen: '0.0.0.0',
      port: ib.port,
      protocol: 'vless',
      settings: {
        clients: active.map((c) => ({ id: c.uuid, email: c.id, flow: 'xtls-rprx-vision', level: 0 })),
        decryption: 'none',
      },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          show: false, dest: ib.dest, xver: 0, serverNames: [ib.sni], privateKey: ib.privateKey, shortIds: [ib.shortId],
        },
      },
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true },
    });
  }
  return {
    log: { loglevel: 'warning', access: 'none' },
    stats: {},
    dns: { servers: ['localhost'], queryStrategy: 'UseIPv4' },
    api: { tag: 'api', services: ['StatsService'] },
    policy: { levels: { 0: { statsUserUplink: true, statsUserDownlink: true } } },
    inbounds,
    outbounds: [
      { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } },
      { tag: 'block', protocol: 'blackhole' },
    ],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' },
        { type: 'field', ip: PRIVATE_CIDRS, outboundTag: 'block' },
        { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
      ],
    },
  };
}

// ---------- links ----------
function buildLink(host, ib, client) {
  const h = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const q = [
    ['encryption', 'none'], ['flow', 'xtls-rprx-vision'], ['security', 'reality'], ['sni', ib.sni], ['fp', ib.fp],
    ['pbk', ib.publicKey], ['sid', ib.shortId], ['type', 'tcp'], ['headerType', 'none'],
  ];
  if (ib.country) q.push(['cc', ib.country]);
  const qs = q.map(([k, v]) => `${k}=${enc(v)}`).join('&');
  return `vless://${client.uuid}@${h}:${ib.port}?${qs}#${enc(`${ib.name}-${client.name}`)}`;
}
function clientLinks(state, client) {
  return state.inbounds.filter((ib) => ib.enabled).map((ib) => ({
    inboundId: ib.id, name: ib.name, url: buildLink(state.settings.host, ib, client),
  }));
}
function subscriptionBody(state, client) {
  const lines = clientLinks(state, client).map((l) => l.url).concat(state.settings.extraLinks || []);
  return Buffer.from(lines.join('\n'), 'utf8').toString('base64');
}

// ---------- state store ----------
class Store {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'state.json');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  exists() { return fs.existsSync(this.file); }
  load() { return JSON.parse(fs.readFileSync(this.file, 'utf8')); }
  save(state) {
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

function newInbound(xrayBin, { name, port, sni, dest, fp, country }) {
  const s = cleanSni(sni);
  const ib = {
    id: rid(4), name: cleanName(name, 'نام سرور'), type: 'reality', enabled: true,
    port: cleanPort(port), sni: s, dest: cleanDest(dest, s), fp: cleanFp(fp), country: cleanCountry(country),
    privateKey: '', publicKey: '', shortId: rid(8),
  };
  const keys = genRealityKeys(xrayBin);
  ib.privateKey = keys.privateKey; ib.publicKey = keys.publicKey;
  return ib;
}
function newClient(name) {
  return {
    id: `c${rid(4)}`, uuid: crypto.randomUUID(), name: cleanName(name, 'نام کانفیگ'),
    enabled: true, sub: randAlnum(24), createdAt: Date.now(), up: 0, down: 0,
  };
}

// ---------- Xray process manager ----------
class XrayManager {
  constructor({ bin, apiPort, dataDir }) {
    this.bin = bin; this.apiPort = apiPort; this.dir = dataDir;
    this.child = null; this.stopping = false; this.startedAt = 0; this.lastError = '';
    this.logs = []; this.backoff = 2000; this.timer = null; this.version = '';
    this.configPath = path.join(dataDir, 'xray.json');
    this.lastConfigText = '';
    const r = spawnSync(bin, ['version'], { encoding: 'utf8', timeout: 8000 });
    this.available = !r.error && r.status === 0;
    if (this.available) this.version = (String(r.stdout).match(/Xray\s+([\d.]+)/) || [])[1] || '';
    else this.lastError = 'فایل xray پیدا نشد.';
  }
  log(line) { this.logs.push(line); if (this.logs.length > 300) this.logs.shift(); }
  status() {
    return {
      available: this.available, running: !!this.child, version: this.version,
      uptime: this.child ? Math.floor((Date.now() - this.startedAt) / 1000) : 0, lastError: this.lastError,
    };
  }
  test(config) {
    return new Promise((resolve) => {
      if (!this.available) return resolve({ ok: true });
      const tmp = path.join(this.dir, `xray.test.${rid(3)}.json`);
      fs.writeFileSync(tmp, JSON.stringify(config), { mode: 0o600 });
      execFile(this.bin, ['run', '-test', '-c', tmp], { timeout: 15000 }, (err, stdout, stderr) => {
        fs.rmSync(tmp, { force: true });
        if (!err) return resolve({ ok: true });
        const msg = String(stderr || stdout || err.message).split(/\r?\n/).filter(Boolean).slice(-2).join(' ');
        resolve({ ok: false, error: msg.slice(0, 300) });
      });
    });
  }
  async apply(config) {
    if (!this.available) return false;
    const text = JSON.stringify(config, null, 2);
    if (text === this.lastConfigText && this.child) return false; // nothing changed
    fs.writeFileSync(this.configPath, text, { mode: 0o600 });
    this.lastConfigText = text;
    await this.restart();
    return true;
  }
  async stop() {
    clearTimeout(this.timer);
    const c = this.child;
    if (!c) return;
    this.stopping = true;
    await new Promise((resolve) => {
      c.once('exit', resolve);
      c.kill('SIGTERM');
      setTimeout(() => { try { c.kill('SIGKILL'); } catch { /* gone */ } }, 3000);
    });
    this.stopping = false;
  }
  async restart() { await this.stop(); this.start(); }
  start() {
    if (!this.available || this.child) return;
    const c = spawn(this.bin, ['run', '-c', this.configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    this.child = c; this.startedAt = Date.now(); this.lastError = '';
    const onData = (d) => String(d).split(/\r?\n/).filter(Boolean).forEach((l) => {
      this.log(l);
      if (/error|fail/i.test(l)) this.lastError = l.slice(0, 300);
    });
    c.stdout.on('data', onData); c.stderr.on('data', onData);
    c.on('exit', (code) => {
      if (this.child === c) this.child = null;
      if (this.stopping) return;
      this.lastError = this.lastError || `xray exited (code ${code})`;
      this.log(`[panel] xray exited with code ${code}; restarting in ${this.backoff / 1000}s`);
      this.timer = setTimeout(() => { this.start(); }, this.backoff);
      this.backoff = Math.min(this.backoff * 2, 30000);
    });
    setTimeout(() => { if (this.child === c) this.backoff = 2000; }, 10000);
  }
  // Returns { clientId: {up, down} } deltas and resets the counters inside xray.
  statsDelta() {
    return new Promise((resolve) => {
      if (!this.child) return resolve({});
      execFile(this.bin, ['api', 'statsquery', `--server=127.0.0.1:${this.apiPort}`, '-pattern', 'user>>>', '-reset'],
        { timeout: 6000 }, (err, stdout) => {
          if (err) return resolve({});
          const out = {};
          try {
            for (const s of JSON.parse(stdout).stat || []) {
              const m = String(s.name).match(/^user>>>(.+?)>>>traffic>>>(uplink|downlink)$/);
              if (!m) continue;
              const e = out[m[1]] || (out[m[1]] = { up: 0, down: 0 });
              e[m[2] === 'uplink' ? 'up' : 'down'] += Number(s.value || 0);
            }
          } catch { /* ignore malformed output */ }
          resolve(out);
        });
    });
  }
}

module.exports = {
  VERSION, ApiError, FP_LIST, rid, randAlnum, hashPassword, verifyPassword,
  cleanName, cleanPort, cleanSni, cleanDest, cleanCountry, cleanFp, cleanHost, cleanExtraLinks,
  genRealityKeys, buildXrayConfig, buildLink, clientLinks, subscriptionBody,
  Store, newInbound, newClient, XrayManager,
};
