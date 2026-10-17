'use strict';
// API contract test. Works against either backend (Node or Python).
// Usage: BASE=http://127.0.0.1:19443/testpath ADMIN_PASS=... DATA_DIR=... node tests/api.test.js
const fs = require('fs');
const path = require('path');

const BASE = process.env.BASE;
const PASS = process.env.ADMIN_PASS || 'TestPass12345';
const DATA = process.env.DATA_DIR;
const PANEL_PORT = Number(process.env.PANEL_PORT || 19443);
const HAS_XRAY = process.env.HAS_XRAY !== '0';
let cookie = '';
let passed = 0;
let failed = 0;

function ok(cond, name) {
  if (cond) { passed++; console.log(`  ok   ${name}`); } else { failed++; console.log(`  FAIL ${name}`); }
}
async function call(method, p, body, opts = {}) {
  const headers = { 'content-type': 'application/json' };
  if (!opts.noCsrf) headers['x-akh'] = '1';
  if (cookie && !opts.noCookie) headers.cookie = cookie;
  const r = await fetch(BASE + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const sc = r.headers.get('set-cookie');
  if (sc && sc.startsWith('akh=') && !sc.startsWith('akh=;')) cookie = sc.split(';')[0];
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: r.status, json, text, headers: r.headers };
}
const state = async () => (await call('GET', '/api/state')).json;
const readXrayConf = () => (DATA && fs.existsSync(path.join(DATA, 'xray.json')) ? JSON.parse(fs.readFileSync(path.join(DATA, 'xray.json'), 'utf8')) : null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  console.log('auth & hardening');
  ok((await call('GET', '/api/state', undefined, { noCookie: true })).status === 401, 'state requires login');
  ok((await fetch(BASE.replace(/\/[^/]+$/, '/nope') + '/api/state')).status === 404, 'wrong base path gives 404');
  ok((await call('POST', '/api/login', { username: 'admin', password: PASS }, { noCsrf: true })).status === 403, 'missing CSRF header is rejected');
  ok((await call('POST', '/api/login', { username: 'admin', password: 'wrong' })).status === 401, 'bad password rejected');
  const login = await call('POST', '/api/login', { username: 'admin', password: PASS });
  ok(login.status === 200 && cookie.startsWith('akh='), 'login works and sets cookie');
  const sc = login.headers.get('set-cookie') || '';
  ok(/HttpOnly/i.test(sc) && /SameSite=Strict/i.test(sc), 'cookie is HttpOnly + SameSite=Strict');
  const idx = await fetch(BASE + '/');
  const idxText = await idx.text();
  ok(idx.status === 200 && idxText.includes('<html'), 'panel UI is served');
  ok((idx.headers.get('content-security-policy') || '').includes("default-src 'self'"), 'CSP header present');

  console.log('state');
  let s = await state();
  ok(s.ok && s.panel && s.xray && s.settings && Array.isArray(s.inbounds) && Array.isArray(s.clients), 'state shape');
  ok(s.inbounds.every((i) => !('privateKey' in i) && i.publicKey && i.shortId), 'private keys never leave the server');
  const startInbounds = s.inbounds.length;
  const startClients = s.clients.length;
  if (HAS_XRAY) ok(s.xray.running === true, 'xray is running');

  console.log('clients');
  s = (await call('POST', '/api/clients', { name: 'phone' })).json;
  const c = s.clients.find((x) => x.name === 'phone');
  ok(!!c && s.clients.length === startClients + 1, 'create client');
  ok(c.links.length === s.inbounds.filter((i) => i.enabled).length, 'one link per enabled server');
  ok(/^vless:\/\/[0-9a-f-]{36}@/.test(c.links[0].url) && c.links[0].url.includes('security=reality') && c.links[0].url.includes('flow=xtls-rprx-vision'), 'link looks like VLESS Reality');
  ok((await call('POST', '/api/clients', { name: '' })).status === 400, 'empty name rejected');
  const conf1 = readXrayConf();
  if (conf1) ok(JSON.stringify(conf1).includes(c.uuid), 'new client is in the xray config');
  let sub = await call('GET', new URL(c.subUrl).pathname.replace(new URL(BASE).pathname, ''), undefined, { noCookie: true, noCsrf: true });
  const decoded = Buffer.from(sub.text, 'base64').toString('utf8').split('\n');
  ok(sub.status === 200 && decoded.length === c.links.length && decoded[0] === c.links[0].url, 'subscription (no login) returns base64 links');
  ok(/upload=\d+; download=\d+/.test(sub.headers.get('subscription-userinfo') || ''), 'subscription-userinfo header');
  s = (await call('PATCH', `/api/clients/${c.id}`, { name: 'phone2' })).json;
  ok(s.clients.find((x) => x.id === c.id).name === 'phone2', 'rename client');
  s = (await call('PATCH', `/api/clients/${c.id}`, { enabled: false })).json;
  ok(s.clients.find((x) => x.id === c.id).enabled === false, 'disable client');
  const conf2 = readXrayConf();
  if (conf2) ok(!JSON.stringify(conf2).includes(c.uuid), 'disabled client removed from xray config');
  const subPath = new URL(c.subUrl).pathname.replace(new URL(BASE).pathname, '');
  ok((await call('GET', subPath, undefined, { noCookie: true, noCsrf: true })).status === 403, 'disabled client subscription is 403');
  await call('PATCH', `/api/clients/${c.id}`, { enabled: true });
  const oldUuid = c.uuid;
  s = (await call('POST', `/api/clients/${c.id}/regen-uuid`)).json;
  const c2 = s.clients.find((x) => x.id === c.id);
  ok(c2.uuid !== oldUuid, 'regenerate UUID');
  s = (await call('POST', `/api/clients/${c.id}/regen-sub`)).json;
  ok((await call('GET', subPath, undefined, { noCookie: true, noCsrf: true })).status === 404, 'old subscription token stops working');
  s = (await call('DELETE', `/api/clients/${c.id}`)).json;
  ok(!s.clients.some((x) => x.id === c.id), 'delete client');

  console.log('servers (inbounds)');
  if (HAS_XRAY) {
    ok((await call('POST', '/api/inbounds', { name: 'bad', port: 23001, sni: 'not a host' })).status === 400, 'invalid SNI rejected');
    ok((await call('POST', '/api/inbounds', { name: 'bad', port: PANEL_PORT, sni: 'www.cloudflare.com' })).status === 400, 'panel port is reserved');
    ok((await call('POST', '/api/inbounds', { name: 'bad', port: 99999, sni: 'www.cloudflare.com' })).status === 400, 'invalid port rejected');
    s = (await call('POST', '/api/inbounds', { name: 'Akhavan-DE', port: 23001, sni: 'www.cloudflare.com', country: 'de' })).json;
    const ib = s.inbounds.find((x) => x.name === 'Akhavan-DE');
    ok(!!ib && ib.country === 'DE' && ib.dest === 'www.cloudflare.com:443', 'create server (defaults + country uppercased)');
    ok((await call('POST', '/api/inbounds', { name: 'dup', port: 23001, sni: 'www.cloudflare.com' })).status === 400, 'duplicate port rejected');
    ok(s.clients[0].links.length === startInbounds + 1 && s.clients[0].links.some((l) => l.url.includes('cc=DE')), 'every client gets a link for the new server');
    const confIb = readXrayConf();
    if (confIb) ok(confIb.inbounds.some((i) => i.port === 23001), 'new server is in the xray config');
    const pbk1 = ib.publicKey;
    s = (await call('POST', `/api/inbounds/${ib.id}/regen-keys`)).json;
    ok(s.inbounds.find((x) => x.id === ib.id).publicKey !== pbk1, 'regenerate Reality keys');
    s = (await call('PATCH', `/api/inbounds/${ib.id}`, { enabled: false })).json;
    ok(s.clients[0].links.length === startInbounds, 'disabled server disappears from links');
    s = (await call('DELETE', `/api/inbounds/${ib.id}`)).json;
    ok(!s.inbounds.some((x) => x.id === ib.id), 'delete server');
  }
  const cd = await call('POST', '/api/check-dest', { dest: '127.0.0.1:1' });
  ok(cd.status === 200 && cd.json.ok === false, 'check-dest reports unreachable target');

  console.log('settings');
  s = (await call('PUT', '/api/settings', { host: 'example.org' })).json;
  ok(s.settings.host === 'example.org' && s.clients[0].links[0].url.includes('@example.org:'), 'host change updates all links');
  ok((await call('PUT', '/api/settings', { host: 'bad host!' })).status === 400, 'invalid host rejected');
  ok((await call('PUT', '/api/settings', { extraLinks: ['http://evil'] })).status === 400, 'non-proxy extra link rejected');
  const extra = 'vless://11111111-2222-4333-8444-555555555555@other.example:443?security=reality&type=tcp&sni=x.com&pbk=abc&sid=01#Other-VPS';
  s = (await call('PUT', '/api/settings', { extraLinks: [extra, ''] })).json;
  ok(s.settings.extraLinks.length === 1, 'extra links saved');
  const subAll = await call('GET', new URL(s.clients[0].subUrl).pathname.replace(new URL(BASE).pathname, ''), undefined, { noCookie: true, noCsrf: true });
  ok(Buffer.from(subAll.text, 'base64').toString('utf8').split('\n').includes(extra), 'extra links are appended to subscriptions');
  await call('PUT', '/api/settings', { host: process.env.PUBLIC_HOST || '127.0.0.1', extraLinks: [] });

  console.log('xray');
  const logs = await call('GET', '/api/xray/logs');
  ok(logs.status === 200 && Array.isArray(logs.json.logs), 'logs endpoint');
  if (HAS_XRAY) {
    s = (await call('POST', '/api/xray/restart')).json;
    await sleep(500);
    ok((await state()).xray.running === true, 'restart keeps xray running');
  }

  console.log('password & lockout');
  ok((await call('POST', '/api/password', { current: 'nope', next: 'AnotherPass12345' })).status === 400, 'wrong current password');
  ok((await call('POST', '/api/password', { current: PASS, next: 'short' })).status === 400, 'short password rejected');
  ok((await call('POST', '/api/password', { current: PASS, next: 'AnotherPass12345' })).status === 200, 'password changed');
  ok((await call('GET', '/api/state')).status === 401, 'old session invalidated after password change');
  cookie = '';
  ok((await call('POST', '/api/login', { username: 'admin', password: PASS })).status === 401, 'old password no longer works');
  ok((await call('POST', '/api/login', { username: 'admin', password: 'AnotherPass12345' })).status === 200, 'new password works');
  let locked = false;
  for (let i = 0; i < 7; i++) {
    const r = await call('POST', '/api/login', { username: 'admin', password: `bad${i}` });
    if (r.status === 429) { locked = true; break; }
  }
  ok(locked, 'brute force is locked out (429)');
  ok((await call('POST', '/api/login', { username: 'admin', password: 'AnotherPass12345' })).status === 429, 'lockout applies even to the right password');

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('test crashed:', e); process.exit(2); });
