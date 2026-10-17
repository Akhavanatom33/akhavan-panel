'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
let S = null;
let pollTimer = null;

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function fmtBytes(b) {
  b = Number(b) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(0)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}
function fmtUptime(s) {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

/* ---------- api ---------- */
async function api(method, path, body) {
  const r = await fetch(`api/${path}`, {
    method,
    headers: { 'x-akh': '1', 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  let j = null;
  try { j = await r.json(); } catch { /* ignore */ }
  if (r.status === 401 && path !== 'login') { showLogin(); throw new Error('لطفاً دوباره وارد شوید.'); }
  if (!r.ok || (j && j.ok === false)) throw new Error((j && j.error) || 'خطای ناشناخته');
  return j;
}

let toastTimer = null;
function toast(msg, isErr = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('err', isErr);
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), isErr ? 5500 : 2400);
}
async function run(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); return null; }
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); toast('کپی شد'); return; }
  } catch { /* fall through */ }
  const ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly', '');
  ta.className = 'hidden-copy';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { /* ignore */ }
  ta.remove();
  toast(ok ? 'کپی شد' : 'کپی نشد؛ متن را دستی انتخاب کن', !ok);
}

/* ---------- dialogs ---------- */
const dlg = $('#dlg');
function openDialog(html) { $('#dlgBody').innerHTML = `<div class="dlg">${html}</div>`; if (!dlg.open) dlg.showModal(); }
function closeDialog() { if (dlg.open) dlg.close(); }
dlg.addEventListener('click', (e) => { if (e.target === dlg) closeDialog(); });
function confirmDialog(msg, okLabel = 'تأیید') {
  return new Promise((resolve) => {
    openDialog(`<h2>${esc(msg)}</h2><div class="dlg-actions"><button class="btn danger" data-dlg="yes">${esc(okLabel)}</button><button class="btn" data-dlg="no">انصراف</button></div>`);
    const h = (e) => {
      const b = e.target.closest('[data-dlg]');
      if (!b) return;
      dlg.removeEventListener('click', h); closeDialog(); resolve(b.dataset.dlg === 'yes');
    };
    dlg.addEventListener('click', h);
    dlg.addEventListener('close', () => { dlg.removeEventListener('click', h); resolve(false); }, { once: true });
  });
}
function qrDialog(title, text) {
  let img = '';
  try {
    const qr = window.qrcode(0, 'M');
    qr.addData(text); qr.make();
    img = qr.createDataURL(6, 4);
  } catch { img = ''; }
  openDialog(`<h2>${esc(title)}</h2>${img ? `<img class="qr" src="${img}" alt="QR">` : '<p class="hint">متن برای QR بیش از حد طولانی است.</p>'}
    <p class="hint">این کد شامل کلید خصوصی اتصال شماست؛ برای کسی نفرستید.</p>
    <div class="dlg-actions"><button class="btn" data-action="close-dlg">بستن</button></div>`);
}
function formDialog(title, fields, submitLabel) {
  return new Promise((resolve) => {
    const inputs = fields.map((f) => `<label class="field"><span>${esc(f.label)}</span><input class="input${f.ltr ? ' ltr' : ''}" data-f="${f.key}" value="${esc(f.value ?? '')}" ${f.maxlength ? `maxlength="${f.maxlength}"` : ''}></label>`).join('');
    openDialog(`<h2>${esc(title)}</h2>${inputs}<div class="dlg-actions"><button class="btn primary" data-dlg="ok">${esc(submitLabel || 'ذخیره')}</button><button class="btn" data-dlg="cancel">انصراف</button></div>`);
    const h = (e) => {
      const b = e.target.closest('[data-dlg]');
      if (!b) return;
      const out = {};
      $$('[data-f]', dlg).forEach((i) => { out[i.dataset.f] = i.value.trim(); });
      dlg.removeEventListener('click', h); closeDialog(); resolve(b.dataset.dlg === 'ok' ? out : null);
    };
    dlg.addEventListener('click', h);
    dlg.addEventListener('close', () => { dlg.removeEventListener('click', h); resolve(null); }, { once: true });
  });
}

/* ---------- views ---------- */
function showLogin() { clearInterval(pollTimer); $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); $('#lPass').value = ''; }
function showApp() { $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); }

function renderHeader() {
  const x = S.xray;
  const p = $('#xrayPill');
  if (!x.available) { p.textContent = 'Xray پیدا نشد'; p.className = 'pill bad'; }
  else if (x.running) { p.textContent = `Xray ${x.version} · فعال`; p.className = 'pill ok'; }
  else { p.textContent = 'Xray متوقف است'; p.className = 'pill bad'; }
}

function clientCard(c) {
  const rows = c.links.map((l, i) => `<div class="link-row"><span class="link-name">${esc(l.name)}</span><span class="link-url">${esc(l.url)}</span>
    <button class="btn small" data-action="copy-link" data-id="${esc(c.id)}" data-i="${i}">کپی</button>
    <button class="btn small" data-action="qr-link" data-id="${esc(c.id)}" data-i="${i}">QR</button></div>`).join('');
  const none = '<div class="hint">هیچ سرور فعالی نیست؛ از تب «سرورها» یکی اضافه یا فعال کن.</div>';
  return `<article class="item${c.enabled ? '' : ' off'}">
    <div class="item-head">
      <div class="item-title">${esc(c.name)} ${c.enabled ? '' : '<span class="tag warn">غیرفعال</span>'}</div>
      <span class="item-meta">↓ ${fmtBytes(c.down)} · ↑ ${fmtBytes(c.up)}</span>
      <label class="switch-row"><input type="checkbox" data-action="toggle-client" data-id="${esc(c.id)}" ${c.enabled ? 'checked' : ''}><span class="switch"></span><span>فعال</span></label>
    </div>
    <div class="links">${rows || none}
      <div class="link-row"><span class="link-name">آدرس اشتراک</span><span class="link-url">${esc(c.subUrl)}</span>
        <button class="btn small" data-action="copy-sub" data-id="${esc(c.id)}">کپی</button>
        <button class="btn small" data-action="qr-sub" data-id="${esc(c.id)}">QR</button></div>
    </div>
    <div class="item-actions">
      <button class="btn small" data-action="copy-all" data-id="${esc(c.id)}">کپی همهٔ لینک‌ها</button>
      <button class="btn small" data-action="rename-client" data-id="${esc(c.id)}">تغییر نام</button>
      <button class="btn small" data-action="regen-uuid" data-id="${esc(c.id)}">UUID جدید</button>
      <button class="btn small" data-action="regen-sub" data-id="${esc(c.id)}">اشتراک جدید</button>
      <button class="btn small danger" data-action="delete-client" data-id="${esc(c.id)}">حذف</button>
    </div>
  </article>`;
}
function renderClients() {
  $('#clientList').innerHTML = S.clients.length ? S.clients.map(clientCard).join('') : '<div class="empty">هنوز کانفیگی نیست. بالا یک نام بنویس و «افزودن کانفیگ» را بزن.</div>';
}

function serverCard(ib) {
  return `<article class="item${ib.enabled ? '' : ' off'}">
    <div class="item-head">
      <div class="item-title">${esc(ib.name)} ${ib.country ? `<span class="tag">${esc(ib.country)}</span>` : ''}</div>
      <span class="item-meta">:${ib.port} · ${esc(ib.sni)} · ${esc(ib.fp)}</span>
      <label class="switch-row"><input type="checkbox" data-action="toggle-inbound" data-id="${esc(ib.id)}" ${ib.enabled ? 'checked' : ''}><span class="switch"></span><span>فعال</span></label>
    </div>
    <div class="hint">کلید عمومی: <span class="ltr-i">${esc(ib.publicKey)}</span> · dest: <span class="ltr-i">${esc(ib.dest)}</span></div>
    <div class="item-actions">
      <button class="btn small" data-action="edit-inbound" data-id="${esc(ib.id)}">ویرایش</button>
      <button class="btn small" data-action="regen-keys" data-id="${esc(ib.id)}">کلید جدید</button>
      <button class="btn small danger" data-action="delete-inbound" data-id="${esc(ib.id)}">حذف</button>
    </div>
  </article>`;
}
function renderServers() {
  $('#serverList').innerHTML = S.inbounds.length ? S.inbounds.map(serverCard).join('') : '<div class="empty">سروری تعریف نشده. پایین یکی اضافه کن (پورت پیشنهادی ۴۴۳).</div>';
  const ta = $('#extraLinks');
  if (document.activeElement !== ta) ta.value = (S.settings.extraLinks || []).join('\n');
}
function renderSettings() {
  const hi = $('#hostInput');
  if (document.activeElement !== hi) hi.value = S.settings.host;
  const p = S.panel;
  const rows = [
    ['نسخهٔ پنل', `${p.version} (${p.backend})`],
    ['Xray', S.xray.available ? `${S.xray.version} · uptime ${fmtUptime(S.xray.uptime)}` : 'پیدا نشد'],
    ['اتصال به پنل', p.tls ? 'HTTPS' : 'HTTP (بدون رمزنگاری؛ فقط برای localhost)'],
  ];
  if (p.certFingerprint) rows.push(['اثر انگشت گواهی SHA-256', p.certFingerprint]);
  $('#panelInfo').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
}
function renderAll() { renderHeader(); renderClients(); renderServers(); renderSettings(); }

async function load() {
  S = await api('GET', 'state');
  showApp();
  renderAll();
}
function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (document.hidden || $('#app').classList.contains('hidden') || dlg.open) return;
    try { S = await api('GET', 'state'); renderAll(); } catch { /* ignore */ }
  }, 15000);
}

/* ---------- actions ---------- */
const byId = (list, id) => list.find((x) => x.id === id);
const actions = {
  'close-dlg': () => closeDialog(),
  logout: async () => { await run(() => api('POST', 'logout')); showLogin(); },
  'add-client': async () => {
    const i = $('#newClientName');
    const r = await run(() => api('POST', 'clients', { name: i.value || 'device' }), 'کانفیگ ساخته شد');
    if (r) { S = r; i.value = ''; renderAll(); }
  },
  'copy-link': (el) => copyText(byId(S.clients, el.dataset.id).links[Number(el.dataset.i)].url),
  'qr-link': (el) => { const c = byId(S.clients, el.dataset.id); qrDialog(c.links[Number(el.dataset.i)].name, c.links[Number(el.dataset.i)].url); },
  'copy-sub': (el) => copyText(byId(S.clients, el.dataset.id).subUrl),
  'qr-sub': (el) => qrDialog('آدرس اشتراک', byId(S.clients, el.dataset.id).subUrl),
  'copy-all': (el) => {
    const c = byId(S.clients, el.dataset.id);
    copyText(c.links.map((l) => l.url).concat(S.settings.extraLinks || []).join('\n'));
  },
  'rename-client': async (el) => {
    const c = byId(S.clients, el.dataset.id);
    const f = await formDialog('تغییر نام کانفیگ', [{ key: 'name', label: 'نام', value: c.name, maxlength: 40 }]);
    if (f) { const r = await run(() => api('PATCH', `clients/${c.id}`, { name: f.name })); if (r) { S = r; renderAll(); } }
  },
  'regen-uuid': async (el) => {
    if (!(await confirmDialog('UUID جدید ساخته شود؟ لینک قبلی این کانفیگ از کار می‌افتد.', 'بساز'))) return;
    const r = await run(() => api('POST', `clients/${el.dataset.id}/regen-uuid`), 'UUID جدید ساخته شد');
    if (r) { S = r; renderAll(); }
  },
  'regen-sub': async (el) => {
    if (!(await confirmDialog('آدرس اشتراک جدید ساخته شود؟ آدرس قبلی از کار می‌افتد.', 'بساز'))) return;
    const r = await run(() => api('POST', `clients/${el.dataset.id}/regen-sub`), 'آدرس اشتراک جدید ساخته شد');
    if (r) { S = r; renderAll(); }
  },
  'delete-client': async (el) => {
    if (!(await confirmDialog('این کانفیگ حذف شود؟', 'حذف'))) return;
    const r = await run(() => api('DELETE', `clients/${el.dataset.id}`), 'حذف شد');
    if (r) { S = r; renderAll(); }
  },
  'check-dest': async () => {
    const sni = $('#ibSni').value.trim();
    const out = $('#destResult');
    out.textContent = 'در حال تست…';
    const r = await run(() => api('POST', 'check-dest', { dest: `${sni}:443` }));
    if (!r) { out.textContent = ''; return; }
    if (!r.ok) out.textContent = `✗ از سمت سرور در دسترس نیست (${r.error})`;
    else if (r.tls13 && r.h2) out.textContent = `✓ مناسب است (TLS 1.3 و h2، ${r.ms}ms)`;
    else out.textContent = `⚠ پاسخ می‌دهد ولی TLS 1.3/h2 کامل نیست؛ سایت دیگری انتخاب کن`;
  },
  'add-inbound': async () => {
    const body = { name: $('#ibName').value.trim() || 'Akhavan', port: $('#ibPort').value.trim(), sni: $('#ibSni').value.trim(), country: $('#ibCc').value.trim() };
    const r = await run(() => api('POST', 'inbounds', body), 'سرور اضافه شد');
    if (r) { S = r; $('#ibName').value = ''; $('#ibPort').value = ''; $('#ibCc').value = ''; renderAll(); }
  },
  'toggle-inbound': async (el) => { const r = await run(() => api('PATCH', `inbounds/${el.dataset.id}`, { enabled: el.checked })); if (r) S = r; renderAll(); },
  'toggle-client': async (el) => { const r = await run(() => api('PATCH', `clients/${el.dataset.id}`, { enabled: el.checked })); if (r) S = r; renderAll(); },
  'edit-inbound': async (el) => {
    const ib = byId(S.inbounds, el.dataset.id);
    const f = await formDialog('ویرایش سرور', [
      { key: 'name', label: 'نام', value: ib.name, maxlength: 40 },
      { key: 'port', label: 'پورت', value: ib.port, ltr: true },
      { key: 'sni', label: 'SNI', value: ib.sni, ltr: true },
      { key: 'country', label: 'کد کشور', value: ib.country, ltr: true, maxlength: 2 },
    ]);
    if (!f) return;
    const r = await run(() => api('PATCH', `inbounds/${ib.id}`, f), 'ذخیره شد');
    if (r) { S = r; renderAll(); }
  },
  'regen-keys': async (el) => {
    if (!(await confirmDialog('کلید Reality جدید ساخته شود؟ همهٔ لینک‌های این سرور باید دوباره وارد شوند.', 'بساز'))) return;
    const r = await run(() => api('POST', `inbounds/${el.dataset.id}/regen-keys`), 'کلید جدید ساخته شد');
    if (r) { S = r; renderAll(); }
  },
  'delete-inbound': async (el) => {
    if (!(await confirmDialog('این سرور حذف شود؟', 'حذف'))) return;
    const r = await run(() => api('DELETE', `inbounds/${el.dataset.id}`), 'حذف شد');
    if (r) { S = r; renderAll(); }
  },
  'save-extra': async () => {
    const lines = $('#extraLinks').value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const r = await run(() => api('PUT', 'settings', { extraLinks: lines }), 'ذخیره شد');
    if (r) { S = r; renderAll(); }
  },
  'save-host': async () => {
    const r = await run(() => api('PUT', 'settings', { host: $('#hostInput').value.trim() }), 'ذخیره شد');
    if (r) { S = r; renderAll(); }
  },
  'change-password': async () => {
    const cur = $('#pwCur').value; const nxt = $('#pwNew').value;
    const r = await run(() => api('POST', 'password', { current: cur, next: nxt }), 'رمز تغییر کرد؛ دوباره وارد شو');
    if (r) { $('#pwCur').value = ''; $('#pwNew').value = ''; showLogin(); }
  },
  'refresh-logs': async () => {
    const r = await run(() => api('GET', 'xray/logs'));
    if (r) { const b = $('#logBox'); b.textContent = r.logs.join('\n') || '(گزارشی نیست)'; b.scrollTop = b.scrollHeight; }
  },
  'restart-xray': async () => {
    const r = await run(() => api('POST', 'xray/restart'), 'Xray دوباره راه‌اندازی شد');
    if (r) { S = r; renderAll(); }
  },
};

document.addEventListener('click', (e) => {
  const tab = e.target.closest('[data-tab]');
  if (tab) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    $$('.page').forEach((p) => p.classList.toggle('hidden', p.id !== `page-${tab.dataset.tab}`));
    if (tab.dataset.tab === 'logs') actions['refresh-logs']();
    return;
  }
  const el = e.target.closest('[data-action]');
  if (!el || el.tagName === 'INPUT') return;
  const fn = actions[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
document.addEventListener('change', (e) => {
  const el = e.target;
  if (el.tagName === 'INPUT' && el.type === 'checkbox' && actions[el.dataset.action]) actions[el.dataset.action](el);
});

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#lErr').textContent = '';
  try {
    await api('POST', 'login', { username: $('#lUser').value.trim(), password: $('#lPass').value });
    await load();
    startPolling();
  } catch (err) { $('#lErr').textContent = err.message; }
});

(async function init() {
  try { await load(); startPolling(); } catch { showLogin(); }
})();
