// Dropbox-Anbindung. Login per OAuth mit PKCE direkt aus dem Browser, ohne Server: der App-Schlüssel ist öffentlich,
// ein Geheimnis gibt es nicht. Der Erneuerungsschlüssel gilt unbegrenzt, man meldet sich also einmal pro Gerät an.
// Nutzt aus index.html: $, t, esc, toast, openDlg, fmtDate, render, save, merge, parseData, ts, shots, graves, dataReady.
const DBX_KEY = 'r5cm8btj0otythh'; // App-Schlüssel aus der Dropbox-Konsole; leer = Sync-Bereich ausgeblendet
const DBX_STORE = 'ca-dropbox'; // pro Gerät: Schlüssel, Konto, ob schon einmal abgeglichen, letzter Abgleich
const OPT_IMG = 'ca-offline-images'; // pro Gerät: Bilder vorhalten (Standard) oder nur bei Bedarf laden
const offlineImages = () => localStorage.getItem(OPT_IMG) !== '0';

const dbx = {
  get() { try { return JSON.parse(localStorage.getItem(DBX_STORE)) || {}; } catch { return {}; } },
  set(v) { localStorage.setItem(DBX_STORE, JSON.stringify(v)); }
};
// muss exakt einer in der Dropbox-Konsole eingetragenen Rücksprung-Adresse entsprechen
const redirectUri = () => location.origin + location.pathname.replace(/index\.html$/, '');
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// ---------- Login ----------

// manual = Plan B ohne Rücksprung: Dropbox zeigt einen Code an, den man in die App kopiert
async function dbxStart(manual) {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  const s = dbx.get();
  // localStorage statt sessionStorage: der Rücksprung kann in einem anderen Fenster landen (iPhone-Homescreen-App).
  // prev: bei „Neu verbinden“ mit demselben Konto gilt der Abgleich weiter als eingerichtet
  dbx.set({verifier, state, prev: s.synced ? s.account : s.prev});
  const p = new URLSearchParams({client_id: DBX_KEY, response_type: 'code', code_challenge: challenge,
    code_challenge_method: 'S256', token_access_type: 'offline'});
  if (!manual) { p.set('redirect_uri', redirectUri()); p.set('state', state); }
  const url = 'https://www.dropbox.com/oauth2/authorize?' + p;
  if (!manual) return location.assign(url);
  window.open(url, '_blank');
  // Eingabefeld statt prompt(): Chrome unterdrückt Dialoge, solange der Tab im Hintergrund ist
  manualPending = true;
  renderSync();
}
let manualPending = false;

class DbxError extends Error {
  constructor(status, summary) { super(summary || 'HTTP ' + status); this.status = status; }
}
async function check(r) {
  if (r.ok) return r;
  const text = await r.text().catch(() => '');
  let s = '';
  try { s = JSON.parse(text).error_summary; } catch {} // manche Fehler (z. B. fehlende Berechtigung) sind reiner Text
  throw new DbxError(r.status, s || text.slice(0, 300));
}

async function dbxToken(params) {
  const r = await fetch('https://api.dropboxapi.com/oauth2/token', {method: 'POST', body: new URLSearchParams({client_id: DBX_KEY, ...params})});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new DbxError(r.status, j.error || j.error_description);
  return j;
}
async function dbxExchange(code, withRedirect) {
  const {verifier, prev} = dbx.get();
  const j = await dbxToken({code, grant_type: 'authorization_code', code_verifier: verifier, ...(withRedirect ? {redirect_uri: redirectUri()} : {})});
  dbx.set({refresh: j.refresh_token, access: j.access_token, exp: Date.now() + j.expires_in * 1000, account: j.account_id, synced: !!prev && prev === j.account_id});
  manualPending = false;
  const acc = await dbxCall('users/get_current_account');
  dbx.set({...dbx.get(), name: acc.name?.display_name || '', email: acc.email || ''});
  setState('idle');
  toast(t('sync.connected'));
  syncSoon(0);
}
// gültiger Zugangsschlüssel; eine Minute vor Ablauf wird still erneuert
async function dbxAccess() {
  const s = dbx.get();
  if (!s.refresh) throw new DbxError(401, 'not connected');
  if (s.access && s.exp > Date.now() + 60000) return s.access;
  const j = await dbxToken({grant_type: 'refresh_token', refresh_token: s.refresh});
  dbx.set({...dbx.get(), access: j.access_token, exp: Date.now() + j.expires_in * 1000});
  return j.access_token;
}
async function dbxCall(endpoint, args) {
  const r = await check(await fetch('https://api.dropboxapi.com/2/' + endpoint, {method: 'POST',
    headers: {Authorization: 'Bearer ' + await dbxAccess(), ...(args ? {'Content-Type': 'application/json'} : {})},
    body: args ? JSON.stringify(args) : null}));
  return r.headers.get('Content-Type')?.includes('json') ? r.json() : null;
}
// Datei-Endpunkte: Parameter im Header, Inhalt im Körper. Fehler wertet der Aufrufer aus (409 ist teils erwartet).
async function dbxContent(endpoint, arg, body) {
  return fetch('https://content.dropboxapi.com/2/' + endpoint, {method: 'POST',
    headers: {Authorization: 'Bearer ' + await dbxAccess(), 'Dropbox-API-Arg': JSON.stringify(arg),
      ...(body ? {'Content-Type': 'application/octet-stream'} : {})}, body: body || null});
}
const summaryOf = async r => (await r.json().catch(() => ({}))).error_summary || '';

// ---------- Dateien in der Dropbox ----------
// /data.json  = {app, version, shots, deleted}; Bilder darin als Verweis „img:<Name>“
// /images/<Name> = die Bilder, Name = SHA-256 des Inhalts: dasselbe Bild liegt nie doppelt dort

// erst die Versionskennung, dann genau diese Version laden: so passen Inhalt und Kennung sicher zusammen
async function pull() {
  let rev;
  try { ({rev} = await dbxCall('files/get_metadata', {path: '/data.json'})); }
  catch (e) { if (e.message.includes('not_found')) return {rev: null, text: null, data: null}; throw e; }
  const text = await (await check(await dbxContent('files/download', {path: 'rev:' + rev}))).text();
  return {rev, text, data: parseData(JSON.parse(text))}; // kaputte Datei: Fehler, es wird nichts überschrieben
}
// nur hochladen, wenn data.json seit dem Laden unverändert ist; false = jemand war schneller, von vorn beginnen
async function push(text, rev) {
  const r = await dbxContent('files/upload', {path: '/data.json', mode: rev ? {'.tag': 'update', update: rev} : {'.tag': 'add'},
    autorename: false, mute: true}, new Blob([text]));
  if (r.status === 409) {
    const s = await summaryOf(r);
    if (s.includes('conflict')) return false;
    throw new DbxError(409, s);
  }
  await check(r);
  return true;
}
async function remoteImages() {
  const names = new Set();
  try {
    let r = await dbxCall('files/list_folder', {path: '/images'});
    for (;;) {
      r.entries.forEach(e => names.add(e.name));
      if (!r.has_more) break;
      r = await dbxCall('files/list_folder/continue', {cursor: r.cursor});
    }
  } catch (e) { if (!e.message.includes('not_found')) throw e; } // Ordner gibt es noch nicht
  return names;
}
const names = new Map(); // data-URL → Name (Rechnen kostet, Bilder ändern sich nicht)
async function imgName(dataUrl) {
  if (!names.has(dataUrl)) {
    const blob = await (await fetch(dataUrl)).blob();
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()))]
      .map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 40);
    names.set(dataUrl, hash + '.' + ((blob.type.split('/')[1] || 'bin').replace('jpeg', 'jpg').replace(/[^a-z0-9]/g, '') || 'bin'));
  }
  return names.get(dataUrl);
}
async function uploadImg(name, dataUrl) {
  const r = await dbxContent('files/upload', {path: '/images/' + name, mode: {'.tag': 'add'}, autorename: false, mute: true},
    await (await fetch(dataUrl)).blob());
  if (r.status === 409 && (await summaryOf(r)).includes('conflict')) return; // liegt schon dort
  await check(r);
}
// Dropbox liefert jede Datei als application/octet-stream; den Bildtyp gibt die Endung im Namen vor
const IMG_TYPES = {jpg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', svgxml: 'image/svg+xml', avif: 'image/avif'};
async function downloadImg(name) {
  const blob = await (await check(await dbxContent('files/download', {path: '/images/' + name}))).blob();
  const typed = new Blob([blob], {type: IMG_TYPES[name.split('.').pop()] || blob.type});
  return new Promise((res, rej) => { const f = new FileReader(); f.onload = () => res(f.result); f.onerror = rej; f.readAsDataURL(typed); });
}

// Bilder nur bei Bedarf (Option aus): einmal geladene bleiben für diese Sitzung im Speicher
const urls = new Map(), loading = new Set();
window.imgUrl = ref => {
  const n = ref.slice(4);
  if (urls.has(n)) return urls.get(n);
  if (dbx.get().refresh && navigator.onLine && !loading.has(n)) {
    loading.add(n);
    downloadImg(n).then(u => { urls.set(n, u); render(); }).catch(() => {}).finally(() => loading.delete(n));
  }
  return null;
};

// ---------- Abgleich ----------

class Later extends Error {} // Nutzer hat die Frage beim ersten Verbinden vertagt
const sig = d => d.shots.map(s => s.id + ':' + ts(s)).join() + '|' + Object.entries(d.deleted).join();
const stampName = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');

// ein Durchlauf; false = data.json wurde zwischendurch von einem anderen Gerät geändert
async function syncOnce() {
  const remote = await pull();
  if (!dbx.get().synced && remote.data?.shots.length && shots.length) {
    const choice = await askFirst(shots.length, remote.data.shots.length);
    if (!choice) throw new Later();
    if (choice === 'remote') { shots = []; graves = {}; } // Sicherung wurde schon beim Tippen exportiert
    if (choice === 'local') {
      await dbxCall('files/copy_v2', {from_path: '/data.json', to_path: `/backup-${stampName()}.json`, autorename: true});
      // was nur in der Dropbox liegt, verschwindet auch auf den anderen Geräten
      const mine = new Set(shots.map(s => s.id)), now = Date.now();
      for (const s of remote.data.shots) if (!mine.has(s.id)) graves[s.id] = Math.max(now, ts(s));
      save(false);
    }
  }
  // zusammenführen ohne await dazwischen, damit keine gleichzeitige Eingabe verloren geht
  if (remote.data) {
    const m = merge({shots, deleted: graves}, remote.data);
    if (sig(m) !== sig({shots, deleted: graves}) || m.shots.some((s, i) => s !== shots[i])) { ({shots, deleted: graves} = m); save(false); }
  }
  const mine = shots, deleted = {...graves};
  const have = await remoteImages();
  const out = [];
  for (const s of mine) {
    if (!s.image?.startsWith('data:')) { out.push(s); continue; }
    const name = await imgName(s.image);
    if (!have.has(name)) { await uploadImg(name, s.image); have.add(name); }
    out.push({...s, image: 'img:' + name});
  }
  const text = JSON.stringify({app: 'caffeine-analytica', version: 2, shots: out, deleted});
  if (text !== remote.text && !await push(text, remote.rev)) return false;
  dbx.set({...dbx.get(), synced: true, last: Date.now()});
  await localImages(have);
  return true;
}

// Option an: fehlende Bilder herunterladen. Option aus: Bilder, die sicher in der Dropbox liegen, vom Gerät entfernen.
async function localImages(have) {
  const got = new Map();
  if (offlineImages()) {
    for (const n of new Set(shots.filter(s => s.image?.startsWith('img:')).map(s => s.image.slice(4))))
      got.set(n, urls.get(n) || await downloadImg(n));
  } else {
    for (const s of shots) if (s.image?.startsWith('data:')) {
      const n = await imgName(s.image);
      if (have.has(n)) { urls.set(n, s.image); got.set(s.image, 'img:' + n); } // bleibt diese Sitzung angezeigt
    }
  }
  if (!got.size) return;
  let changed = false;
  for (const s of shots) {
    const v = s.image?.startsWith('img:') ? got.get(s.image.slice(4)) : got.get(s.image);
    if (v && v !== s.image) { s.image = v; changed = true; }
  }
  if (changed) save(false);
}

// ---------- Ablaufsteuerung und Status ----------
let state = 'idle', lastError = '', running = null, again = false, timer = 0;
function setState(s, err = '') {
  state = s; lastError = err;
  const dot = $('syncDot'), connected = !!dbx.get().refresh;
  dot.hidden = !connected || s === 'idle';
  dot.classList.toggle('bad', s === 'error' || s === 'auth');
  renderSync();
}
window.syncSoon = (delay = 2000) => {
  if (!dbx.get().refresh) return;
  if (state !== 'auth') setState('pending');
  clearTimeout(timer);
  timer = setTimeout(syncNow, delay);
};
async function syncNow() {
  if (!dbx.get().refresh || !dataReady || state === 'auth') return;
  if (running) { again = true; return running; }
  if (!navigator.onLine) return setState('pending');
  setState('running');
  running = (async () => {
    try {
      let ok = false;
      for (let i = 0; i < 3 && !ok; i++) ok = await syncOnce();
      if (!ok) throw new Error('conflict');
      setState('idle');
    } catch (e) {
      if (e instanceof Later) setState('pending');
      // fehlende Berechtigung: Dropbox vergibt sie beim Verbinden, nach dem Freischalten also neu verbinden
      else if (e.status === 401 || /invalid_grant|expired_access_token|missing_scope|required scope/.test(e.message)) setState('auth');
      else if (e instanceof TypeError) setState('pending'); // Netzwerk weg
      else setState('error', e.message.includes('insufficient_space') ? t('sync.full') : e.message);
    } finally {
      running = null;
      if (again) { again = false; syncNow(); }
    }
  })();
  return running;
}
addEventListener('online', () => syncSoon(0));
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') syncSoon(0); });

// Frage beim ersten Verbinden, wenn auf beiden Seiten schon Daten liegen
function askFirst(local, remote) {
  const d = $('firstDlg');
  d.innerHTML = `<h3 id="firstTitle">${t('sync.first.title')}</h3><p>${t('sync.first.text', local, remote)}</p><div class="langs">
    <button class="primary" data-c="merge">${t('sync.first.merge')}</button><small>${t('sync.first.mergeHint')}</small>
    <button data-c="remote">${t('sync.first.remote')}</button><small>${t('sync.first.remoteHint')}</small>
    <button data-c="local">${t('sync.first.local')}</button><small>${t('sync.first.localHint')}</small>
    <button class="link" data-c="">${t('sync.first.later')}</button></div>`;
  if ($('setDlg').open) $('setDlg').close();
  openDlg(d);
  return new Promise(res => {
    d.onclick = e => {
      const b = e.target.closest('[data-c]');
      if (!b) return;
      // Sicherung vor dem Ersetzen: hier im Tipp, denn das Teilen-Menü auf dem iPhone braucht eine Nutzeraktion
      if (b.dataset.c === 'remote') $('export').onclick();
      d.onclose = null;
      d.close();
      res(b.dataset.c);
    };
    d.onclose = () => res(''); // Esc = später entscheiden
  });
}

async function dbxDisconnect() {
  // Option aus: Bilder, die nur in der Dropbox liegen, vorher holen, sonst fehlen sie danach (nach Rückfrage)
  const refs = [...new Set(shots.filter(s => s.image?.startsWith('img:')).map(s => s.image.slice(4)))];
  if (refs.length) {
    try {
      const got = new Map();
      for (const n of refs) got.set(n, urls.get(n) || await downloadImg(n));
      shots.forEach(s => { if (s.image?.startsWith('img:')) s.image = got.get(s.image.slice(4)); });
      save(false);
    } catch { if (!confirm(t('sync.missingImgs', refs.length))) return; }
  }
  try { await dbxCall('auth/token/revoke'); } catch {} // offline o. Ä.: lokal trotzdem trennen
  localStorage.removeItem(DBX_STORE);
  localStorage.removeItem(OPT_IMG);
  clearTimeout(timer);
  setState('idle');
  toast(t('sync.disconnected'));
}

// Dropbox-Logo (offene Box aus fünf Rauten)
const DBX_ICON = '<svg class="brand" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 1.81 0 5.63l6 3.82 6-3.82zm12 0-6 3.82 6 3.82 6-3.82zM0 13.27l6 3.83 6-3.83-6-3.82zm18-3.82-6 3.82 6 3.83 6-3.83zM6 18.37l6 3.82 6-3.82-6-3.82z"/></svg>';
const SYNC_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
function renderSync() {
  const box = $('syncBox');
  box.hidden = !DBX_KEY;
  const s = dbx.get();
  const status = state === 'running' ? t('sync.st.running') : state === 'pending' ? t('sync.st.pending')
    : state === 'auth' ? t('sync.st.auth') : state === 'error' ? t('sync.st.error', esc(lastError))
    : s.last ? t('sync.st.idle', fmtDate(s.last)) : '';
  box.innerHTML = `<span class="flabel">${t('sync.title')}</span>` + (s.refresh
    ? `<div class="syncrow"><div><p class="note">${t('sync.as', esc(s.name), esc(s.email))}</p>
       ${status ? `<p class="note state${state === 'error' || state === 'auth' ? ' bad' : ''}" role="status">${status}</p>` : ''}</div>
       ${state === 'auth' ? '' : `<button type="button" class="icon" id="dbxNow" title="${t('sync.now')}" aria-label="${t('sync.now')}"${state === 'running' ? ' disabled' : ''}>${SYNC_ICON}</button>`}</div>
       <div class="langs">${state === 'auth' ? `<button type="button" class="dbx" id="dbxOn">${DBX_ICON}${t('sync.reconnect')}</button>` : ''}
       <button type="button" class="swrow" id="dbxImg" role="switch" aria-checked="${offlineImages()}">${t('sync.offlineImgs')}<span class="sw" aria-hidden="true"></span></button>
       <button type="button" class="destructive" id="dbxOff">${t('sync.disconnect')}</button></div>`
    : manualPending
    ? `<form class="langs" id="dbxCodeForm"><label for="dbxCode" class="note">${t('sync.pasteCode')}</label>
       <input id="dbxCode" autocomplete="off" autocapitalize="off" spellcheck="false" required>
       <button class="primary">${t('sync.confirm')}</button><button type="button" class="link" id="dbxBack">${t('sync.back')}</button></form>`
    : `<p class="note">${t('sync.intro')}</p><div class="langs"><button type="button" class="dbx" id="dbxOn">${DBX_ICON}${t('sync.connect')}</button>
       <button type="button" class="link" id="dbxManual">${t('sync.manual')}</button></div>`);
}
const syncFail = err => toast(t('sync.failed') + ' (' + err.message + ')', true);
$('syncBox').onclick = e => {
  const id = e.target.closest('button')?.id; // Tipp auf Logo oder Schieber zählt für den Knopf
  if (id === 'dbxOn') dbxStart(false).catch(syncFail);
  else if (id === 'dbxManual') dbxStart(true).catch(syncFail);
  else if (id === 'dbxOff') dbxDisconnect();
  else if (id === 'dbxBack') { manualPending = false; renderSync(); }
  else if (id === 'dbxNow') syncSoon(0);
  else if (id === 'dbxImg') { localStorage.setItem(OPT_IMG, offlineImages() ? '0' : '1'); syncSoon(0); }
};
$('syncBox').onsubmit = e => {
  e.preventDefault();
  dbxExchange($('dbxCode').value.trim(), false).catch(syncFail);
};

// Rücksprung von Dropbox: ?code=…&state=… (oder ?error=… bei Abbruch)
(async () => {
  const q = new URLSearchParams(location.search);
  if (!q.has('code') && !q.has('error')) return;
  history.replaceState(null, '', redirectUri()); // Code nicht in der Adresszeile oder im Verlauf lassen
  if (q.has('error')) return toast(t('sync.denied'), true);
  if (q.get('state') !== dbx.get().state) return toast(t('sync.failed'), true);
  try { await dbxExchange(q.get('code'), true); openDlg($('setDlg')); }
  catch (err) { syncFail(err); }
})();
setState('idle');
// Abgleich beim Öffnen: index.html stößt ihn nach dem Laden der Daten an. Waren die Daten schneller geladen
// als diese Datei (IndexedDB ist meist schneller als das Netz), lief der Aufruf ins Leere, also hier nachholen.
if (dataReady) syncSoon(0);
