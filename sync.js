// Dropbox-Anbindung. Login per OAuth mit PKCE direkt aus dem Browser, ohne Server: der App-Schlüssel ist öffentlich,
// ein Geheimnis gibt es nicht. Der Erneuerungsschlüssel gilt unbegrenzt, man meldet sich also einmal pro Gerät an.
// Nutzt aus index.html: $, t, esc, toast, openDlg.
const DBX_KEY = 'r5cm8btj0otythh'; // App-Schlüssel aus der Dropbox-Konsole; leer = Sync-Bereich ausgeblendet
const DBX_STORE = 'ca-dropbox'; // pro Gerät: Schlüssel, Kontoname, PKCE-Zwischenwerte

const dbx = {
  get() { try { return JSON.parse(localStorage.getItem(DBX_STORE)) || {}; } catch { return {}; } },
  set(v) { localStorage.setItem(DBX_STORE, JSON.stringify(v)); }
};
// muss exakt einer in der Dropbox-Konsole eingetragenen Rücksprung-Adresse entsprechen
const redirectUri = () => location.origin + location.pathname.replace(/index\.html$/, '');
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// manual = Plan B ohne Rücksprung: Dropbox zeigt einen Code an, den man in die App kopiert
async function dbxStart(manual) {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  // localStorage statt sessionStorage: der Rücksprung kann in einem anderen Fenster landen (iPhone-Homescreen-App)
  dbx.set({verifier, state});
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

async function dbxToken(params) {
  const r = await fetch('https://api.dropboxapi.com/oauth2/token', {method: 'POST', body: new URLSearchParams({client_id: DBX_KEY, ...params})});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error_description || j.error || 'HTTP ' + r.status);
  return j;
}
async function dbxExchange(code, withRedirect) {
  const {verifier} = dbx.get();
  const j = await dbxToken({code, grant_type: 'authorization_code', code_verifier: verifier, ...(withRedirect ? {redirect_uri: redirectUri()} : {})});
  dbx.set({refresh: j.refresh_token, access: j.access_token, exp: Date.now() + j.expires_in * 1000});
  manualPending = false;
  const acc = await dbxCall('users/get_current_account');
  dbx.set({...dbx.get(), name: acc.name?.display_name || '', email: acc.email || ''});
  renderSync();
  toast(t('sync.connected'));
}
// gültiger Zugangsschlüssel; eine Minute vor Ablauf wird still erneuert
async function dbxAccess() {
  const s = dbx.get();
  if (!s.refresh) throw new Error('not connected');
  if (s.access && s.exp > Date.now() + 60000) return s.access;
  const j = await dbxToken({grant_type: 'refresh_token', refresh_token: s.refresh});
  dbx.set({...s, access: j.access_token, exp: Date.now() + j.expires_in * 1000});
  return j.access_token;
}
async function dbxCall(endpoint, args) {
  const r = await fetch('https://api.dropboxapi.com/2/' + endpoint, {method: 'POST',
    headers: {Authorization: 'Bearer ' + await dbxAccess(), ...(args ? {'Content-Type': 'application/json'} : {})},
    body: args ? JSON.stringify(args) : null});
  if (!r.ok) throw new Error((await r.text().catch(() => '')) || 'HTTP ' + r.status);
  return r.status === 200 && r.headers.get('Content-Type')?.includes('json') ? r.json() : null;
}
async function dbxDisconnect() {
  try { await dbxCall('auth/token/revoke'); } catch {} // offline o. Ä.: lokal trotzdem trennen
  localStorage.removeItem(DBX_STORE);
  renderSync();
  toast(t('sync.disconnected'));
}

function renderSync() {
  const box = $('syncBox');
  box.hidden = !DBX_KEY;
  const s = dbx.get();
  box.innerHTML = `<span class="flabel">${t('sync.title')}</span>` + (s.refresh
    ? `<p class="note">${t('sync.as', esc(s.name), esc(s.email))}</p><div class="langs"><button type="button" id="dbxOff">${t('sync.disconnect')}</button></div>`
    : manualPending
    ? `<form class="langs" id="dbxCodeForm"><label for="dbxCode" class="note">${t('sync.pasteCode')}</label>
       <input id="dbxCode" autocomplete="off" autocapitalize="off" spellcheck="false" required>
       <button class="primary">${t('sync.confirm')}</button><button type="button" class="link" id="dbxBack">${t('sync.back')}</button></form>`
    : `<p class="note">${t('sync.intro')}</p><div class="langs"><button type="button" class="primary" id="dbxOn">${t('sync.connect')}</button>
       <button type="button" class="link" id="dbxManual">${t('sync.manual')}</button></div>`);
}
const syncFail = err => toast(t('sync.failed') + ' (' + err.message + ')', true);
$('syncBox').onclick = e => {
  if (e.target.id === 'dbxOn') dbxStart(false).catch(syncFail);
  else if (e.target.id === 'dbxManual') dbxStart(true).catch(syncFail);
  else if (e.target.id === 'dbxOff') dbxDisconnect();
  else if (e.target.id === 'dbxBack') { manualPending = false; renderSync(); }
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
  catch (err) { toast(t('sync.failed') + ' (' + err.message + ')', true); }
})();
renderSync();
