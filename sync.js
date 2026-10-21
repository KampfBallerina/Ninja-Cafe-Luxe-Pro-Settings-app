// Dropbox-Anbindung. Login per OAuth mit PKCE direkt aus dem Browser, ohne Server: der App-Schlüssel ist öffentlich,
// ein Geheimnis gibt es nicht. Der Erneuerungsschlüssel gilt unbegrenzt, man meldet sich also einmal pro Gerät an.
// Nutzt aus index.html: $, t, esc, toast, openDlg, fmtDate, render, save, merge, parseData, ts, shots, graves, dataReady,
// ME_KEY, mine, favsOf.
const DBX_KEY = 'xss99a55z0g75yq'; // App-Schlüssel aus der Dropbox-Konsole; leer = Sync-Bereich ausgeblendet
// pro Gerät: Schlüssel, Konto, ob schon einmal abgeglichen, letzter Abgleich, genutzter geteilter Ordner (ns, owner)
const DBX_STORE = 'ca-dropbox';
// Eigene Daten liegen in diesem Ordner. Ein geteilter Ordner heißt und liegt bei jedem anders, darum wird er über seine
// ID angesprochen (Kopfzeile Dropbox-API-Path-Root), die Pfade darin beginnen dann direkt mit /data.json.
const FOLDER = '/Caffeine Analytica';
const at = p => (dbx.get().ns ? '' : FOLDER) + p;
const pathRoot = endpoint => dbx.get().ns && endpoint.startsWith('files/')
  ? {'Dropbox-API-Path-Root': JSON.stringify({'.tag': 'namespace_id', namespace_id: dbx.get().ns})} : {};
const OPT_IMG = 'ca-offline-images'; // pro Gerät: Bilder nur bei Bedarf aus der Dropbox laden (Standard) oder vorhalten
const offlineImages = () => localStorage.getItem(OPT_IMG) === '1';

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
  // prev: bei „Neu verbinden“ mit demselben Konto gilt der Abgleich weiter als eingerichtet, samt geteiltem Ordner
  dbx.set({verifier, state, prev: s.synced ? {account: s.account, ns: s.ns, owner: s.owner} : s.prev});
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
  const same = prev?.account === j.account_id;
  dbx.set({key: DBX_KEY, refresh: j.refresh_token, access: j.access_token, exp: Date.now() + j.expires_in * 1000, account: j.account_id,
    synced: same, ...(same && prev.ns ? {ns: prev.ns, owner: prev.owner} : {})});
  manualPending = false;
  const acc = await dbxCall('users/get_current_account');
  dbx.set({...dbx.get(), name: acc.name?.display_name || '', email: acc.email || ''});
  localStorage.setItem(ME_KEY, JSON.stringify({id: j.account_id, name: acc.name?.display_name || acc.email || ''}));
  setState('idle');
  toast(t('sync.connected'));
  if (!dbx.get().ns) await offerShares(true).catch(syncFail);
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
    headers: {Authorization: 'Bearer ' + await dbxAccess(), ...pathRoot(endpoint), ...(args ? {'Content-Type': 'application/json'} : {})},
    body: args ? JSON.stringify(args) : null}));
  return r.headers.get('Content-Type')?.includes('json') ? r.json() : null;
}
// Datei-Endpunkte: Parameter im Header, Inhalt im Körper. Fehler wertet der Aufrufer aus (409 ist teils erwartet).
// home = Pfad in der eigenen Dropbox, auch wenn gerade ein geteilter Ordner genutzt wird
async function dbxContent(endpoint, arg, body, home) {
  return fetch('https://content.dropboxapi.com/2/' + endpoint, {method: 'POST',
    headers: {Authorization: 'Bearer ' + await dbxAccess(), ...(home ? {} : pathRoot(endpoint)), 'Dropbox-API-Arg': JSON.stringify(arg),
      ...(body ? {'Content-Type': 'application/octet-stream'} : {})}, body: body || null});
}
const summaryOf = async r => (await r.json().catch(() => ({}))).error_summary || '';

// ---------- Dateien in der Dropbox ----------
// /data.json  = {app, version, shots, deleted}; Bilder darin als Verweis „img:<Name>“
// /images/<Name> = die Bilder, Name = SHA-256 des Inhalts: dasselbe Bild liegt nie doppelt dort

// erst die Versionskennung, dann genau diese Version laden: so passen Inhalt und Kennung sicher zusammen
async function pull() {
  let rev;
  try { ({rev} = await dbxCall('files/get_metadata', {path: at('/data.json')})); }
  catch (e) { if (e.message.includes('not_found')) return {rev: null, text: null, data: null}; throw e; }
  const text = await (await check(await dbxContent('files/download', {path: 'rev:' + rev}))).text();
  return {rev, text, data: parseData(JSON.parse(text))}; // kaputte Datei: Fehler, es wird nichts überschrieben
}
// nur hochladen, wenn data.json seit dem Laden unverändert ist; false = jemand war schneller, von vorn beginnen
async function push(text, rev) {
  const r = await dbxContent('files/upload', {path: at('/data.json'), mode: rev ? {'.tag': 'update', update: rev} : {'.tag': 'add'},
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
    let r = await dbxCall('files/list_folder', {path: at('/images')});
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
async function uploadImg(name, blob) {
  const r = await dbxContent('files/upload', {path: at('/images/' + name), mode: {'.tag': 'add'}, autorename: false, mute: true}, blob);
  if (r.status === 409 && (await summaryOf(r)).includes('conflict')) return; // liegt schon dort
  await check(r);
}
// Dropbox liefert jede Datei als application/octet-stream; den Bildtyp gibt die Endung im Namen vor
const IMG_TYPES = {jpg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', svgxml: 'image/svg+xml', avif: 'image/avif'};
async function downloadImg(name) {
  const blob = await (await check(await dbxContent('files/download', {path: at('/images/' + name)}))).blob();
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
const OLD_IMAGES = '/Apps/Caffeine Analytica/images/';
const lost = new Set(); // Bilder, die nirgends zu finden sind: in dieser Sitzung nicht erneut suchen
const stampName = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');

// ein Durchlauf; false = data.json wurde zwischendurch von einem anderen Gerät geändert
async function syncOnce() {
  const remote = await pull();
  await refreshOwner();
  if (!dbx.get().synced) claim();
  // erstes Verbinden: nur fragen, wenn beide Seiten Shots haben, die der anderen fehlen; sonst verliert Zusammenführen nichts
  const there = new Set(remote.data?.shots.map(s => s.id)), here = new Set(shots.map(s => s.id));
  const onlyHere = shots.filter(s => !there.has(s.id)).length, onlyThere = (remote.data?.shots || []).filter(s => !here.has(s.id)).length;
  if (!dbx.get().synced && onlyHere && onlyThere) {
    const choice = await askFirst(onlyHere, onlyThere, shots.length, remote.data.shots.length);
    if (!choice) throw new Later();
    if (choice === 'remote') { shots = []; graves = {}; } // Sicherung wurde schon beim Tippen exportiert
    if (choice === 'local') {
      await dbxCall('files/copy_v2', {from_path: at('/data.json'), to_path: at(`/backup-${stampName()}.json`), autorename: true});
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
    if (!have.has(name)) { await uploadImg(name, await (await fetch(s.image)).blob()); have.add(name); }
    out.push({...s, image: 'img:' + name});
  }
  // Bilder, die hier fehlen, aus dem Ordner der früheren Dropbox-App übernehmen (bis 1.2.0 lag alles in Apps/…)
  for (const n of new Set(out.filter(s => s.image?.startsWith('img:')).map(s => s.image.slice(4)))) {
    if (have.has(n) || lost.has(n)) continue;
    const r = await dbxContent('files/download', {path: OLD_IMAGES + n}, null, true);
    if (r.status === 409) { lost.add(n); continue; } // auch dort nicht: bleibt ein Platzhalter
    await uploadImg(n, await (await check(r)).blob());
    have.add(n);
  }
  const text = JSON.stringify({app: 'caffeine-analytica', version: 2, shots: out, deleted});
  if (text !== remote.text && !await push(text, remote.rev)) return false;
  dbx.set({...dbx.get(), synced: true, last: Date.now()});
  await localImages(have);
  return true;
}

// Shots ohne Ersteller und Favoriten von vor dem ersten Verbinden ('local' oder altes fav: true) gehören diesem Konto.
// Läuft vor dem Zusammenführen, betrifft also nur, was auf diesem Gerät entstanden ist.
function claim() {
  const m = mine();
  if (!m) return;
  let changed = false;
  for (const s of shots) {
    if (!s.by) { s.by = m; changed = true; }
    if (s.fav || s.favs?.includes('local')) {
      s.favs = [...new Set(favsOf(s).map(id => id === 'local' ? m.id : id))];
      delete s.fav;
      changed = true;
    }
  }
  if (changed) save(); // neuer Änderungszeitpunkt, damit es beim Zusammenführen gewinnt
}

// Option an: fehlende Bilder herunterladen. Option aus: Bilder, die sicher in der Dropbox liegen, vom Gerät entfernen.
async function localImages(have) {
  const got = new Map();
  if (offlineImages()) {
    for (const n of new Set(shots.filter(s => s.image?.startsWith('img:')).map(s => s.image.slice(4)))) {
      if (lost.has(n)) continue; // fehlt in der Dropbox: kein Grund, den ganzen Abgleich abzubrechen
      got.set(n, urls.get(n) || await downloadImg(n));
    }
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
  if (!dbx.get().refresh || !dataReady || state === 'auth' || choosing) return;
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
      // kein Zugriff mehr auf den geteilten Ordner (entfernt worden oder Teilen beendet): mit den eigenen Daten weiter
      else if (dbx.get().ns && (e.status === 422 || /no_permission|invalid_root/.test(e.message))) {
        toast(dbx.get().owner ? t('share.lost', dbx.get().owner) : t('share.ended'), true);
        ownFolder();
      }
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

// Auswahl im Fenster firstDlg; liefert data-c der getippten Schaltfläche, Esc = ''
function ask(html, onTap) {
  const d = $('firstDlg');
  d.innerHTML = html;
  if ($('setDlg').open) $('setDlg').close();
  openDlg(d);
  return new Promise(res => {
    d.onclick = e => {
      const b = e.target.closest('[data-c]');
      if (!b) return;
      onTap?.(b.dataset.c);
      d.onclose = null;
      d.close();
      res(b.dataset.c);
    };
    d.onclose = () => res('');
  });
}

// Frage beim ersten Verbinden, wenn beide Seiten Shots haben, die der anderen fehlen. Zusammenführen steht vorn,
// was löscht, liegt eingeklappt dahinter. Bei geteilten Daten gibt es kein „nur dieses Gerät“: das löschte bei allen anderen.
function askFirst(onlyHere, onlyThere, local, remote) {
  const who = dbx.get().owner;
  return ask(`<h3 id="firstTitle">${t('sync.first.title')}</h3><p>${t('sync.first.text', local, remote, who && esc(who))}</p><div class="langs">
    <button class="primary" data-c="merge">${t('sync.first.merge')}</button><small>${t('sync.first.mergeHint')}</small>
    <details><summary>${t('sync.first.more')}</summary><div class="langs">
      <button data-c="remote">${t('sync.first.remote')}</button><small>${t('sync.first.remoteHint', onlyHere)}</small>
      ${who ? '' : `<button data-c="local">${t('sync.first.local')}</button><small>${t('sync.first.localHint', onlyThere)}</small>`}
    </div></details>
    <button class="link" data-c="">${t('sync.first.later')}</button></div>`,
    // Sicherung vor dem Ersetzen: hier im Tipp, denn das Teilen-Menü auf dem iPhone braucht eine Nutzeraktion
    c => { if (c === 'remote') $('export').onclick(); });
}

// ---------- Teilen ----------
// Wer einlädt, teilt seinen Ordner FOLDER (Bearbeiten erlaubt, auch Eingeladene dürfen einladen). Eingeladene suchen
// beim Verbinden oder per Knopf nach geteilten Ordnern mit diesem Namen und nutzen dann deren Daten statt der eigenen.
let choosing = false; // währenddessen nicht abgleichen, sonst fragt askFirst für den falschen Ordner

// größere Ordner teilt Dropbox im Hintergrund: auf das Ende des Auftrags warten
async function finished(r, statusEndpoint) {
  const job = r.async_job_id;
  for (let i = 0; r['.tag'] === 'async_job_id' || r['.tag'] === 'in_progress'; i++) {
    if (i > 30) throw new Error(statusEndpoint + ' timeout');
    await new Promise(res => setTimeout(res, 1000));
    r = await dbxCall(statusEndpoint, {async_job_id: job});
  }
  if (r['.tag'] === 'failed') throw new Error(JSON.stringify(r.failed));
  return r;
}

// zurück zum eigenen Ordner; was auf dem Gerät ist, bleibt und wird dorthin abgeglichen
function ownFolder() {
  const {ns, owner, ...rest} = dbx.get();
  dbx.set({...rest, synced: false});
  renderSync();
  syncSoon(0);
}

async function invite(email) {
  let id = dbx.get().ns;
  if (!id) {
    let meta;
    try { meta = await dbxCall('files/get_metadata', {path: FOLDER}); }
    catch (e) { if (!e.message.includes('not_found')) throw e; meta = (await dbxCall('files/create_folder_v2', {path: FOLDER})).metadata; }
    id = meta.sharing_info?.shared_folder_id;
    if (!id) {
      const r = await dbxCall('sharing/share_folder', {path: FOLDER, acl_update_policy: {'.tag': 'editors'}});
      id = (await finished(r, 'sharing/check_share_job_status')).shared_folder_id;
    }
    dbx.set({...dbx.get(), ns: id});
  }
  await dbxCall('sharing/add_folder_member', {shared_folder_id: id,
    members: [{member: {'.tag': 'email', email}, access_level: {'.tag': 'editor'}}]});
  dbx.set({...dbx.get(), alone: false});
  renderSync();
  toast(t('share.sent', email));
}

// geteilte Kaffeedaten anderer: beigetretene und noch offene Einladungen, nur Ordner mit unserem Namen
async function findShares() {
  const all = new Map();
  for (const ep of ['sharing/list_folders', 'sharing/list_mountable_folders']) {
    // shortcut: nur die erste Seite (100 Ordner), bei mehr geteilten Ordnern …/continue nachladen
    for (const f of (await dbxCall(ep, {limit: 100})).entries) all.set(f.shared_folder_id, f);
  }
  const found = [...all.values()].filter(f => f.name.startsWith(FOLDER.slice(1)) && f.access_type['.tag'] !== 'owner'
    && f.shared_folder_id !== dbx.get().ns);
  for (const f of found) f.owner = (await ownerOf(f.shared_folder_id))?.display_name || f.name;
  return found;
}
const ownerOf = async id => (await dbxCall('sharing/list_folder_members', {shared_folder_id: id}))
  .users.find(u => u.access_type['.tag'] === 'owner')?.user;

// Besitz und Mitglieder ändern sich im Dropbox-Web: einmal pro Sitzung und beim Öffnen der Einstellungen nachsehen.
// Gehört der Ordner mir, bin ich Besitzer (owner leer: „Teilen beenden“ statt „Nicht mehr mitmachen“);
// alone = niemand sonst drin und keine Einladung offen, dann gibt es nichts zu beenden.
let ownerChecked = false;
async function refreshOwner() {
  const s = dbx.get();
  if (ownerChecked || !s.ns) return;
  // klappt es nicht, beim nächsten Mal; Abgleich nicht aufhalten
  const m = await dbxCall('sharing/list_folder_members', {shared_folder_id: s.ns}).catch(() => null);
  const o = m?.users.find(u => u.access_type['.tag'] === 'owner')?.user;
  if (!o) return;
  ownerChecked = true;
  const {owner, alone, ...rest} = dbx.get();
  dbx.set({...rest, ...(o.account_id === s.account ? {} : {owner: o.display_name}), alone: m.users.length + (m.invitees?.length || 0) < 2});
  renderSync();
}
$('setBtn').addEventListener('click', () => { ownerChecked = false; refreshOwner(); });

// quiet = direkt nach dem Verbinden: findet sich nichts, nichts sagen
async function offerShares(quiet) {
  choosing = true;
  try {
    const found = await findShares();
    if (!found.length) return quiet || toast(t('share.none'));
    const c = await ask(`<h3 id="firstTitle">${t('share.found')}</h3><p>${t('share.foundText')}</p><div class="langs">
      ${found.map((f, i) => `<button class="primary" data-c="${i}">${t('share.use', esc(f.owner))}</button>`).join('')}
      <button data-c="own">${t('share.own')}</button><small>${t('share.later')}</small></div>`);
    const f = found[c];
    if (!f || !await keepImages()) return;
    if (!f.path_lower) { // Einladung noch nicht angenommen: in die eigene Dropbox einhängen
      try { await dbxCall('sharing/mount_folder', {shared_folder_id: f.shared_folder_id}); }
      catch (e) { if (!e.message.includes('already_mounted')) throw e; }
    }
    dbx.set({...dbx.get(), ns: f.shared_folder_id, owner: f.owner, synced: false});
    // Bilder auf dem Gerät halten: fällt der Zugriff später weg (entfernt, Teilen beendet), sind sie sonst verloren
    localStorage.setItem(OPT_IMG, '1');
  } finally {
    choosing = false;
    renderSync();
    syncSoon(0);
  }
}

async function leaveShare() {
  const s = dbx.get();
  if (!confirm(t('share.leaveAsk', s.owner)) || !await keepImages()) return;
  // 409: schon entfernt worden o. Ä., dann nur noch lokal umstellen
  try { await dbxCall('sharing/relinquish_folder_membership', {shared_folder_id: s.ns, leave_a_copy: false}); }
  catch (e) { if (e.status !== 409) throw e; }
  ownFolder();
}

// Besitzer beendet das Teilen: alle Mitglieder behalten eine Kopie in ihrer Dropbox, er selbst arbeitet im selben Ordner weiter
async function stopShare() {
  if (!confirm(t('share.stopAsk'))) return;
  choosing = true;
  try {
    await finished(await dbxCall('sharing/unshare_folder', {shared_folder_id: dbx.get().ns, leave_a_copy: true}), 'sharing/check_job_status');
    ownFolder();
  } finally { choosing = false; }
}

// Bilder, die nur im bisherigen Dropbox-Ordner liegen, aufs Gerät holen, bevor er wechselt oder getrennt wird;
// sonst fehlen sie danach. Klappt das nicht (offline), nachfragen. false = abbrechen.
async function keepImages() {
  const refs = [...new Set(shots.filter(s => s.image?.startsWith('img:')).map(s => s.image.slice(4)))];
  if (!refs.length) return true;
  try {
    const got = new Map();
    for (const n of refs) got.set(n, urls.get(n) || await downloadImg(n));
    shots.forEach(s => { if (s.image?.startsWith('img:')) s.image = got.get(s.image.slice(4)); });
    save(false);
    return true;
  } catch { return confirm(t('sync.missingImgs', refs.length)); }
}

async function dbxDisconnect() {
  if (!await keepImages()) return;
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
  // Neuzeichnen beim Statuswechsel darf eine angefangene E-Mail-Adresse nicht verlieren
  const mail = $('shareMail')?.value, typing = document.activeElement?.id === 'shareMail';
  const status = state === 'running' ? t('sync.st.running') : state === 'pending' ? t('sync.st.pending')
    : state === 'auth' ? t('sync.st.auth') : state === 'error' ? t('sync.st.error', esc(lastError))
    : s.last ? t('sync.st.idle', fmtDate(s.last)) : '';
  box.innerHTML = `<span class="flabel">${t('sync.title')}</span>` + (s.refresh
    ? `<div class="syncrow"><div><p class="note">${t('sync.as', esc(s.name), esc(s.email))}</p>
       ${status ? `<p class="note state${state === 'error' || state === 'auth' ? ' bad' : ''}" role="status">${status}</p>` : ''}</div>
       ${state === 'auth' ? '' : `<button type="button" class="icon" id="dbxNow" title="${t('sync.now')}" aria-label="${t('sync.now')}"${state === 'running' ? ' disabled' : ''}>${SYNC_ICON}</button>`}</div>
       <div class="langs">${state === 'auth' ? `<button type="button" class="dbx" id="dbxOn">${DBX_ICON}${t('sync.reconnect')}</button>` : ''}
       <button type="button" class="swrow" id="dbxImg" role="switch" aria-checked="${offlineImages()}">${t('sync.offlineImgs')}<span class="sw" aria-hidden="true"></span></button></div>
       ${state === 'auth' ? '' : `<span class="flabel share">${t('share.title')}</span><p class="note">${s.owner ? t('share.using', esc(s.owner)) : s.ns && !s.alone ? t('share.owning') : t('share.intro')}</p>
       <form class="langs" id="shareForm"><input type="email" id="shareMail" placeholder="${t('share.mail')}" aria-label="${t('share.mail')}" autocomplete="email" required>
       <button class="primary">${t('share.invite')}</button></form>
       <div class="langs">${s.owner ? `<button type="button" class="destructive" id="shareLeave">${t('share.leave')}</button>`
         : s.ns && !s.alone ? `<button type="button" class="destructive" id="shareStop">${t('share.stop')}</button>`
         : `<button type="button" class="link" id="shareFind">${t('share.find')}</button>`}</div>`}
       <div class="langs"><button type="button" class="destructive" id="dbxOff">${t('sync.disconnect')}</button></div>`
    : manualPending
    ? `<form class="langs" id="dbxCodeForm"><label for="dbxCode" class="note">${t('sync.pasteCode')}</label>
       <input id="dbxCode" autocomplete="off" autocapitalize="off" spellcheck="false" required>
       <button class="primary">${t('sync.confirm')}</button><button type="button" class="link" id="dbxBack">${t('sync.back')}</button></form>`
    : `<p class="note">${t('sync.intro')}</p><div class="langs"><button type="button" class="dbx" id="dbxOn">${DBX_ICON}${t('sync.connect')}</button>
       <button type="button" class="link" id="dbxManual">${t('sync.manual')}</button></div>`);
  if (mail && $('shareMail')) { $('shareMail').value = mail; if (typing) $('shareMail').focus(); }
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
  else if (id === 'shareFind') offerShares(false).catch(syncFail);
  else if (id === 'shareLeave') leaveShare().catch(syncFail);
  else if (id === 'shareStop') stopShare().catch(syncFail);
};
$('syncBox').onsubmit = e => {
  e.preventDefault();
  if (e.target.id === 'shareForm') {
    const b = e.target.querySelector('button');
    b.disabled = true; // kein doppeltes Einladen durch zweimal Tippen
    return invite($('shareMail').value.trim()).then(() => { $('shareMail').value = ''; }).catch(syncFail).finally(() => { b.disabled = false; });
  }
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
// Verbindung über einen älteren App-Schlüssel (andere Dropbox-App) gilt nicht mehr: neu verbinden lassen
setState(dbx.get().refresh && dbx.get().key !== DBX_KEY ? 'auth' : 'idle');
// Abgleich beim Öffnen: index.html stößt ihn nach dem Laden der Daten an. Waren die Daten schneller geladen
// als diese Datei (IndexedDB ist meist schneller als das Netz), lief der Aufruf ins Leere, also hier nachholen.
if (dataReady) syncSoon(0);
