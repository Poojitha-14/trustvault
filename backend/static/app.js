const $ = id => document.getElementById(id);
const say = text => { $('msg').textContent = text; };
const JSON_HEADERS = { 'Content-Type': 'application/json' };

const ROLE_INFO = {
  admin: 'Admin: you can see document names, owners and the activity log. You cannot open file contents.',
  owner: 'Owner: you can upload. On your own documents you can read, download, edit, delete and share.',
  viewer: 'Viewer: you only see documents that someone shared with you. Everything else is denied.'
};

async function api(path, options) {
  const r = await fetch(path, options);
  let d = null;
  try { d = await r.json(); } catch (e) { /* no JSON body */ }
  return { r, d };
}

async function login() {
  const { r, d } = await api('/login', {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({ username: $('u').value, password: $('p').value })
  });
  if (r.ok) { say(''); init(); } else { say((d && d.error) || 'login failed'); }
}

async function logout() {
  await api('/logout', { method: 'POST' });
  $('app').hidden = true;
  $('login').hidden = false;
}

async function init() {
  const { r, d } = await api('/me');
  if (!r.ok) return;
  $('login').hidden = true;
  $('app').hidden = false;
  $('who').textContent = d.username + ' (' + d.role + ')';
  $('roleInfo').textContent = ROLE_INFO[d.role];
  $('uploadBox').hidden = d.role !== 'owner';
  $('adminBox').hidden = d.role !== 'admin';
  load();
}

function addButton(cell, label, handler) {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = handler;
  cell.append(' ', b);
}

async function load() {
  const { r, d } = await api('/search?q=' + encodeURIComponent($('q').value));
  const table = $('docs');
  table.textContent = '';
  if (!r.ok) return;

  const head = table.insertRow();
  ['Name', 'Owner', 'Your access', 'Actions'].forEach(h => {
    const th = document.createElement('th');
    th.textContent = h;
    head.appendChild(th);
  });

  d.forEach(doc => {
    const row = table.insertRow();
    row.insertCell().textContent = doc.name;
    row.insertCell().textContent = doc.owner;

    const badge = document.createElement('span');
    badge.className = 'badge ' + doc.access.split(' ')[0];
    badge.textContent = doc.access;
    row.insertCell().appendChild(badge);

    // Buttons are only a convenience. The server decides every time.
    const cell = row.insertCell();
    if (doc.access !== 'metadata only') {
      const a = document.createElement('a');
      a.href = '/documents/' + doc.id + '/download';
      a.textContent = 'Download';
      cell.appendChild(a);
    }
    if (doc.access === 'owner') {
      addButton(cell, 'Share', () => share(doc.id));
      addButton(cell, 'Revoke', () => revoke(doc.id));
      addButton(cell, 'Delete', () => remove(doc.id));
    }
  });
}

async function upload() {
  const file = $('f').files[0];
  if (!file) return say('choose a file first');
  const form = new FormData();
  form.append('file', file);
  form.append('category', $('cat').value);
  const { r, d } = await api('/documents', { method: 'POST', body: form });
  say(r.ok ? 'Uploaded' : (d && d.error) || 'upload failed');
  load();
}

async function share(id) {
  const username = prompt('Username to share with');
  if (!username) return;
  const permission = prompt('Permission: read or edit', 'read');
  const { r, d } = await api('/documents/' + id + '/grants', {
    method: 'POST', headers: JSON_HEADERS,
    body: JSON.stringify({ username, permission })
  });
  say(r.ok ? 'Shared with ' + username : (d && d.error) || 'failed');
}

async function revoke(id) {
  const username = prompt('Username to revoke');
  if (!username) return;
  const { r, d } = await api('/documents/' + id + '/grants/' + encodeURIComponent(username),
    { method: 'DELETE' });
  say(r.ok ? 'Revoked ' + username : (d && d.error) || 'failed');
}

async function remove(id) {
  if (!confirm('Delete this document?')) return;
  const { r, d } = await api('/documents/' + id, { method: 'DELETE' });
  say(r.ok ? 'Deleted' : (d && d.error) || 'failed');
  load();
}

async function audit() {
  const { r, d } = await api('/admin/audit');
  $('auditOut').textContent = r.ok ? JSON.stringify(d, null, 1) : 'not allowed';
}

init();