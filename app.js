/* Логика выпуска лицензий S Optimization.
   Подпись считается локально через WebCrypto, интернет не нужен. */

'use strict';

const STORE_KEY = 'sopt.keyblob.v1';
const STORE_LOG = 'sopt.log.v1';
const ITER = 200000;

let signingKey = null;

// ---------------- утилиты ----------------

function b64FromBytes(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64FromText(text) {
  return b64FromBytes(new TextEncoder().encode(text));
}

function bytesFromB64(b64) {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function normalizeId(raw) {
  const c = (raw || '').toUpperCase().replace(/[^0-9A-F]/g, '');
  return c.length === 32 ? c : null;
}

function formatDate(d) {
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!b64) throw new Error('пустой ключ');
  return bytesFromB64(b64);
}

// ---------------- криптография ----------------

async function deriveAesKey(pass, salt, iterations) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptPem(pem, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(pass, salt, ITER);
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(pem));
  return {
    v: 1,
    iter: ITER,
    salt: b64FromBytes(salt),
    iv: b64FromBytes(iv),
    data: b64FromBytes(new Uint8Array(data))
  };
}

async function decryptPem(blob, pass) {
  const salt = bytesFromB64(blob.salt);
  const iv = bytesFromB64(blob.iv);
  const key = await deriveAesKey(pass, salt, blob.iter || ITER);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv }, key, bytesFromB64(blob.data));
  return new TextDecoder().decode(plain);
}

async function importSigningKey(pem) {
  const der = pemToDer(pem);
  // extractable = false: ключ нельзя выгрузить обратно из браузера
  return crypto.subtle.importKey(
    'pkcs8', der,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']);
}

// ---------------- формирование лицензии ----------------

function buildPayload(id32, name) {
  return 'SOPT-LIC1\n' +
    'NAME=' + b64FromText(name) + '\n' +
    'ISSUED=' + formatDate(new Date()) + '\n' +
    'C1=' + id32.slice(0, 8) + '\n' +
    'C2=' + id32.slice(8, 16) + '\n' +
    'C3=' + id32.slice(16, 24) + '\n' +
    'C4=' + id32.slice(24, 32);
}

async function makeLicense(idRaw, name) {
  if (!signingKey) throw new Error('ключ не разблокирован');
  const id32 = normalizeId(idRaw);
  if (!id32) throw new Error('ID должен содержать 32 hex-символа');
  const payload = buildPayload(id32, name);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKey,
    new TextEncoder().encode(payload));
  // WebCrypto отдаёт «сырую» подпись r||s — именно это ждёт программа
  return payload + '\nSIG=' + b64FromBytes(new Uint8Array(sig)) + '\n';
}

// ---------------- журнал ----------------

function readLog() {
  try {
    const raw = localStorage.getItem(STORE_LOG);
    return raw ? JSON.parse(raw) : [];
  } catch (e) { return []; }
}

function pushLog(entry) {
  const log = readLog();
  log.unshift(entry);
  try { localStorage.setItem(STORE_LOG, JSON.stringify(log.slice(0, 30))); } catch (e) {}
  renderLog();
}

function renderLog() {
  const box = document.getElementById('log-list');
  if (!box) return;
  const log = readLog();
  if (!log.length) {
    box.className = 'hint';
    box.textContent = 'Пока пусто.';
    return;
  }
  box.className = '';
  box.innerHTML = '';
  log.forEach(function (item) {
    const div = document.createElement('div');
    div.className = 'log-item';
    const b = document.createElement('b');
    b.textContent = item.name;
    div.appendChild(b);
    div.appendChild(document.createTextNode(' · ' + item.date));
    div.appendChild(document.createElement('br'));
    div.appendChild(document.createTextNode(item.id));
    box.appendChild(div);
  });
}

// ---------------- экраны ----------------

function show(id) {
  ['screen-setup', 'screen-unlock', 'screen-main'].forEach(function (s) {
    const el = document.getElementById(s);
    if (!el) return;
    el.classList.toggle('hidden', s !== id);
  });
}

function setStatus(id, text, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text || '';
  el.className = 'status' + (kind ? ' ' + kind : '');
}

function storedBlob() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}

// ---------------- сценарии ----------------

async function saveKey() {
  const pem = document.getElementById('setup-key').value.trim();
  const p1 = document.getElementById('setup-pass').value;
  const p2 = document.getElementById('setup-pass2').value;

  if (pem.indexOf('BEGIN') < 0) {
    setStatus('setup-status', 'Вставьте ключ: он должен начинаться с BEGIN PRIVATE KEY', 'err');
    return;
  }
  if (p1.length < 8) {
    setStatus('setup-status', 'Пароль должен быть не короче 8 символов', 'err');
    return;
  }
  if (p1 !== p2) {
    setStatus('setup-status', 'Пароли не совпадают', 'err');
    return;
  }

  try {
    await importSigningKey(pem);                       // проверка, что ключ валиден
    const blob = await encryptPem(pem, p1);
    localStorage.setItem(STORE_KEY, JSON.stringify(blob));
    document.getElementById('setup-pass').value = '';
    document.getElementById('setup-pass2').value = '';
    document.getElementById('setup-key').value = '';
    setStatus('setup-status', 'Ключ сохранён. Разблокируйте его паролем.', 'ok');
    document.getElementById('unlock-pass').value = '';
    show('screen-unlock');
    document.getElementById('unlock-pass').focus();
  } catch (e) {
    setStatus('setup-status', 'Не удалось прочитать ключ: ' + e.message, 'err');
  }
}

async function unlock() {
  const blob = storedBlob();
  if (!blob) { show('screen-setup'); return; }
  const pass = document.getElementById('unlock-pass').value;
  if (!pass) { setStatus('unlock-status', 'Введите пароль', 'err'); return; }

  try {
    const pem = await decryptPem(blob, pass);
    signingKey = await importSigningKey(pem);
    document.getElementById('unlock-pass').value = '';
    setStatus('unlock-status', '');
    show('screen-main');
    renderLog();
  } catch (e) {
    setStatus('unlock-status', 'Неверный пароль или повреждённый ключ', 'err');
  }
}

async function issue() {
  const idRaw = document.getElementById('machine-id').value;
  const id = normalizeId(idRaw);
  if (!id) {
    setStatus('issue-status', 'ID должен содержать 32 hex-символа', 'err');
    return;
  }
  const nameInput = document.getElementById('client-name').value.trim();
  const name = nameInput || 'Клиент';

  try {
    const license = await makeLicense(id, name);
    lastLicense = license;
    lastName = name;
    document.getElementById('license-text').textContent = license;
    document.getElementById('result-card').classList.remove('hidden');
    setStatus('issue-status', '');
    setStatus('result-status', '');
    pushLog({ name: name, id: id, date: formatDate(new Date()) });
    document.getElementById('result-card').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) {
    setStatus('issue-status', 'Ошибка: ' + e.message, 'err');
  }
}

let lastLicense = '';
let lastName = '';

function fileSafe(name) {
  const cleaned = name.replace(/[^0-9A-Za-zА-Яа-яЁё]/g, '_').replace(/_+/g, '_');
  return cleaned || 'client';
}

function download() {
  if (!lastLicense) return;
  const blob = new Blob([lastLicense], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'license_' + fileSafe(lastName) + '.key';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
  setStatus('result-status', 'Файл скачан. Отправьте его клиенту.', 'ok');
}

async function copyLicense() {
  if (!lastLicense) return;
  try {
    await navigator.clipboard.writeText(lastLicense);
    setStatus('result-status', 'Скопировано в буфер обмена.', 'ok');
  } catch (e) {
    setStatus('result-status', 'Не удалось скопировать — выделите текст вручную.', 'err');
  }
}

function nextOne() {
  document.getElementById('machine-id').value = '';
  document.getElementById('client-name').value = '';
  document.getElementById('result-card').classList.add('hidden');
  lastLicense = '';
  setStatus('issue-status', '');
  document.getElementById('machine-id').focus();
}

function lock() {
  signingKey = null;
  document.getElementById('unlock-pass').value = '';
  setStatus('unlock-status', '');
  show('screen-unlock');
}

function resetKey() {
  if (!confirm('Удалить сохранённый ключ из этого браузера?')) return;
  localStorage.removeItem(STORE_KEY);
  signingKey = null;
  show('screen-setup');
}

// ---------------- запуск ----------------

function init() {
  const pick = document.getElementById('btn-pick-key');
  const file = document.getElementById('file-key');

  pick.addEventListener('click', function () { file.click(); });
  file.addEventListener('change', function () {
    const f = file.files && file.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = function () {
      document.getElementById('setup-key').value = String(reader.result || '');
      setStatus('setup-status', 'Файл загружен. Придумайте пароль.', '');
    };
    reader.readAsText(f);
  });

  document.getElementById('btn-save-key').addEventListener('click', saveKey);
  document.getElementById('btn-unlock').addEventListener('click', unlock);
  document.getElementById('btn-reset').addEventListener('click', resetKey);
  document.getElementById('btn-issue').addEventListener('click', issue);
  document.getElementById('btn-save').addEventListener('click', download);
  document.getElementById('btn-copy').addEventListener('click', copyLicense);
  document.getElementById('btn-next').addEventListener('click', nextOne);
  document.getElementById('btn-lock').addEventListener('click', lock);

  document.getElementById('unlock-pass').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') unlock();
  });

  if (storedBlob()) {
    show('screen-unlock');
    document.getElementById('unlock-pass').focus();
  } else {
    show('screen-setup');
  }

  renderLog();

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
}

document.addEventListener('DOMContentLoaded', init);
