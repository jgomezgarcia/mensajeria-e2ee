// app.js
// Logica del cliente: identidad local (IndexedDB), conexion Socket.io,
// gestion de estado y renderizado de mensajes ya descifrados.
// El cifrado/descifrado real vive en crypto.js; aqui solo se orquesta.

import {
  generateIdentityKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  importPublicKeyJwk,
  importPrivateKeyJwk,
  deriveSharedAesKey,
  encryptMessage,
  decryptMessage,
  computeSecurityCode,
} from './crypto.js';

// ---------------------------------------------------------------------------
// IndexedDB: unico lugar donde vive la clave privada en el navegador.
// ---------------------------------------------------------------------------

const IDB_NAME = 'e2ee-chat';
const IDB_STORE = 'identity';
const IDB_KEY = 'me';

function openIdb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(IDB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGetIdentity() {
  const db = await openIdb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readonly');
    const req = tx.objectStore(IDB_STORE).get(IDB_KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbSetIdentity(record) {
  const db = await openIdb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readwrite');
    tx.objectStore(IDB_STORE).put(record, IDB_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbClearIdentity() {
  const db = await openIdb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readwrite');
    tx.objectStore(IDB_STORE).delete(IDB_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// Estado global de la sesion en memoria.
// ---------------------------------------------------------------------------

const state = {
  username: null,
  token: null,
  privateKey: null,      // CryptoKey (no extraible de la memoria, solo en RAM)
  publicKeyJwk: null,
  publicKey: null,        // CryptoKey publico propio (para calcular codigo de seguridad)
  socket: null,
  contacts: [],           // [{ username, publicKeyJwk, publicKey }]
  sharedKeys: new Map(),  // username -> CryptoKey AES-GCM derivada
  currentContact: null,
};

// ---------------------------------------------------------------------------
// Elementos del DOM
// ---------------------------------------------------------------------------

const el = {
  authScreen: document.getElementById('auth-screen'),
  appScreen: document.getElementById('app-screen'),

  tabRegister: document.getElementById('tab-register'),
  tabImport: document.getElementById('tab-import'),

  registerForm: document.getElementById('register-form'),
  registerUsername: document.getElementById('register-username'),
  registerInvite: document.getElementById('register-invite'),
  registerError: document.getElementById('register-error'),

  importForm: document.getElementById('import-form'),
  importFile: document.getElementById('import-file'),
  importError: document.getElementById('import-error'),

  myUsername: document.getElementById('my-username'),
  exportKeyBtn: document.getElementById('export-key-btn'),
  logoutBtn: document.getElementById('logout-btn'),

  contactList: document.getElementById('contact-list'),
  refreshContactsBtn: document.getElementById('refresh-contacts-btn'),

  chatEmpty: document.getElementById('chat-empty'),
  chatPanel: document.getElementById('chat-panel'),
  chatContactName: document.getElementById('chat-contact-name'),
  chatSecurityCode: document.getElementById('chat-security-code'),
  messageList: document.getElementById('message-list'),

  messageForm: document.getElementById('message-form'),
  messageInput: document.getElementById('message-input'),
};

// ---------------------------------------------------------------------------
// Llamadas HTTP autenticadas (header x-username / x-token)
// ---------------------------------------------------------------------------

async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers, {
    'x-username': state.username || '',
    'x-token': state.token || '',
  });
  const res = await fetch(path, Object.assign({}, options, { headers }));
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Error HTTP ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Arranque de sesion (registro / import / auto-login)
// ---------------------------------------------------------------------------

function showAuthScreen() {
  el.authScreen.hidden = false;
  el.appScreen.hidden = true;
}

function showAppScreen() {
  el.authScreen.hidden = true;
  el.appScreen.hidden = false;
  el.myUsername.textContent = state.username;
}

async function startSessionWithIdentity(record) {
  state.username = record.username;
  state.token = record.token;
  state.publicKeyJwk = record.publicKeyJwk;
  state.privateKey = await importPrivateKeyJwk(record.privateKeyJwk);
  state.publicKey = await importPublicKeyJwk(record.publicKeyJwk);

  // Verificamos contra el servidor que el token sigue siendo valido.
  await apiFetch('/api/session/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: state.username, token: state.token }),
  });

  connectSocket();
  showAppScreen();
  await loadContacts();
}

async function tryAutoLogin() {
  try {
    const record = await idbGetIdentity();
    if (!record) {
      showAuthScreen();
      return;
    }
    await startSessionWithIdentity(record);
  } catch (err) {
    console.warn('No se pudo reanudar la sesion automaticamente:', err.message);
    showAuthScreen();
  }
}

// --- Registro ---------------------------------------------------------

el.tabRegister.addEventListener('click', () => switchAuthTab('register'));
el.tabImport.addEventListener('click', () => switchAuthTab('import'));

function switchAuthTab(tab) {
  const isRegister = tab === 'register';
  el.tabRegister.classList.toggle('active', isRegister);
  el.tabImport.classList.toggle('active', !isRegister);
  el.registerForm.hidden = !isRegister;
  el.importForm.hidden = isRegister;
}

el.registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  el.registerError.textContent = '';
  const username = el.registerUsername.value.trim();
  const inviteCode = el.registerInvite.value;

  try {
    const keyPair = await generateIdentityKeyPair();
    const publicKeyJwk = await exportPublicKeyJwk(keyPair.publicKey);
    const privateKeyJwk = await exportPrivateKeyJwk(keyPair.privateKey);

    const result = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, inviteCode, publicKeyJwk }),
    }).then(async (res) => {
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || 'Error al registrarse');
      return body;
    });

    const record = {
      username: result.username,
      token: result.token,
      publicKeyJwk,
      privateKeyJwk,
    };
    await idbSetIdentity(record);
    await startSessionWithIdentity(record);
  } catch (err) {
    el.registerError.textContent = err.message;
  }
});

// --- Importar clave privada (recuperar acceso en otro navegador/dispositivo)

el.importForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  el.importError.textContent = '';
  const file = el.importFile.files[0];
  if (!file) {
    el.importError.textContent = 'Selecciona un archivo .json exportado previamente';
    return;
  }
  try {
    const text = await file.text();
    const record = JSON.parse(text);
    if (!record.username || !record.token || !record.privateKeyJwk || !record.publicKeyJwk) {
      throw new Error('El archivo no tiene el formato esperado');
    }
    await idbSetIdentity(record);
    await startSessionWithIdentity(record);
  } catch (err) {
    el.importError.textContent = err.message;
  }
});

// --- Exportar clave privada (backup) -----------------------------------

el.exportKeyBtn.addEventListener('click', async () => {
  const record = await idbGetIdentity();
  if (!record) return;
  const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `e2ee-chat-${record.username}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// --- Logout local (no borra nada en el servidor, solo el dispositivo) --

el.logoutBtn.addEventListener('click', async () => {
  if (!confirm('Esto borrara tu clave privada de este navegador. Asegurate de haberla exportado antes. ¿Continuar?')) {
    return;
  }
  if (state.socket) state.socket.disconnect();
  await idbClearIdentity();
  state.username = null;
  state.token = null;
  state.privateKey = null;
  state.publicKey = null;
  state.contacts = [];
  state.sharedKeys.clear();
  state.currentContact = null;
  showAuthScreen();
});

// ---------------------------------------------------------------------------
// Socket.io
// ---------------------------------------------------------------------------

function connectSocket() {
  state.socket = io({ auth: { username: state.username, token: state.token } });

  state.socket.on('connect_error', (err) => {
    console.error('Error de conexion socket.io:', err.message);
  });

  state.socket.on('message', async (message) => {
    // Nos llega tanto el mensaje que enviamos (eco) como los que recibimos.
    if (message.from !== state.username && message.to !== state.username) return;

    const otherParty = message.from === state.username ? message.to : message.from;
    if (state.currentContact === otherParty) {
      const plaintext = await decryptForContact(otherParty, message.ciphertext, message.iv);
      appendMessageToView(message, plaintext);
    }
  });
}

// ---------------------------------------------------------------------------
// Contactos y claves compartidas por conversacion
// ---------------------------------------------------------------------------

async function loadContacts() {
  const directory = await apiFetch('/api/directory');
  state.contacts = directory.filter((c) => c.username !== state.username);
  renderContactList();
}

el.refreshContactsBtn.addEventListener('click', loadContacts);

function renderContactList() {
  el.contactList.innerHTML = '';
  if (state.contacts.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'contact-empty';
    empty.textContent = 'Todavia no hay otros usuarios registrados.';
    el.contactList.appendChild(empty);
    return;
  }
  for (const contact of state.contacts) {
    const li = document.createElement('li');
    li.className = 'contact-item';
    li.textContent = contact.username;
    li.dataset.username = contact.username;
    if (contact.username === state.currentContact) li.classList.add('active');
    li.addEventListener('click', () => openChat(contact.username));
    el.contactList.appendChild(li);
  }
}

async function getSharedKey(username) {
  if (state.sharedKeys.has(username)) return state.sharedKeys.get(username);
  const contact = state.contacts.find((c) => c.username === username);
  if (!contact) throw new Error(`Contacto desconocido: ${username}`);
  if (!contact.publicKey) {
    contact.publicKey = await importPublicKeyJwk(contact.publicKeyJwk);
  }
  const sharedKey = await deriveSharedAesKey(state.privateKey, contact.publicKey);
  state.sharedKeys.set(username, sharedKey);
  return sharedKey;
}

async function decryptForContact(username, ciphertext, iv) {
  try {
    const key = await getSharedKey(username);
    return await decryptMessage(key, ciphertext, iv);
  } catch (err) {
    console.error('No se pudo descifrar un mensaje:', err);
    return '[Mensaje ilegible: no se pudo descifrar]';
  }
}

// ---------------------------------------------------------------------------
// Ventana de chat
// ---------------------------------------------------------------------------

async function openChat(username) {
  state.currentContact = username;
  renderContactList();

  el.chatEmpty.hidden = true;
  el.chatPanel.hidden = false;
  el.chatContactName.textContent = username;
  el.messageList.innerHTML = '';
  el.chatSecurityCode.textContent = 'Calculando codigo de seguridad...';

  const contact = state.contacts.find((c) => c.username === username);
  if (!contact.publicKey) {
    contact.publicKey = await importPublicKeyJwk(contact.publicKeyJwk);
  }
  el.chatSecurityCode.textContent = await computeSecurityCode(state.publicKey, contact.publicKey);

  const history = await apiFetch(`/api/messages?with=${encodeURIComponent(username)}`);
  for (const message of history) {
    const plaintext = await decryptForContact(username, message.ciphertext, message.iv);
    appendMessageToView(message, plaintext);
  }
}

function appendMessageToView(message, plaintext) {
  const li = document.createElement('li');
  const outgoing = message.from === state.username;
  li.className = `message ${outgoing ? 'outgoing' : 'incoming'}`;

  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';
  bubble.textContent = plaintext;

  const time = document.createElement('div');
  time.className = 'message-time';
  time.textContent = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  li.appendChild(bubble);
  li.appendChild(time);
  el.messageList.appendChild(li);
  el.messageList.scrollTop = el.messageList.scrollHeight;
}

el.messageForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = el.messageInput.value.trim();
  if (!text || !state.currentContact) return;

  const to = state.currentContact;
  const key = await getSharedKey(to);
  const { ciphertext, iv } = await encryptMessage(key, text);

  state.socket.emit('message', { to, ciphertext, iv }, (ack) => {
    if (!ack || !ack.ok) {
      console.error('No se pudo enviar el mensaje:', ack && ack.error);
    }
  });

  el.messageInput.value = '';
});

// ---------------------------------------------------------------------------
// Arranque
// ---------------------------------------------------------------------------

switchAuthTab('register');
tryAutoLogin();
