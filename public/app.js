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
  generateRawGroupKeyBytes,
  importGroupKey,
  wrapGroupKeyForMember,
  unwrapGroupKey,
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
  sharedKeys: new Map(),  // username -> CryptoKey AES-GCM derivada (chats 1 a 1)
  groups: new Map(),      // groupId -> { id, name, createdBy, members, key: CryptoKey }
  currentChat: null,      // { type: 'user', id: username } | { type: 'group', id: groupId }
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

  groupList: document.getElementById('group-list'),
  newGroupBtn: document.getElementById('new-group-btn'),

  groupModalOverlay: document.getElementById('group-modal-overlay'),
  groupForm: document.getElementById('group-form'),
  groupName: document.getElementById('group-name'),
  groupMemberList: document.getElementById('group-member-list'),
  groupCancelBtn: document.getElementById('group-cancel-btn'),
  groupError: document.getElementById('group-error'),

  chatEmpty: document.getElementById('chat-empty'),
  chatPanel: document.getElementById('chat-panel'),
  chatBackBtn: document.getElementById('chat-back-btn'),
  chatContactName: document.getElementById('chat-contact-name'),
  chatSecurityCodeRow: document.getElementById('chat-security-code-row'),
  chatSecurityCode: document.getElementById('chat-security-code'),
  chatGroupMembers: document.getElementById('chat-group-members'),
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
  await loadGroups();
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
  state.groups.clear();
  state.currentChat = null;
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
    if (state.currentChat && state.currentChat.type === 'user' && state.currentChat.id === otherParty) {
      const plaintext = await decryptForContact(otherParty, message.ciphertext, message.iv);
      appendMessageToView(message, plaintext);
    }
  });

  state.socket.on('group-message', async (message) => {
    const group = state.groups.get(message.groupId);
    if (!group) return; // grupo que todavia no hemos cargado localmente
    if (state.currentChat && state.currentChat.type === 'group' && state.currentChat.id === message.groupId) {
      const plaintext = await decryptGroupMessage(group, message.ciphertext, message.iv);
      appendMessageToView(message, plaintext, group);
    }
  });

  // Otro miembro nos ha metido en un grupo nuevo: lo desenvolvemos y lo
  // añadimos a la lista sin necesidad de recargar la pagina.
  state.socket.on('group-created', async (groupPayload) => {
    try {
      await addGroupFromServer(groupPayload);
      renderGroupList();
    } catch (err) {
      console.error('No se pudo incorporar el grupo nuevo:', err);
    }
  });
}

// ---------------------------------------------------------------------------
// Contactos y claves compartidas por conversacion 1 a 1
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
    if (state.currentChat && state.currentChat.type === 'user' && state.currentChat.id === contact.username) {
      li.classList.add('active');
    }
    li.addEventListener('click', () => openChat(contact.username));
    el.contactList.appendChild(li);
  }
}

async function ensureContactPublicKey(contact) {
  if (!contact.publicKey) {
    contact.publicKey = await importPublicKeyJwk(contact.publicKeyJwk);
  }
  return contact.publicKey;
}

async function getSharedKey(username) {
  if (state.sharedKeys.has(username)) return state.sharedKeys.get(username);
  const contact = state.contacts.find((c) => c.username === username);
  if (!contact) throw new Error(`Contacto desconocido: ${username}`);
  await ensureContactPublicKey(contact);
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
// Grupos: creacion, carga y cifrado/descifrado con la clave simetrica compartida
// ---------------------------------------------------------------------------

// Clave AES por pares (ECDH) con un miembro concreto, usada SOLO para envolver
// y desenvolver la clave de grupo (no para cifrar los mensajes del grupo).
async function getPairwiseKeyWith(username) {
  if (username === state.username) {
    // "ECDH con uno mismo": combinacion matematicamente valida de mi privada
    // con mi propia publica, usada para que yo tambien pueda desenvolver mi
    // copia de la clave de grupo (por ejemplo tras reimportar la identidad).
    return deriveSharedAesKey(state.privateKey, state.publicKey);
  }
  return getSharedKey(username);
}

async function loadGroups() {
  const list = await apiFetch('/api/groups');
  for (const groupPayload of list) {
    await addGroupFromServer(groupPayload);
  }
  renderGroupList();
}

async function addGroupFromServer(groupPayload) {
  if (!groupPayload.wrappedKey) return; // no deberia pasar, pero por si acaso
  const pairwiseKey = await getPairwiseKeyWith(groupPayload.createdBy);
  const rawKeyBytes = await unwrapGroupKey(pairwiseKey, groupPayload.wrappedKey);
  const key = await importGroupKey(rawKeyBytes);
  state.groups.set(groupPayload.id, {
    id: groupPayload.id,
    name: groupPayload.name,
    createdBy: groupPayload.createdBy,
    members: groupPayload.members,
    key,
  });
}

function renderGroupList() {
  el.groupList.innerHTML = '';
  const groups = Array.from(state.groups.values()).sort((a, b) => a.name.localeCompare(b.name));
  if (groups.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'contact-empty';
    empty.textContent = 'Todavia no perteneces a ningun grupo.';
    el.groupList.appendChild(empty);
    return;
  }
  for (const group of groups) {
    const li = document.createElement('li');
    li.className = 'contact-item';
    li.innerHTML = `<span class="group-badge">#</span>${escapeHtml(group.name)}`;
    if (state.currentChat && state.currentChat.type === 'group' && state.currentChat.id === group.id) {
      li.classList.add('active');
    }
    li.addEventListener('click', () => openGroup(group.id));
    el.groupList.appendChild(li);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function decryptGroupMessage(group, ciphertext, iv) {
  try {
    return await decryptMessage(group.key, ciphertext, iv);
  } catch (err) {
    console.error('No se pudo descifrar un mensaje de grupo:', err);
    return '[Mensaje ilegible: no se pudo descifrar]';
  }
}

// --- Modal: crear grupo -------------------------------------------------

function openGroupModal() {
  el.groupError.textContent = '';
  el.groupName.value = '';
  el.groupMemberList.innerHTML = '';
  if (state.contacts.length === 0) {
    const li = document.createElement('li');
    li.className = 'checkbox-empty';
    li.textContent = 'No hay otros usuarios registrados todavia.';
    el.groupMemberList.appendChild(li);
  } else {
    for (const contact of state.contacts) {
      const li = document.createElement('li');
      const checkboxId = `group-member-${contact.username}`;
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = checkboxId;
      checkbox.value = contact.username;
      const label = document.createElement('label');
      label.htmlFor = checkboxId;
      label.style.margin = '0';
      label.textContent = contact.username;
      li.appendChild(checkbox);
      li.appendChild(label);
      el.groupMemberList.appendChild(li);
    }
  }
  el.groupModalOverlay.hidden = false;
}

function closeGroupModal() {
  el.groupModalOverlay.hidden = true;
}

el.newGroupBtn.addEventListener('click', openGroupModal);
el.groupCancelBtn.addEventListener('click', closeGroupModal);
el.groupModalOverlay.addEventListener('click', (e) => {
  if (e.target === el.groupModalOverlay) closeGroupModal();
});

el.groupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  el.groupError.textContent = '';

  const name = el.groupName.value.trim();
  const selected = Array.from(el.groupMemberList.querySelectorAll('input[type="checkbox"]:checked')).map(
    (cb) => cb.value
  );

  if (!name) {
    el.groupError.textContent = 'Ponle un nombre al grupo';
    return;
  }
  if (selected.length === 0) {
    el.groupError.textContent = 'Selecciona al menos un miembro';
    return;
  }

  try {
    const members = Array.from(new Set([state.username, ...selected]));

    const rawGroupKeyBytes = generateRawGroupKeyBytes();
    const wrappedKeys = {};
    for (const member of members) {
      const pairwiseKey = await getPairwiseKeyWith(member);
      wrappedKeys[member] = await wrapGroupKeyForMember(pairwiseKey, rawGroupKeyBytes);
    }

    const result = await apiFetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, members: selected, wrappedKeys }),
    });

    const key = await importGroupKey(rawGroupKeyBytes);
    state.groups.set(result.id, {
      id: result.id,
      name: result.name,
      createdBy: result.createdBy,
      members: result.members,
      key,
    });
    renderGroupList();
    closeGroupModal();
    openGroup(result.id);
  } catch (err) {
    el.groupError.textContent = err.message;
  }
});

// ---------------------------------------------------------------------------
// Navegacion movil: mostrar la lista o el chat a pantalla completa
// ---------------------------------------------------------------------------

function showChatView() {
  el.appScreen.classList.add('chat-active');
}

function showListView() {
  el.appScreen.classList.remove('chat-active');
}

el.chatBackBtn.addEventListener('click', () => {
  showListView();
});

// ---------------------------------------------------------------------------
// Ventana de chat (contacto 1 a 1)
// ---------------------------------------------------------------------------

async function openChat(username) {
  state.currentChat = { type: 'user', id: username };
  renderContactList();
  renderGroupList();
  showChatView();

  el.chatEmpty.hidden = true;
  el.chatPanel.hidden = false;
  el.chatContactName.textContent = username;
  el.messageList.innerHTML = '';
  el.chatSecurityCodeRow.hidden = false;
  el.chatGroupMembers.hidden = true;
  el.chatSecurityCode.textContent = 'Calculando codigo de seguridad...';

  const contact = state.contacts.find((c) => c.username === username);
  await ensureContactPublicKey(contact);
  el.chatSecurityCode.textContent = await computeSecurityCode(state.publicKey, contact.publicKey);

  const history = await apiFetch(`/api/messages?with=${encodeURIComponent(username)}`);
  for (const message of history) {
    const plaintext = await decryptForContact(username, message.ciphertext, message.iv);
    appendMessageToView(message, plaintext);
  }
}

// ---------------------------------------------------------------------------
// Ventana de chat (grupo)
// ---------------------------------------------------------------------------

async function openGroup(groupId) {
  const group = state.groups.get(groupId);
  if (!group) return;

  state.currentChat = { type: 'group', id: groupId };
  renderContactList();
  renderGroupList();
  showChatView();

  el.chatEmpty.hidden = true;
  el.chatPanel.hidden = false;
  el.chatContactName.textContent = group.name;
  el.messageList.innerHTML = '';
  el.chatSecurityCodeRow.hidden = true;
  el.chatGroupMembers.hidden = false;
  el.chatGroupMembers.textContent = `Miembros: ${group.members.join(', ')}`;

  const history = await apiFetch(`/api/groups/${encodeURIComponent(groupId)}/messages`);
  for (const message of history) {
    const plaintext = await decryptGroupMessage(group, message.ciphertext, message.iv);
    appendMessageToView(message, plaintext, group);
  }
}

function appendMessageToView(message, plaintext, group) {
  const li = document.createElement('li');
  const outgoing = message.from === state.username;
  li.className = `message ${outgoing ? 'outgoing' : 'incoming'}`;

  if (group && !outgoing) {
    const sender = document.createElement('div');
    sender.className = 'message-sender';
    sender.textContent = message.from;
    li.appendChild(sender);
  }

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
  if (!text || !state.currentChat) return;

  if (state.currentChat.type === 'user') {
    const to = state.currentChat.id;
    const key = await getSharedKey(to);
    const { ciphertext, iv } = await encryptMessage(key, text);
    state.socket.emit('message', { to, ciphertext, iv }, (ack) => {
      if (!ack || !ack.ok) {
        console.error('No se pudo enviar el mensaje:', ack && ack.error);
      }
    });
  } else {
    const groupId = state.currentChat.id;
    const group = state.groups.get(groupId);
    if (!group) return;
    const { ciphertext, iv } = await encryptMessage(group.key, text);
    state.socket.emit('group-message', { groupId, ciphertext, iv }, (ack) => {
      if (!ack || !ack.ok) {
        console.error('No se pudo enviar el mensaje de grupo:', ack && ack.error);
      }
    });
  }

  el.messageInput.value = '';
});

// ---------------------------------------------------------------------------
// Arranque
// ---------------------------------------------------------------------------

switchAuthTab('register');
tryAutoLogin();
