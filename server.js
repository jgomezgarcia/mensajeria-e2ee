// server.js
// Servidor "ciego": solo conoce usuarios, sus claves PUBLICAS y mensajes cifrados.
// Nunca ve texto plano ni claves privadas. Todo el cifrado ocurre en el navegador (public/crypto.js).

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;

// La clave de invitacion ya NO vive en .env ni en el codigo: se pide por
// terminal cada vez que arranca el servidor (ver promptInviteCode mas abajo),
// salvo que se pase por variable de entorno INVITE_CODE (util para arranques
// no interactivos, p.ej. systemd o Docker). Se guarda solo en memoria.
let activeInviteCode = null;

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

// ---------------------------------------------------------------------------
// Persistencia local en disco: archivo JSON con escritura atomica (tmp + rename)
// para evitar corrupcion si el proceso se interrumpe a mitad de escritura.
// ---------------------------------------------------------------------------

function loadDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    const empty = { users: {}, messages: [], groups: {}, groupKeys: {}, groupMessages: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.users) parsed.users = {};
    if (!parsed.messages) parsed.messages = [];
    if (!parsed.groups) parsed.groups = {};
    if (!parsed.groupKeys) parsed.groupKeys = {};
    if (!parsed.groupMessages) parsed.groupMessages = [];
    return parsed;
  } catch (err) {
    console.error('No se pudo leer data/db.json, se crea una base nueva:', err.message);
    const empty = { users: {}, messages: [], groups: {}, groupKeys: {}, groupMessages: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
}

function saveDb(db) {
  const tmpFile = DB_FILE + '.tmp';
  fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2));
  fs.renameSync(tmpFile, DB_FILE); // rename es atomico en el mismo filesystem
}

// Estado en memoria, persistido a disco en cada mutacion. Node es single-threaded
// y todas las mutaciones aqui son sincronas, asi que no hay condiciones de carrera.
let db = loadDb();

function findUser(username) {
  return db.users[username];
}

function isValidUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_-]{3,24}$/.test(username);
}

function groupRoom(groupId) {
  return `group:${groupId}`;
}

// Grupos a los que pertenece un usuario (los mas recientes primero).
function groupsForUser(username) {
  return Object.values(db.groups)
    .filter((g) => g.members.includes(username))
    .sort((a, b) => b.createdAt - a.createdAt);
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ---------------------------------------------------------------------------
// Prompt interactivo de la clave de invitacion (nunca se escribe en disco).
// En una terminal real se enmascara con "*"; si no hay TTY (p.ej. systemd,
// Docker sin -it, un pipe) se lee una linea normal para no bloquear el arranque.
// ---------------------------------------------------------------------------

function promptInviteCodeMasked(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    let value = '';
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '') { // Ctrl+C
          cleanup();
          process.stdout.write('\n');
          process.exit(1);
        } else if (char === '\r' || char === '\n') {
          cleanup();
          process.stdout.write('\n');
          resolve(value);
          return;
        } else if (char === '' || char === '\b') { // backspace
          if (value.length > 0) {
            value = value.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          value += char;
          process.stdout.write('*');
        }
      }
    };

    function cleanup() {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
    }

    stdin.on('data', onData);
  });
}

function promptPlain(question) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function resolveInviteCode() {
  if (process.env.INVITE_CODE) {
    console.log('Usando INVITE_CODE de la variable de entorno (no se pedira por terminal).');
    return process.env.INVITE_CODE;
  }

  const question = '\nElige la clave de invitacion para esta sesion del servidor (no se guarda en disco): ';
  const isInteractive = process.stdin.isTTY && process.stdout.isTTY;
  const value = isInteractive
    ? await promptInviteCodeMasked(question)
    : await promptPlain(question);

  if (!value || !value.trim()) {
    console.error('La clave de invitacion no puede estar vacia. Reinicia el servidor e introduce una clave.');
    process.exit(1);
  }
  return value.trim();
}

function parseYesNo(answer, defaultValue) {
  const trimmed = (answer || '').trim().toLowerCase();
  if (!trimmed) return defaultValue;
  if (['s', 'si', 'sí', 'y', 'yes'].includes(trimmed)) return true;
  if (['n', 'no'].includes(trimmed)) return false;
  return defaultValue;
}

// Pregunta si se deben conservar usuarios y conversaciones para la proxima
// vez que se arranque el servidor. Si la respuesta es "no", data/db.json se
// vacia automaticamente cuando el proceso se detenga (Ctrl+C / cierre del
// tunel), para no dejar rastro de esa sesion.
async function resolvePersistData() {
  if (process.env.PERSIST_DATA) {
    return parseYesNo(process.env.PERSIST_DATA, true);
  }

  const isInteractive = process.stdin.isTTY && process.stdout.isTTY;
  if (!isInteractive) {
    console.log('Sin terminal interactiva: se conservaran los datos entre reinicios (usa PERSIST_DATA=no para cambiarlo).');
    return true;
  }

  const question = '¿Guardar usuarios y conversaciones para la proxima vez que arranques el servidor? (S/n): ';
  const answer = await promptPlain(question);
  return parseYesNo(answer, true);
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Necesario para que Express reconozca correctamente el protocolo/host reales
// cuando la app se expone detras de un reverse proxy / Cloudflare Tunnel.
app.set('trust proxy', 1);

// CORS dinamico: reflejamos el origen de la peticion para que funcione tanto en
// http://localhost:3000 como en cualquier https://*.trycloudflare.com aleatorio.
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const username = req.header('x-username');
  const token = req.header('x-token');
  const user = username && findUser(username);
  if (!user || !token || user.token !== token) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  req.username = username;
  next();
}

// Registro: requiere el INVITE_CODE para evitar que cualquiera que encuentre la
// URL del tunel pueda crear una cuenta sin conocer la palabra clave.
app.post('/api/register', (req, res) => {
  const { username, inviteCode, publicKeyJwk } = req.body || {};

  if (inviteCode !== activeInviteCode) {
    return res.status(403).json({ error: 'Codigo de invitacion incorrecto' });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Nombre de usuario invalido (3-24 caracteres, letras/numeros/_/-)' });
  }
  if (!publicKeyJwk || typeof publicKeyJwk !== 'object') {
    return res.status(400).json({ error: 'Falta la clave publica' });
  }
  if (findUser(username)) {
    return res.status(409).json({ error: 'Ese nombre de usuario ya existe' });
  }

  const token = generateToken();
  db.users[username] = { publicKeyJwk, token, createdAt: Date.now() };
  saveDb(db);

  res.json({ username, token });
});

// Verifica que un par (username, token) sigue siendo valido. Se usa al cargar
// la app con una identidad ya existente en IndexedDB (o recien importada).
app.post('/api/session/verify', (req, res) => {
  const { username, token } = req.body || {};
  const user = username && findUser(username);
  if (!user || user.token !== token) {
    return res.status(401).json({ error: 'Sesion invalida' });
  }
  res.json({ ok: true, publicKeyJwk: user.publicKeyJwk });
});

// Directorio de contactos: el servidor solo expone nombres de usuario y claves
// PUBLICAS, nunca texto plano ni claves privadas.
app.get('/api/directory', authMiddleware, (req, res) => {
  const list = Object.entries(db.users).map(([username, u]) => ({
    username,
    publicKeyJwk: u.publicKeyJwk,
  }));
  res.json(list);
});

// Historial cifrado de una conversacion 1 a 1. El servidor jamas descifra nada,
// solo filtra por remitente/destinatario y ordena por fecha.
app.get('/api/messages', authMiddleware, (req, res) => {
  const other = req.query.with;
  if (!isValidUsername(other)) {
    return res.status(400).json({ error: 'Parametro "with" invalido' });
  }
  const me = req.username;
  const history = db.messages
    .filter((m) => (m.from === me && m.to === other) || (m.from === other && m.to === me))
    .sort((a, b) => a.timestamp - b.timestamp);
  res.json(history);
});

// ---------------------------------------------------------------------------
// Grupos: el servidor solo almacena metadatos (nombre, miembros) y, por cada
// miembro, su copia de la clave de grupo ENVUELTA (cifrada). Esa clave de
// grupo se genera en el navegador del creador y se envuelve individualmente
// para cada miembro usando la clave AES derivada por ECDH entre el creador y
// ese miembro (la misma tecnica que ya se usa para los chats 1 a 1). El
// servidor nunca ve la clave de grupo en claro, ni el contenido de los
// mensajes.
// ---------------------------------------------------------------------------

app.post('/api/groups', authMiddleware, (req, res) => {
  const { name, members, wrappedKeys } = req.body || {};
  const me = req.username;

  if (typeof name !== 'string' || !name.trim() || name.length > 60) {
    return res.status(400).json({ error: 'Nombre de grupo invalido (1-60 caracteres)' });
  }
  if (!Array.isArray(members) || members.some((m) => !isValidUsername(m))) {
    return res.status(400).json({ error: 'Lista de miembros invalida' });
  }
  const uniqueMembers = Array.from(new Set([me, ...members]));
  if (uniqueMembers.length < 2) {
    return res.status(400).json({ error: 'Un grupo necesita al menos otro miembro' });
  }
  for (const m of uniqueMembers) {
    if (!findUser(m)) {
      return res.status(400).json({ error: `El usuario "${m}" no existe` });
    }
  }
  if (!wrappedKeys || typeof wrappedKeys !== 'object') {
    return res.status(400).json({ error: 'Falta la clave de grupo envuelta' });
  }
  for (const m of uniqueMembers) {
    const wk = wrappedKeys[m];
    if (!wk || !wk.ciphertext || !wk.iv) {
      return res.status(400).json({ error: `Falta la clave envuelta para "${m}"` });
    }
  }

  const id = crypto.randomUUID();
  const group = {
    id,
    name: name.trim(),
    createdBy: me,
    members: uniqueMembers,
    createdAt: Date.now(),
  };
  db.groups[id] = group;
  db.groupKeys[id] = {};
  for (const m of uniqueMembers) {
    db.groupKeys[id][m] = { ciphertext: wrappedKeys[m].ciphertext, iv: wrappedKeys[m].iv };
  }
  saveDb(db);

  // Metemos en la sala de socket.io a todos los miembros que esten conectados
  // ahora mismo, y avisamos a los que no son el creador para que refresquen
  // su lista de grupos en tiempo real.
  io.in(uniqueMembers).socketsJoin(groupRoom(id));
  for (const m of uniqueMembers) {
    if (m === me) continue;
    io.to(m).emit('group-created', {
      id: group.id,
      name: group.name,
      createdBy: group.createdBy,
      members: group.members,
      createdAt: group.createdAt,
      wrappedKey: db.groupKeys[id][m],
    });
  }

  res.json({
    id: group.id,
    name: group.name,
    createdBy: group.createdBy,
    members: group.members,
    createdAt: group.createdAt,
  });
});

// Lista de grupos del usuario autenticado, cada uno con SU copia (y solo la
// suya) de la clave de grupo envuelta.
app.get('/api/groups', authMiddleware, (req, res) => {
  const me = req.username;
  const list = groupsForUser(me).map((g) => ({
    id: g.id,
    name: g.name,
    createdBy: g.createdBy,
    members: g.members,
    createdAt: g.createdAt,
    wrappedKey: (db.groupKeys[g.id] || {})[me] || null,
  }));
  res.json(list);
});

// Historial cifrado de un grupo. El servidor solo comprueba pertenencia.
app.get('/api/groups/:id/messages', authMiddleware, (req, res) => {
  const group = db.groups[req.params.id];
  if (!group || !group.members.includes(req.username)) {
    return res.status(404).json({ error: 'Grupo no encontrado' });
  }
  const history = db.groupMessages
    .filter((m) => m.groupId === group.id)
    .sort((a, b) => a.timestamp - b.timestamp);
  res.json(history);
});

const server = http.createServer(app);

// ---------------------------------------------------------------------------
// Socket.io: entrega en tiempo real. Mismas reglas de CORS dinamico que Express.
// ---------------------------------------------------------------------------
const io = new Server(server, {
  cors: {
    origin: true,
    methods: ['GET', 'POST'],
  },
});

io.use((socket, next) => {
  const { username, token } = socket.handshake.auth || {};
  const user = username && findUser(username);
  if (!user || !token || user.token !== token) {
    return next(new Error('No autorizado'));
  }
  socket.data.username = username;
  next();
});

io.on('connection', (socket) => {
  const me = socket.data.username;
  socket.join(me); // una "sala" por usuario para poder dirigirle mensajes
  for (const group of groupsForUser(me)) {
    socket.join(groupRoom(group.id));
  }

  socket.on('group-message', (payload, ack) => {
    try {
      const { groupId, ciphertext, iv } = payload || {};
      const group = db.groups[groupId];
      if (!group || !group.members.includes(me) || !ciphertext || !iv) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Payload invalido' });
        return;
      }

      const message = {
        id: crypto.randomUUID(),
        groupId,
        from: me,
        ciphertext, // texto cifrado en base64 con la clave simetrica del grupo, opaco para el servidor
        iv,
        timestamp: Date.now(),
      };

      db.groupMessages.push(message);
      saveDb(db);

      io.to(groupRoom(groupId)).emit('group-message', message);

      if (typeof ack === 'function') ack({ ok: true, message });
    } catch (err) {
      console.error('Error procesando mensaje de grupo:', err);
      if (typeof ack === 'function') ack({ ok: false, error: 'Error interno' });
    }
  });

  socket.on('message', (payload, ack) => {
    try {
      const { to, ciphertext, iv } = payload || {};
      if (!isValidUsername(to) || !findUser(to) || !ciphertext || !iv) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Payload invalido' });
        return;
      }

      const message = {
        id: crypto.randomUUID(),
        from: me,
        to,
        ciphertext, // texto cifrado en base64, opaco para el servidor
        iv,         // IV en base64, unico por mensaje
        timestamp: Date.now(),
      };

      db.messages.push(message);
      saveDb(db);

      io.to(to).emit('message', message);
      io.to(me).emit('message', message); // eco al propio emisor (otras pestañas)

      if (typeof ack === 'function') ack({ ok: true, message });
    } catch (err) {
      console.error('Error procesando mensaje:', err);
      if (typeof ack === 'function') ack({ ok: false, error: 'Error interno' });
    }
  });
});

// ---------------------------------------------------------------------------
// Tunel de Cloudflare opcional: se lanza como proceso hijo cuando arrancas
// con `npm run tunnel` (o `node server.js --tunnel`), para no tener que abrir
// una segunda terminal ni acordarte del comando de cloudflared.
// ---------------------------------------------------------------------------

// Devuelve una funcion para detener el tunel, o null si no se lanzo ninguno.
function maybeStartTunnel() {
  const wantsTunnel = process.argv.includes('--tunnel') || process.env.ENABLE_TUNNEL === '1';
  if (!wantsTunnel) return null;

  console.log('\nIniciando Cloudflare Tunnel (cloudflared)...\n');
  const { spawn } = require('child_process');
  // shell:true para que funcione igual en Linux/macOS y en Windows (resolucion
  // de "cloudflared" / "cloudflared.exe" vía PATH a traves del shell del SO).
  const tunnel = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${PORT}`], {
    stdio: 'inherit',
    shell: true,
  });

  tunnel.on('error', (err) => {
    console.error('No se pudo lanzar cloudflared. ¿Esta instalado y en el PATH? Detalle:', err.message);
  });

  const stopTunnel = () => {
    try { tunnel.kill(); } catch (_) { /* ya estaba parado */ }
  };
  process.on('exit', stopTunnel);
  return stopTunnel;
}

// Vacia la base de datos local (usuarios, mensajes y grupos) para no dejar
// rastro de esta sesion cuando el usuario elige no conservar los datos.
function resetDb() {
  db = { users: {}, messages: [], groups: {}, groupKeys: {}, groupMessages: [] };
  saveDb(db);
}

async function main() {
  activeInviteCode = await resolveInviteCode();
  const persistData = await resolvePersistData();

  let stopTunnel = null;

  // Un unico manejador para Ctrl+C / cierre del proceso: para el tunel si
  // estaba activo y, si el usuario pidio no conservar los datos, vacia
  // data/db.json antes de salir.
  const handleShutdown = () => {
    if (stopTunnel) stopTunnel();
    if (!persistData) {
      console.log('\nBorrando usuarios y conversaciones de esta sesion (se pidio no conservarlos)...');
      resetDb();
    }
    process.exit(0);
  };
  process.on('SIGINT', handleShutdown);
  process.on('SIGTERM', handleShutdown);

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\nServidor de mensajeria E2EE escuchando en http://0.0.0.0:${PORT}`);
    console.log('Clave de invitacion activa para esta sesion (compartela solo con quien quieras invitar).');
    console.log(persistData
      ? 'Los datos de esta sesion se conservaran para la proxima vez.'
      : 'Los datos de esta sesion se borraran al cerrar el servidor (Ctrl+C).');
    stopTunnel = maybeStartTunnel();
  });
}

main();
