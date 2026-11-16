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
    const empty = { users: {}, messages: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.users) parsed.users = {};
    if (!parsed.messages) parsed.messages = [];
    return parsed;
  } catch (err) {
    console.error('No se pudo leer data/db.json, se crea una base nueva:', err.message);
    const empty = { users: {}, messages: [] };
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

function promptInviteCodePlain(question) {
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
    : await promptInviteCodePlain(question);

  if (!value || !value.trim()) {
    console.error('La clave de invitacion no puede estar vacia. Reinicia el servidor e introduce una clave.');
    process.exit(1);
  }
  return value.trim();
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

function maybeStartTunnel() {
  const wantsTunnel = process.argv.includes('--tunnel') || process.env.ENABLE_TUNNEL === '1';
  if (!wantsTunnel) return;

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
  process.on('SIGINT', () => { stopTunnel(); process.exit(0); });
  process.on('SIGTERM', () => { stopTunnel(); process.exit(0); });
}

async function main() {
  activeInviteCode = await resolveInviteCode();

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\nServidor de mensajeria E2EE escuchando en http://0.0.0.0:${PORT}`);
    console.log('Clave de invitacion activa para esta sesion (compartela solo con quien quieras invitar).');
    maybeStartTunnel();
  });
}

main();
