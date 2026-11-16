# Mensajeria E2EE (modo bunker local)

Mensajeria privada con **cifrado de extremo a extremo (E2EE)**. Todo el
cifrado y descifrado ocurre en el navegador con la Web Crypto API nativa
(`window.crypto.subtle`) — la clave privada de cada persona nunca sale de su
propio navegador. El servidor es "ciego": solo almacena nombres de usuario,
claves **publicas** y mensajes ya cifrados (`{ id, from, to, ciphertext, iv,
timestamp }`). Nunca ve texto plano ni claves privadas.

Pensada para correr en local (tu propio PC/Mac/servidor Linux) y exponerse
solo cuando quieras, mediante un [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
sin necesidad de abrir puertos en tu router ni tener una IP publica.

## Como funciona la seguridad, en resumen

- **Identidad** = un par de claves ECDH (P-256) que genera tu propio
  navegador al registrarte. La privada vive solo en tu navegador
  (IndexedDB); la publica se manda al servidor.
- **Por cada conversacion 1 a 1** se deriva, via ECDH, un secreto compartido
  distinto, y con el se cifran los mensajes con AES-GCM-256 (IV aleatorio
  por mensaje).
- **Codigo de seguridad** (en la cabecera de cada chat): hash SHA-256 de
  ambas claves publicas. Compararlo en persona con tu contacto confirma que
  nadie esta interceptando la conexion (MITM).
- **Clave de invitacion**: es la unica puerta de entrada para registrarse.
  Desde esta version, **ya no se guarda en ningun archivo ni en el codigo**:
  el servidor te la pide por terminal cada vez que arranca (ver mas abajo).
  Si pierdes/cierras esa terminal, la clave se olvida — tendras que arrancar
  de nuevo y fijar una (la misma o una distinta).

## Indice

1. [Instalar Node.js](#1-instalar-nodejs)
2. [Instalar cloudflared](#2-instalar-cloudflared)
3. [Descargar e instalar el proyecto](#3-descargar-e-instalar-el-proyecto)
4. [Arrancar la app](#4-arrancar-la-app)
5. [Uso de la aplicacion](#5-uso-de-la-aplicacion)
6. [Arranque no interactivo (servidores, Docker, systemd)](#6-arranque-no-interactivo-servidores-docker-systemd)
7. [Datos persistidos](#7-datos-persistidos)

---

## 1. Instalar Node.js

Se necesita **Node.js 18 o superior**. Elige tu sistema:

### Linux (recomendado: nvm, funciona igual en cualquier distro)

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
# Cierra y reabre la terminal, o ejecuta:
source ~/.bashrc   # o ~/.zshrc si usas zsh

nvm install --lts
node -v   # deberia mostrar v18 o superior
```

Alternativa con el gestor de paquetes de tu distro:

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y nodejs npm

# Fedora
sudo dnf install -y nodejs npm

# Arch Linux
sudo pacman -S nodejs npm
```

> En Debian/Ubuntu el paquete del repositorio suele ir bastante por detras.
> Si `node -v` te da menos de 18, usa nvm (arriba) o el repositorio oficial
> de NodeSource: https://github.com/nodesource/distributions

### macOS

```bash
brew install node
```
(si no tienes Homebrew: https://brew.sh)

### Windows

Descarga el instalador LTS desde https://nodejs.org y sigue el asistente, o
con [winget](https://learn.microsoft.com/windows/package-manager/winget/):

```powershell
winget install OpenJS.NodeJS.LTS
```

---

## 2. Instalar cloudflared

Solo lo necesitas si quieres **exponer** la app por internet. Para usarla
solo en tu propia maquina puedes saltarte este paso.

### Linux

```bash
# Debian / Ubuntu (x86_64)
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# Fedora / RHEL (x86_64)
curl -L --output cloudflared.rpm https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.rpm
sudo rpm -i cloudflared.rpm

# Arch Linux (AUR)
yay -S cloudflared

# Cualquier distro, binario generico (x86_64)
curl -L --output cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/cloudflared
```

> Para ARM64 (Raspberry Pi de 64 bits, etc.) cambia `amd64` por `arm64` en
> las URLs anteriores.

Verifica la instalacion:
```bash
cloudflared --version
```

### macOS

```bash
brew install cloudflared
```

### Windows

```powershell
winget install --id Cloudflare.cloudflared
```
O descarga el `.exe` desde https://github.com/cloudflare/cloudflared/releases/latest.

Documentacion oficial completa: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

---

## 3. Descargar e instalar el proyecto

```bash
git clone <URL-DE-ESTE-REPOSITORIO>
cd mensajeria-e2ee
npm install
```

(Si ya tienes el codigo descargado sin `git clone`, simplemente entra en la
carpeta del proyecto y ejecuta `npm install`.)

---

## 4. Arrancar la app

### Opcion A: solo en local (sin tunel)

```bash
npm start
```

El servidor te preguntara en la propia terminal:

```
Elige la clave de invitacion para esta sesion del servidor (no se guarda en disco):
```

Escribe la que quieras (se enmascara con `*` mientras la escribes) y pulsa
Enter. Esa es la clave que tendras que compartir con quien quieras invitar a
registrarse — nadie puede crear una cuenta sin ella.

Abre `http://localhost:3000` en el navegador.

### Opcion B: servidor + Cloudflare Tunnel en un solo comando

```bash
npm run tunnel
```

Hace lo mismo que `npm start` (te pide la clave de invitacion por terminal)
y, en cuanto el servidor arranca, lanza `cloudflared` automaticamente y
muestra en la misma terminal la URL publica temporal, algo como:

```
https://algo-aleatorio.trycloudflare.com
```

Comparte esa URL **y** la clave de invitacion solo con las personas con las
que quieras chatear — cualquiera que tenga la URL pero no la clave no podra
registrarse.

Para parar todo (servidor + tunel), simplemente `Ctrl+C` en esa terminal.

> Si prefieres controlarlo por separado (dos terminales), tambien puedes
> hacer `npm start` en una y, en otra, `cloudflared tunnel --url http://localhost:3000`.

---

## 5. Uso de la aplicacion

1. **Registro**: cada persona elige su nombre de usuario y escribe la clave
   de invitacion que te haya compartido quien arranco el servidor. El
   navegador genera su propio par de claves ECDH; la privada se queda en su
   IndexedDB y nunca se envia al servidor.
2. **Exportar clave**: pulsa "Exportar clave" para descargar un `.json` de
   respaldo. Guardalo en un sitio seguro — es la unica forma de recuperar el
   acceso al historial si cambias de navegador o borras los datos del sitio.
3. **Importar clave**: en un navegador nuevo, pestaña "Importar clave" y
   selecciona ese `.json` para recuperar tu identidad sin volver a pedir la
   clave de invitacion.
4. **Codigo de seguridad**: al abrir un chat, en la cabecera aparece un
   codigo derivado de las dos claves publicas (SHA-256). Comparalo en
   persona (o por otro canal de confianza) con tu contacto: si coincide
   exactamente, la conexion no esta siendo interceptada.

---

## 6. Arranque no interactivo (servidores, Docker, systemd)

Si vas a dejar esto corriendo de forma desatendida (sin que haya alguien
delante de la terminal para teclear la clave), puedes fijarla por variable
de entorno y el servidor **no** la pedira por pantalla:

```bash
INVITE_CODE="tu-clave-aqui" npm start
# o, con tunel incluido:
INVITE_CODE="tu-clave-aqui" npm run tunnel
```

En ese caso ten cuidado de no dejar esa clave en archivos que se suban a un
repositorio publico (el `.env` del proyecto esta en `.gitignore` por este
motivo).

---

## 7. Datos persistidos

Los datos viven en `data/db.json` (usuarios, claves publicas y mensajes
cifrados), escrito de forma atomica para evitar corrupcion. Para resetear
todo el servidor, simplemente borra ese archivo con el servidor parado.

Ese archivo (y el `.env` real de tu maquina) estan excluidos del
repositorio via `.gitignore` — nunca se suben a GitHub.
