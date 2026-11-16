// crypto.js
// Modulo ES6 con todas las operaciones criptograficas del cliente.
// Usa EXCLUSIVAMENTE window.crypto.subtle (Web Crypto API nativa del navegador).
// Nada de lo que hay aqui envia texto plano ni claves privadas a ningun servidor.

const EC_ALGORITHM = { name: 'ECDH', namedCurve: 'P-256' };

// --- Utilidades de codificacion ------------------------------------------

export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// --- Identidad: par de claves ECDH (P-256) --------------------------------

// Genera el par de claves asimetricas de identidad del usuario.
// extractable = true para permitir el backup/exportacion de la clave privada.
export async function generateIdentityKeyPair() {
  return window.crypto.subtle.generateKey(EC_ALGORITHM, true, ['deriveKey', 'deriveBits']);
}

export async function exportPublicKeyJwk(publicKey) {
  return window.crypto.subtle.exportKey('jwk', publicKey);
}

export async function exportPrivateKeyJwk(privateKey) {
  return window.crypto.subtle.exportKey('jwk', privateKey);
}

export async function importPublicKeyJwk(jwk) {
  return window.crypto.subtle.importKey('jwk', jwk, EC_ALGORITHM, true, []);
}

export async function importPrivateKeyJwk(jwk) {
  return window.crypto.subtle.importKey('jwk', jwk, EC_ALGORITHM, true, ['deriveKey', 'deriveBits']);
}

// --- Secreto compartido por chat (ECDH -> AES-GCM 256) --------------------

// Deriva, para una conversacion 1 a 1, la clave simetrica AES-GCM-256 compartida
// a partir de MI clave privada y la clave publica del contacto. Por propiedad
// matematica de ECDH, el contacto obtiene la MISMA clave con su privada + mi
// publica, sin que ese secreto viaje nunca por la red.
export async function deriveSharedAesKey(myPrivateKey, contactPublicKey) {
  return window.crypto.subtle.deriveKey(
    { name: 'ECDH', public: contactPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false, // la clave derivada no necesita ser extraible, solo se usa en memoria
    ['encrypt', 'decrypt']
  );
}

// --- Cifrado / descifrado de mensajes (AES-GCM, IV aleatorio por mensaje) -

export async function encryptMessage(aesKey, plaintext) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96 bits, recomendado para GCM
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encoded
  );
  return {
    ciphertext: bufferToBase64(ciphertextBuffer),
    iv: bufferToBase64(iv),
  };
}

export async function decryptMessage(aesKey, ciphertextB64, ivB64) {
  const ciphertextBuffer = base64ToBuffer(ciphertextB64);
  const iv = new Uint8Array(base64ToBuffer(ivB64));
  const plaintextBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertextBuffer
  );
  return new TextDecoder().decode(plaintextBuffer);
}

// --- Codigo de seguridad anti-MITM -----------------------------------------

// Huella SHA-256 de ambas claves publicas, ordenadas alfabeticamente antes de
// concatenar para que ambos interlocutores calculen exactamente el mismo valor
// sin importar quien sea "yo" y quien sea "el contacto".
export async function computeSecurityCode(publicKeyA, publicKeyB) {
  const rawA = bufferToHex(await window.crypto.subtle.exportKey('raw', publicKeyA));
  const rawB = bufferToHex(await window.crypto.subtle.exportKey('raw', publicKeyB));
  const [first, second] = [rawA, rawB].sort();
  const concatenated = new TextEncoder().encode(first + second);
  const digest = await window.crypto.subtle.digest('SHA-256', concatenated);
  const hex = bufferToHex(digest);
  // Se agrupa en bloques de 5 caracteres para que sea legible al compararlo en persona.
  return hex.match(/.{1,5}/g).join(' ').toUpperCase();
}
