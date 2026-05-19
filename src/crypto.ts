/**
 * Cryptographic primitives for LibreSQL.
 *
 * All operations use the Web Crypto API (`globalThis.crypto.subtle`) so that
 * the raw key material never leaves the browser's secure context.
 *
 * Encryption scheme
 * -----------------
 *   Key derivation : PBKDF2-SHA256, 600 000 iterations (OWASP minimum)
 *   Symmetric cipher: AES-256-GCM (authenticated encryption)
 *   Random values  : crypto.getRandomValues
 */

import {
  EncryptOptions,
  FILE_VERSION,
  HEADER_MAGIC,
  HEADER_SIZE,
  IV_LENGTH,
  KDF_PBKDF2_SHA256,
  OpenOptions,
  SALT_LENGTH,
} from './types.js';

/** Default PBKDF2 iteration count (OWASP 2023 recommendation). */
export const DEFAULT_ITERATIONS = 600_000;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Ensures `src` is a `Uint8Array<ArrayBuffer>` (not SharedArrayBuffer-backed).
 * Creates a copy only when necessary.
 *
 * TypeScript 6+ distinguishes between `Uint8Array<ArrayBuffer>` and
 * `Uint8Array<ArrayBufferLike>`.  The Web Crypto API requires the former.
 */
function toArrayBufferView(src: Uint8Array): Uint8Array<ArrayBuffer> {
  if (src.buffer instanceof ArrayBuffer) {
    return src as Uint8Array<ArrayBuffer>;
  }
  // Copy into a fresh ArrayBuffer (handles SharedArrayBuffer-backed views)
  const copy = new Uint8Array(src.byteLength);
  copy.set(src);
  return copy;
}

/** Fills a new `Uint8Array<ArrayBuffer>` with cryptographically random bytes. */
function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(n) as Uint8Array<ArrayBuffer>;
  crypto.getRandomValues(buf);
  return buf;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * Derives a 256-bit AES-GCM key from a password using PBKDF2-SHA256.
 *
 * @param password   - The user-supplied password.
 * @param salt       - A random 32-byte salt (must be stored alongside the ciphertext).
 * @param iterations - PBKDF2 iteration count (default: 600 000).
 * @returns A non-extractable CryptoKey suitable for AES-256-GCM.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_ITERATIONS,
): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const enc = new TextEncoder();

  const baseKey = await subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toArrayBufferView(salt),
      iterations,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/**
 * Encrypts `plaintext` and returns an encrypted LibreSQL blob.
 *
 * The returned buffer has the following layout (all big-endian):
 * ```
 *  [magic 4B][version 1B][kdf 1B][iterations 4B][salt 32B][iv 12B][ciphertext…]
 * ```
 *
 * @param plaintext - Raw bytes to encrypt (e.g. a SQLite database file).
 * @param options   - Must contain either `password` or `key`.
 * @returns A new Uint8Array containing the encrypted LibreSQL blob.
 */
export async function encryptData(
  plaintext: Uint8Array,
  options: EncryptOptions,
): Promise<Uint8Array> {
  if (!options.password && !options.key) {
    throw new TypeError('encryptData: either "password" or "key" must be provided');
  }

  const iterations = options.iterations ?? DEFAULT_ITERATIONS;
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);

  let key: CryptoKey;
  if (options.key) {
    key = options.key;
  } else {
    key = await deriveKey(options.password!, salt, iterations);
  }

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    toArrayBufferView(plaintext),
  );

  // Build header
  const header = new ArrayBuffer(HEADER_SIZE);
  const view = new DataView(header);
  const headerBytes = new Uint8Array(header);

  // Magic "LSQL"
  headerBytes.set(HEADER_MAGIC, 0);
  // Version
  view.setUint8(4, FILE_VERSION);
  // KDF identifier
  view.setUint8(5, KDF_PBKDF2_SHA256);
  // Iteration count (big-endian)
  view.setUint32(6, iterations, false);
  // Salt
  headerBytes.set(salt, 10);
  // IV
  headerBytes.set(iv, 10 + SALT_LENGTH);

  // Concatenate header + ciphertext
  const result = new Uint8Array(HEADER_SIZE + ciphertext.byteLength);
  result.set(headerBytes, 0);
  result.set(new Uint8Array(ciphertext), HEADER_SIZE);
  return result;
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/**
 * Decrypts an encrypted LibreSQL blob and returns the original plaintext.
 *
 * @param data    - The encrypted blob produced by {@link encryptData}.
 * @param options - Must contain either `password` or `key`.
 * @returns A Uint8Array containing the decrypted plaintext bytes.
 * @throws {TypeError}  When required options are missing or the magic bytes don't match.
 * @throws {DOMException} When decryption fails (wrong key / corrupted data).
 */
export async function decryptData(
  data: Uint8Array,
  options: OpenOptions,
): Promise<Uint8Array> {
  if (!options.password && !options.key) {
    throw new TypeError('decryptData: either "password" or "key" must be provided');
  }
  if (data.byteLength < HEADER_SIZE) {
    throw new TypeError('decryptData: data is too short to be a valid LibreSQL file');
  }

  // Validate magic bytes
  for (let i = 0; i < HEADER_MAGIC.length; i++) {
    if (data[i] !== HEADER_MAGIC[i]) {
      throw new TypeError(
        'decryptData: invalid magic bytes — not a LibreSQL encrypted file',
      );
    }
  }

  const normalised = toArrayBufferView(data);
  const view = new DataView(normalised.buffer, normalised.byteOffset, normalised.byteLength);

  const version = view.getUint8(4);
  if (version !== FILE_VERSION) {
    throw new TypeError(`decryptData: unsupported file version ${version}`);
  }

  const kdf = view.getUint8(5);
  if (kdf !== KDF_PBKDF2_SHA256) {
    throw new TypeError(`decryptData: unsupported KDF identifier ${kdf}`);
  }

  const iterations = view.getUint32(6, false);
  const salt = normalised.slice(10, 10 + SALT_LENGTH);
  const iv = normalised.slice(10 + SALT_LENGTH, 10 + SALT_LENGTH + IV_LENGTH);
  const ciphertext = normalised.slice(HEADER_SIZE);

  let key: CryptoKey;
  if (options.key) {
    key = options.key;
  } else {
    key = await deriveKey(options.password!, salt, iterations);
  }

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext,
  );

  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// Key import / export helpers
// ---------------------------------------------------------------------------

/**
 * Imports raw key material (32 bytes) as a non-extractable AES-256-GCM CryptoKey.
 *
 * @param rawKey - A 32-byte (256-bit) key buffer.
 * @returns An AES-GCM CryptoKey.
 */
export async function importRawKey(rawKey: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Generates a fresh, random 256-bit AES-GCM key.
 *
 * @returns A non-extractable CryptoKey.
 */
export async function generateKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
