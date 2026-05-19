/**
 * libreSQL – browser-based E2EE SQLite database.
 *
 * @example
 * ```ts
 * import { LibreSQL, KeyStore, deriveKey } from 'libresql';
 *
 * // Derive key once at login; store securely in-session
 * const key = await deriveKey(password, salt);
 * KeyStore.set('main', key);
 *
 * // Load an encrypted database from a remote URL
 * const db = await LibreSQL.fromURL('https://cdn.example.com/store.lsql', {
 *   key: KeyStore.get('main')!,
 * });
 *
 * const [result] = db.exec("SELECT * FROM files WHERE name LIKE '%.pdf'");
 * console.log(result.values);
 *
 * db.close();
 * ```
 *
 * @module
 */

// Main class
export { LibreSQL } from './database.js';

// Secure session key storage
export { KeyStore } from './keystore.js';

// Crypto primitives (for advanced use-cases)
export { DEFAULT_ITERATIONS, decryptData, deriveKey, encryptData, generateKey, importRawKey } from './crypto.js';
export type { DecryptResult } from './crypto.js';

// Types
export type {
  BindParams,
  CreateOptions,
  DatabaseEncryptOptions,
  EncryptOptions,
  OpenOptions,
  QueryResult,
  SqlValue,
  WasmOptions,
} from './types.js';
