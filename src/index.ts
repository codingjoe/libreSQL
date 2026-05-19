/**
 * libreSQL – browser-based E2EE SQLite database.
 *
 * @example
 * ```ts
 * import { LibreSQL } from 'libresql';
 *
 * // Load an encrypted database from a remote URL
 * const db = await LibreSQL.fromURL('https://cdn.example.com/store.lsql', {
 *   password: 'correct horse battery staple',
 * });
 *
 * const [result] = db.exec('SELECT * FROM files');
 * console.log(result.columns, result.values);
 *
 * db.close();
 * ```
 *
 * @module
 */

// Main class
export { LibreSQL } from './database.js';

// Crypto primitives (for advanced use-cases)
export { decryptData, deriveKey, encryptData, generateKey, importRawKey } from './crypto.js';

// Types
export type {
  BindParams,
  CreateOptions,
  EncryptOptions,
  OpenOptions,
  QueryResult,
  SqlValue,
} from './types.js';
