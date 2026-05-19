/**
 * LibreSQL – E2EE SQLite for the browser.
 *
 * @example
 * ```ts
 * import { LibreSQL, KeyStore, deriveKey } from 'libresql';
 *
 * // Derive key once at login and keep it in the secure in-memory store
 * const key = await deriveKey(password, salt);
 * KeyStore.set('main', key);
 *
 * // Load an encrypted database from a remote URL
 * const db = await LibreSQL.fromURL('https://cdn.example.com/app.lsql', {
 *   key: KeyStore.get('main')!,
 * });
 *
 * const [result] = db.exec('SELECT * FROM files WHERE name LIKE ?', ['%.pdf']);
 * console.log(result.values);
 *
 * db.close();
 * ```
 */

import initSqlJs, { Database, BindParams, QueryExecResult } from 'sql.js';
import { decryptData, encryptData } from './crypto.js';
import {
  BindParams as LibreBindParams,
  CreateOptions,
  DatabaseEncryptOptions,
  OpenOptions,
  QueryResult,
  WasmOptions,
} from './types.js';

// ---------------------------------------------------------------------------
// WASM bootstrap helper
// ---------------------------------------------------------------------------

let _sqlJsPromise: ReturnType<typeof initSqlJs> | undefined;

async function getSqlJs(options?: WasmOptions): ReturnType<typeof initSqlJs> {
  if (_sqlJsPromise) return _sqlJsPromise;

  const config: Parameters<typeof initSqlJs>[0] = {};

  if (options?.wasmBinary) {
    config.wasmBinary = options.wasmBinary as ArrayBuffer;
  } else if (options?.wasmBinaryPath) {
    config.locateFile = () => options.wasmBinaryPath!;
  }

  _sqlJsPromise = initSqlJs(config);
  return _sqlJsPromise;
}

// ---------------------------------------------------------------------------
// LibreSQL
// ---------------------------------------------------------------------------

/**
 * A browser-based, end-to-end encrypted SQLite database.
 *
 * Each `LibreSQL` instance holds a reference to a `CryptoKey` that is used
 * automatically by {@link LibreSQL#encrypt} — no need to pass the key on
 * every operation.  The key is non-extractable (raw bytes never accessible
 * to JavaScript) and is kept in memory only for the lifetime of the instance.
 *
 * ### Key lifecycle
 *
 * ```ts
 * // 1. Derive key once at login (store the salt server-side in the user profile)
 * const key = await deriveKey(password, storedSalt);
 * KeyStore.set('main', key);
 *
 * // 2. Open — key is stored in the db instance automatically
 * const db = await LibreSQL.fromURL(url, { key: KeyStore.get('main')! });
 *
 * // 3. Write — onWrite() callback fires after every run()
 * db.run('INSERT INTO logs VALUES (?, ?)', [Date.now(), 'action']);
 *
 * // 4. Persist — no key argument needed
 * const blob = await db.encrypt();
 * await fetch('/api/db', { method: 'PUT', body: blob });
 *
 * // 5. Logout
 * db.close();
 * KeyStore.delete('main');
 * ```
 *
 * ### Extending with push-on-write
 *
 * ```ts
 * class CloudDB extends LibreSQL {
 *   protected override onWrite(): void {
 *     // fire-and-forget push after every write
 *     void this.encrypt().then(blob =>
 *       fetch('/api/db', { method: 'PUT', body: blob })
 *     );
 *   }
 * }
 * ```
 */
export class LibreSQL {
  /** @internal */
  private readonly _db: Database;

  /** @internal */
  private _key: CryptoKey;

  /** @internal */
  protected constructor(db: Database, key: CryptoKey) {
    this._db = db;
    this._key = key;
  }

  // -------------------------------------------------------------------------
  // Factory: from encrypted sources
  // -------------------------------------------------------------------------

  /**
   * Fetches an encrypted LibreSQL file from `url`, decrypts it in the browser,
   * and returns a ready-to-query {@link LibreSQL} instance.
   *
   * The raw database bytes **never** leave the browser; only the encrypted
   * blob is transmitted over the network.
   *
   * @param url     - URL of the encrypted `.lsql` file.
   * @param options - Decryption options (`password` or `key`).
   * @param init    - Optional `RequestInit` forwarded to `fetch()`.
   */
  static async fromURL(
    url: string,
    options: OpenOptions,
    init?: RequestInit,
  ): Promise<LibreSQL> {
    const response = await fetch(url, init);
    if (!response.ok) {
      throw new Error(
        `LibreSQL.fromURL: HTTP ${response.status} ${response.statusText} — ${url}`,
      );
    }
    const buffer = await response.arrayBuffer();
    return LibreSQL.fromBuffer(buffer, options);
  }

  /**
   * Reads an encrypted LibreSQL file selected by the user (e.g. via an
   * `<input type="file">` element), decrypts it, and returns a
   * {@link LibreSQL} instance.
   *
   * @param file    - A browser `File` object.
   * @param options - Decryption options (`password` or `key`).
   */
  static async fromFile(file: File, options: OpenOptions): Promise<LibreSQL> {
    const buffer = await file.arrayBuffer();
    return LibreSQL.fromBuffer(buffer, options);
  }

  /**
   * Decrypts an encrypted LibreSQL blob and returns a {@link LibreSQL}
   * instance backed by the decrypted SQLite database.
   *
   * The resolved `CryptoKey` (whether supplied directly or derived from the
   * password in the blob header) is stored in the instance so that subsequent
   * {@link LibreSQL#encrypt} calls require no key argument.
   *
   * @param buffer  - Encrypted LibreSQL blob (`ArrayBuffer` or `Uint8Array`).
   * @param options - Decryption options (`password` or `key`).
   */
  static async fromBuffer(
    buffer: ArrayBuffer | Uint8Array,
    options: OpenOptions,
  ): Promise<LibreSQL> {
    const data =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const { data: plaintext, key } = await decryptData(data, options);
    return LibreSQL._fromPlainBytes(plaintext, key);
  }

  // -------------------------------------------------------------------------
  // Factory: from plaintext sources (for bootstrapping / migration)
  // -------------------------------------------------------------------------

  /**
   * Creates a new, empty in-memory SQLite database.
   *
   * Use this to build a database programmatically before encrypting and
   * persisting it.  The supplied `key` is stored in the instance and used
   * automatically by all future {@link LibreSQL#encrypt} calls.
   *
   * @param options - WASM configuration and the required encryption key.
   */
  static async create(options: CreateOptions): Promise<LibreSQL> {
    const SQL = await getSqlJs(options);
    return new LibreSQL(new SQL.Database(), options.key);
  }

  /**
   * Opens a raw (unencrypted) SQLite file as a `LibreSQL` instance.
   *
   * Useful for migrating an existing SQLite database into LibreSQL: open it
   * here, then call {@link LibreSQL#encrypt} to produce an encrypted blob.
   *
   * @param buffer  - Raw SQLite bytes (`ArrayBuffer` or `Uint8Array`).
   * @param options - WASM configuration and the required encryption key.
   */
  static async fromPlainBuffer(
    buffer: ArrayBuffer | Uint8Array,
    options: CreateOptions,
  ): Promise<LibreSQL> {
    const bytes =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return LibreSQL._fromPlainBytes(bytes, options.key, options);
  }

  /** @internal */
  private static async _fromPlainBytes(
    bytes: Uint8Array,
    key: CryptoKey,
    options?: WasmOptions,
  ): Promise<LibreSQL> {
    const SQL = await getSqlJs(options);
    return new LibreSQL(new SQL.Database(bytes), key);
  }

  // -------------------------------------------------------------------------
  // SQL interface — reads
  // -------------------------------------------------------------------------

  /**
   * Executes one or more SQL `SELECT` statements and returns all result sets.
   *
   * For data-modification statements (`INSERT`, `UPDATE`, `DELETE`) prefer
   * {@link LibreSQL#run}, which triggers the {@link LibreSQL#onWrite} callback.
   *
   * @param sql    - SQL string (may contain `?` or named `$param` placeholders).
   * @param params - Bind parameters.
   * @returns Array of {@link QueryResult} objects, one per result-producing statement.
   *
   * @example
   * ```ts
   * const [result] = db.exec('SELECT id, name FROM files WHERE size > ?', [1024]);
   * for (const [id, name] of result.values) {
   *   console.log(id, name);
   * }
   * ```
   */
  exec(sql: string, params?: LibreBindParams): QueryResult[] {
    const raw: QueryExecResult[] = this._db.exec(sql, params as BindParams);
    return raw as QueryResult[];
  }

  // -------------------------------------------------------------------------
  // SQL interface — writes
  // -------------------------------------------------------------------------

  /**
   * Executes a single data-modification SQL statement (`INSERT`, `UPDATE`,
   * `DELETE`, `CREATE`, etc.) and fires the {@link LibreSQL#onWrite} callback.
   *
   * Override {@link LibreSQL#onWrite} in a subclass to implement push-on-write
   * or any other write-reaction strategy.
   *
   * @param sql    - SQL string.
   * @param params - Bind parameters.
   * @returns `this` for chaining.
   */
  run(sql: string, params?: LibreBindParams): this {
    this._db.run(sql, params as BindParams);
    void this.onWrite();
    return this;
  }

  /**
   * Called automatically after every {@link LibreSQL#run} invocation.
   *
   * Override this in a subclass to react to writes — for example, to
   * re-encrypt and push the database to the server after every change:
   *
   * ```ts
   * class CloudDB extends LibreSQL {
   *   protected override onWrite(): void {
   *     void this.encrypt().then(blob =>
   *       fetch('/api/db', { method: 'PUT', body: blob })
   *     );
   *   }
   * }
   * ```
   *
   * Any `Promise` returned is **not** awaited by `run()`.  If the callback
   * throws synchronously the error will be an unhandled rejection.
   */
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  protected onWrite(): void | Promise<void> {}

  // -------------------------------------------------------------------------
  // Key management
  // -------------------------------------------------------------------------

  /**
   * The `CryptoKey` stored in this database instance.
   *
   * The key is non-extractable — raw bytes cannot be read by JavaScript.
   * Use this to copy the key into {@link KeyStore} after password-based
   * decryption so subsequent sessions can use the key directly:
   *
   * ```ts
   * const db = await LibreSQL.fromURL(url, { password });
   * KeyStore.set('main', db.key);
   * ```
   */
  get key(): CryptoKey {
    return this._key;
  }

  /**
   * Replaces the stored encryption key.
   *
   * The new key takes effect on the next {@link LibreSQL#encrypt} call.
   * This does **not** re-encrypt any data immediately.
   *
   * @param newKey - The new AES-256-GCM `CryptoKey`.
   */
  rotateKey(newKey: CryptoKey): void {
    this._key = newKey;
  }

  // -------------------------------------------------------------------------
  // Export (encrypted only)
  // -------------------------------------------------------------------------

  /**
   * Vacuums, optionally compresses, and encrypts the current database using
   * the stored {@link LibreSQL#key}.
   *
   * The returned blob can be sent to a server or stored in object storage
   * without exposing any SQL data — decryption requires the key that only
   * the end-user holds.
   *
   * @param options - Optional tuning. Both `vacuum` and `compress` default to
   *   `true` to minimise the blob size.
   * @returns `Uint8Array` containing the encrypted LibreSQL blob.
   *
   * @example
   * ```ts
   * const blob = await db.encrypt();
   * await fetch('/api/db', { method: 'PUT', body: blob });
   * ```
   */
  async encrypt(options?: DatabaseEncryptOptions): Promise<Uint8Array> {
    if (options?.vacuum !== false) {
      this._db.run('VACUUM');
    }
    const raw = this._db.export();
    return encryptData(raw, {
      key: this._key,
      compress: options?.compress !== false,
    });
  }

  // -------------------------------------------------------------------------
  // Version fingerprinting
  // -------------------------------------------------------------------------

  /**
   * Returns a SHA-256 hex digest of the current database content.
   *
   * The digest is computed over the **unencrypted** SQLite bytes (the raw
   * bytes never leave the instance).  Because it is deterministic, two
   * database instances with the same data will produce the same digest —
   * useful for detecting whether a sync is needed:
   *
   * ```ts
   * const localDigest  = await db.digest();
   * const remoteDigest = await fetch('/api/db.sha256').then(r => r.text());
   *
   * if (localDigest !== remoteDigest) {
   *   // Remote has newer data — fetch and reload
   * }
   * ```
   *
   * @returns Lowercase hex-encoded SHA-256 string (64 characters).
   */
  async digest(): Promise<string> {
    const raw = this._db.export();
    // Ensure plain ArrayBuffer backing for Web Crypto
    const data = new Uint8Array(raw.byteLength);
    data.set(raw);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Closes the database and frees WASM memory.
   *
   * After calling `close()`, any further method calls on this instance will
   * throw an error.
   */
  close(): void {
    this._db.close();
  }
}
