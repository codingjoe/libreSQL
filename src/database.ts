/**
 * LibreSQL – E2EE SQLite for the browser.
 *
 * Typical usage (loading an encrypted database from a remote URL):
 * ```ts
 * import { LibreSQL } from 'libresql';
 *
 * const db = await LibreSQL.fromURL('https://cdn.example.com/app.lsql', {
 *   password: 'hunter2',
 * });
 * const results = db.exec('SELECT * FROM files WHERE name LIKE ?', ['%.pdf']);
 * db.close();
 * ```
 */

import initSqlJs, { Database, BindParams, QueryExecResult } from 'sql.js';
import { decryptData, encryptData } from './crypto.js';
import { BindParams as LibreBindParams, CreateOptions, EncryptOptions, OpenOptions, QueryResult } from './types.js';

// ---------------------------------------------------------------------------
// WASM bootstrap helper
// ---------------------------------------------------------------------------

let _sqlJsPromise: ReturnType<typeof initSqlJs> | undefined;

/**
 * Returns a (cached) sql.js module.  The WASM binary is loaded from the
 * local `sql-wasm.wasm` asset by default, which Vite/bundlers will resolve
 * automatically.  Pass a custom `locateFile` via `CreateOptions.wasmBinaryPath`
 * to override.
 */
async function getSqlJs(options?: CreateOptions): ReturnType<typeof initSqlJs> {
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
 * Databases are encrypted at rest and in transit using AES-256-GCM with keys
 * derived via PBKDF2-SHA256.  The plaintext SQL data never leaves the browser
 * context: all cryptographic operations are performed using the Web Crypto API.
 *
 * @example
 * ```ts
 * // Load from a remote encrypted file
 * const db = await LibreSQL.fromURL('https://example.com/store.lsql', {
 *   password: 'my-password',
 * });
 *
 * // Query
 * const [result] = db.exec('SELECT id, name FROM files');
 * console.log(result.values);
 *
 * // Always close when done to free WASM memory
 * db.close();
 * ```
 */
export class LibreSQL {
  /** @internal */
  private readonly _db: Database;

  /** @internal */
  private constructor(db: Database) {
    this._db = db;
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
   * @param buffer  - Encrypted LibreSQL blob (`ArrayBuffer` or `Uint8Array`).
   * @param options - Decryption options (`password` or `key`).
   */
  static async fromBuffer(
    buffer: ArrayBuffer | Uint8Array,
    options: OpenOptions,
  ): Promise<LibreSQL> {
    const data =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const plaintext = await decryptData(data, options);
    return LibreSQL._fromPlainBytes(plaintext);
  }

  // -------------------------------------------------------------------------
  // Factory: from plaintext sources (for bootstrapping / testing)
  // -------------------------------------------------------------------------

  /**
   * Creates a new, empty in-memory SQLite database.
   *
   * Use this to build a database programmatically before encrypting and
   * persisting it.
   *
   * @param options - Optional WASM configuration.
   */
  static async create(options?: CreateOptions): Promise<LibreSQL> {
    const SQL = await getSqlJs(options);
    return new LibreSQL(new SQL.Database());
  }

  /**
   * Opens a raw (unencrypted) SQLite file as a `LibreSQL` instance.
   *
   * Useful for migrating an existing SQLite database into LibreSQL: open it
   * here, then call {@link LibreSQL.encrypt} to produce an encrypted blob.
   *
   * @param buffer  - Raw SQLite bytes (`ArrayBuffer` or `Uint8Array`).
   * @param options - Optional WASM configuration.
   */
  static async fromPlainBuffer(
    buffer: ArrayBuffer | Uint8Array,
    options?: CreateOptions,
  ): Promise<LibreSQL> {
    const bytes =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return LibreSQL._fromPlainBytes(bytes, options);
  }

  /** @internal */
  private static async _fromPlainBytes(
    bytes: Uint8Array,
    options?: CreateOptions,
  ): Promise<LibreSQL> {
    const SQL = await getSqlJs(options);
    return new LibreSQL(new SQL.Database(bytes));
  }

  // -------------------------------------------------------------------------
  // SQL interface
  // -------------------------------------------------------------------------

  /**
   * Executes one or more SQL statements and returns all result sets.
   *
   * For data-modification statements (`INSERT`, `UPDATE`, `DELETE`) the
   * returned array will be empty.
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
    // sql.js QueryExecResult is structurally identical to our QueryResult
    const raw: QueryExecResult[] = this._db.exec(sql, params as BindParams);
    return raw as QueryResult[];
  }

  /**
   * Executes a single data-modification SQL statement.
   *
   * @param sql    - SQL string.
   * @param params - Bind parameters.
   * @returns `this` for chaining.
   */
  run(sql: string, params?: LibreBindParams): this {
    this._db.run(sql, params as BindParams);
    return this;
  }

  // -------------------------------------------------------------------------
  // Export
  // -------------------------------------------------------------------------

  /**
   * Exports the current database as a raw, **unencrypted** SQLite byte array.
   *
   * The returned bytes can be saved locally or used as input to
   * {@link LibreSQL.fromPlainBuffer}.  For persistent storage, prefer
   * {@link LibreSQL.encrypt} instead to keep data protected.
   *
   * @returns `Uint8Array` containing the SQLite database bytes.
   */
  export(): Uint8Array {
    return this._db.export();
  }

  /**
   * Encrypts the current database with AES-256-GCM and returns the
   * resulting encrypted LibreSQL blob.
   *
   * The blob can be sent to a server, stored in object storage, etc. —
   * without exposing any SQL data, because decryption requires the key/
   * password that only the end-user knows.
   *
   * @param options - Must contain either `password` or `key`.
   * @returns `Uint8Array` containing the encrypted LibreSQL blob.
   *
   * @example
   * ```ts
   * const encrypted = await db.encrypt({ password: 'hunter2' });
   * await fetch('/api/upload', { method: 'PUT', body: encrypted });
   * ```
   */
  async encrypt(options: EncryptOptions): Promise<Uint8Array> {
    const plaintext = this.export();
    return encryptData(plaintext, options);
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
