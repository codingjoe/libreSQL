/**
 * Options for opening an encrypted LibreSQL database.
 */
export interface OpenOptions {
  /**
   * A password used to derive the decryption key via PBKDF2-SHA256.
   * Either `password` or `key` must be provided.
   */
  password?: string;

  /**
   * A pre-derived CryptoKey (AES-GCM, 256-bit) used to decrypt the database.
   * Either `password` or `key` must be provided.
   */
  key?: CryptoKey;
}

/**
 * Low-level options for the {@link encryptData} / {@link decryptData} primitives.
 * Application code should use `LibreSQL.encrypt()` instead.
 */
export interface EncryptOptions {
  /**
   * A password used to derive the encryption key via PBKDF2-SHA256.
   * Either `password` or `key` must be provided.
   */
  password?: string;

  /**
   * A pre-derived CryptoKey (AES-GCM, 256-bit) used to encrypt the database.
   * Either `password` or `key` must be provided.
   */
  key?: CryptoKey;

  /**
   * Number of PBKDF2 iterations. Higher values are more secure but slower.
   * Defaults to 600_000 (≥ 2× the 2025 OWASP minimum of 310 000).
   */
  iterations?: number;

  /**
   * Compress the data with DEFLATE before encrypting.
   * Defaults to `false` in the raw primitive; set to `true` via `db.encrypt()`.
   */
  compress?: boolean;
}

/**
 * Options for `LibreSQL.encrypt()` on a database instance.
 */
export interface DatabaseEncryptOptions {
  /**
   * Run `VACUUM` before exporting to compact the database.
   * Defaults to `true`.
   */
  vacuum?: boolean;

  /**
   * Compress the SQLite bytes with DEFLATE before encrypting.
   * Defaults to `true`.
   */
  compress?: boolean;
}

/**
 * WASM loader options shared by factory methods that create a new database.
 */
export interface WasmOptions {
  /**
   * Optional path to a custom sql.js WASM binary.
   * Useful for bundlers that serve the WASM file from a custom URL.
   */
  wasmBinaryPath?: string;

  /**
   * Optional raw WASM binary as a BufferSource.
   * When provided, `wasmBinaryPath` is ignored.
   */
  wasmBinary?: BufferSource;
}

/**
 * Options for creating a new, empty in-memory LibreSQL database, or for
 * opening an existing unencrypted SQLite file via `fromPlainBuffer`.
 */
export interface CreateOptions extends WasmOptions {
  /**
   * The AES-256-GCM key that will be stored in the database instance.
   * All future `encrypt()` calls use this key automatically.
   */
  key: CryptoKey;
}

/**
 * Result row from `LibreSQL.exec()`.
 */
export interface QueryResult {
  /** Column names in result order. */
  columns: string[];
  /** Array of value arrays, one per result row. */
  values: SqlValue[][];
}

/**
 * Scalar SQL value types supported by sql.js.
 */
export type SqlValue = number | string | Uint8Array | null;

/**
 * Bind parameters accepted by `LibreSQL.exec()`.
 */
export type BindParams =
  | SqlValue[]
  | Record<string, SqlValue>;

/**
 * Encrypted LibreSQL file format header (55 bytes).
 *
 * Layout:
 * ```
 * Offset  Size  Description
 * ------  ----  -----------
 *  0       4    Magic bytes: "LSQL"
 *  4       1    File format version (currently 0x01)
 *  5       1    KDF identifier: 0x00 = PBKDF2-SHA256
 *  6       4    PBKDF2 iteration count (big-endian uint32)
 * 10       1    Flags (bit 0 = FLAG_COMPRESSED)
 * 11      32    PBKDF2 salt
 * 43      12    AES-GCM IV (nonce)
 * 55      …     AES-GCM ciphertext (includes 16-byte auth tag appended by WebCrypto)
 * ```
 */
export const HEADER_MAGIC = new Uint8Array([0x4c, 0x53, 0x51, 0x4c]); // "LSQL"
export const FILE_VERSION = 0x01;
export const KDF_PBKDF2_SHA256 = 0x00;
export const SALT_LENGTH = 32;
export const IV_LENGTH = 12;
/** No flags set. */
export const FLAGS_NONE = 0x00;
/** Bit 0: payload was compressed with DEFLATE-raw before encryption. */
export const FLAG_COMPRESSED = 0x01;
export const HEADER_SIZE = 4 + 1 + 1 + 4 + 1 + SALT_LENGTH + IV_LENGTH; // 55 bytes
