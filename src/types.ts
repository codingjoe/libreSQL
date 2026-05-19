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
 * Options for encrypting a LibreSQL database.
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
   * Defaults to 600_000 (OWASP recommended minimum for PBKDF2-SHA256).
   */
  iterations?: number;
}

/**
 * Options for creating a new, empty in-memory LibreSQL database.
 */
export interface CreateOptions {
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
 * Encrypted LibreSQL file format header (38 bytes).
 *
 * Layout:
 * ```
 * Offset  Size  Description
 * ------  ----  -----------
 *  0       4    Magic bytes: "LSQL"
 *  4       1    File format version (currently 0x01)
 *  5       1    KDF identifier: 0x00 = PBKDF2-SHA256
 *  6       4    PBKDF2 iteration count (big-endian uint32)
 * 10      32    PBKDF2 salt
 * 42      12    AES-GCM IV (nonce)
 * 54      …    AES-GCM ciphertext (includes 16-byte auth tag appended by WebCrypto)
 * ```
 */
export const HEADER_MAGIC = new Uint8Array([0x4c, 0x53, 0x51, 0x4c]); // "LSQL"
export const FILE_VERSION = 0x01;
export const KDF_PBKDF2_SHA256 = 0x00;
export const SALT_LENGTH = 32;
export const IV_LENGTH = 12;
export const HEADER_SIZE = 4 + 1 + 1 + 4 + SALT_LENGTH + IV_LENGTH; // 54 bytes
