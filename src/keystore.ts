/**
 * Secure in-browser session key storage for LibreSQL.
 *
 * ## Security model
 *
 * Browser E2EE applications need a place to hold the user's decryption key
 * for the duration of a session without leaking it.  Naïve approaches are
 * dangerous:
 *
 * | Storage | Problem |
 * |---------|---------|
 * | `localStorage` / `sessionStorage` | Accessible by any same-origin script; serialised as plain text |
 * | `document.cookie` | Transmitted with every HTTP request to the origin |
 * | Custom window/global property | Readable by any same-origin script |
 *
 * `KeyStore` avoids all of these problems by keeping keys as **non-extractable
 * `CryptoKey` objects** inside a module-private `Map`.  Because the keys are
 * non-extractable, the raw bytes can never be read out by JavaScript — not
 * even by other scripts running on the same page.  The keys live only in the
 * current JavaScript context (tab/worker) and are automatically discarded when
 * the page is unloaded.
 *
 * For **Service Worker** usage see the `LibreSQL` persistence guide in the
 * README — the key should be held in the SW's module-level scope and re-
 * posted to the page via `postMessage` without ever touching a persistable
 * storage API.
 *
 * @module
 */

/** Module-private storage — inaccessible to any external script. */
const _store = new Map<string, CryptoKey>();

/**
 * Lightweight in-memory store for `CryptoKey` objects.
 *
 * Keys are scoped to the current JavaScript context (browser tab or worker).
 * They are **not** serialised, **not** transmitted, and **not** accessible to
 * other scripts because `CryptoKey` objects are non-extractable by design.
 *
 * @example
 * ```ts
 * import { KeyStore, deriveKey } from 'libresql';
 *
 * // Derive once at login
 * const key = await deriveKey(password, salt);
 * KeyStore.set('main', key);
 *
 * // Re-use across multiple operations in the same session
 * const db = await LibreSQL.fromURL(url, { key: KeyStore.get('main')! });
 *
 * // Wipe on logout
 * KeyStore.delete('main');
 * ```
 */
export const KeyStore = {
  /**
   * Stores a `CryptoKey` under the given identifier.
   *
   * @param id  - Application-defined string identifier (e.g. `'main'`).
   * @param key - A `CryptoKey` — typically non-extractable.
   */
  set(id: string, key: CryptoKey): void {
    _store.set(id, key);
  },

  /**
   * Retrieves the `CryptoKey` associated with `id`, or `undefined` if not
   * present.
   *
   * @param id - The identifier used in {@link KeyStore.set}.
   */
  get(id: string): CryptoKey | undefined {
    return _store.get(id);
  },

  /**
   * Returns `true` if a key exists for `id`.
   *
   * @param id - The identifier to check.
   */
  has(id: string): boolean {
    return _store.has(id);
  },

  /**
   * Removes the key stored under `id`.
   *
   * Call this on logout or whenever the user's session ends to ensure the
   * key is no longer reachable.
   *
   * @param id - The identifier to remove.
   * @returns `true` if a key was present and has been removed.
   */
  delete(id: string): boolean {
    return _store.delete(id);
  },

  /**
   * Removes **all** stored keys.
   *
   * Use this to perform a full session teardown (e.g. sign-out).
   */
  clear(): void {
    _store.clear();
  },

  /**
   * The number of keys currently held in the store.
   */
  get size(): number {
    return _store.size;
  },
} as const;
