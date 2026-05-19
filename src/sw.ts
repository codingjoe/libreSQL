/**
 * Service Worker persistence helpers for LibreSQL.
 *
 * ## Durability pattern
 *
 * Because the in-memory SQLite database is lost when the browser tab is
 * closed or refreshed, a Service Worker can act as a short-lived persistence
 * layer: the page hands the **encrypted** blob to the SW before unloading,
 * and retrieves it when it reopens.
 *
 * The key is **never** sent to the SW — only the encrypted blob.  Decryption
 * still happens exclusively in the page context.
 *
 * ### Service Worker setup (`sw.js`)
 *
 * ```ts
 * import { ServiceWorkerStorage } from 'libresql/sw';
 *
 * const storage = new ServiceWorkerStorage();
 * self.addEventListener('message', (e) => storage.handleMessage(e));
 * ```
 *
 * ### Page setup
 *
 * ```ts
 * import { saveToServiceWorker, loadFromServiceWorker } from 'libresql/sw';
 * import { LibreSQL, KeyStore } from 'libresql';
 *
 * // On startup — restore last known state if available
 * const cached = await loadFromServiceWorker();
 * const db = cached
 *   ? await LibreSQL.fromBuffer(cached, { key: KeyStore.get('main')! })
 *   : await LibreSQL.fromURL('/api/db.lsql', { key: KeyStore.get('main')! });
 *
 * // Before unload — hand the encrypted blob to the SW
 * window.addEventListener('beforeunload', () => {
 *   void db.encrypt().then(saveToServiceWorker);
 * });
 * ```
 *
 * ## DB-in-Service-Worker pattern
 *
 * A more advanced pattern is to keep the database **inside** the Service
 * Worker so all tabs share a single copy with no round-trips:
 *
 * - The SW holds the `LibreSQL` instance and handles queries via `postMessage`
 * - Tabs send SQL read/write messages and receive results
 * - The SW calls `db.encrypt()` and stores the blob after every write
 *
 * This eliminates per-tab copies but adds messaging overhead.  It is best
 * suited to applications with many concurrent tabs and frequent background
 * syncs.  Implement with a `BroadcastChannel` or SW `fetch` interception for
 * a clean API boundary.
 *
 * @module
 */

/** Message type sent from the page to save the latest encrypted blob. */
export const LIBRESQL_SAVE = 'LIBRESQL_SAVE';
/** Message type sent from the page to request the cached blob. */
export const LIBRESQL_LOAD = 'LIBRESQL_LOAD';
/** Message type sent from the SW back to the page with the cached blob. */
export const LIBRESQL_BLOB = 'LIBRESQL_BLOB';

export interface LibreSQLSWMessage {
  type: typeof LIBRESQL_SAVE | typeof LIBRESQL_LOAD | typeof LIBRESQL_BLOB;
  payload?: ArrayBuffer | null;
}

// ---------------------------------------------------------------------------
// Service Worker side
// ---------------------------------------------------------------------------

/**
 * Holds the latest encrypted LibreSQL blob in Service Worker module scope.
 *
 * Instantiate once at the top level of your SW script and route `message`
 * events through {@link ServiceWorkerStorage#handleMessage}.
 *
 * @example
 * ```ts
 * // sw.js
 * import { ServiceWorkerStorage } from 'libresql/sw';
 *
 * const storage = new ServiceWorkerStorage();
 * self.addEventListener('message', (e) => storage.handleMessage(e));
 * ```
 */
export class ServiceWorkerStorage {
  private blob: ArrayBuffer | null = null;

  /**
   * Routes an incoming `message` event from a page or another worker.
   *
   * Handles `LIBRESQL_SAVE` (store blob) and `LIBRESQL_LOAD` (reply with blob).
   */
  handleMessage(event: ExtendableMessageEvent): void {
    const msg = event.data as LibreSQLSWMessage | undefined;
    if (!msg) return;

    if (msg.type === LIBRESQL_SAVE) {
      this.blob = msg.payload ?? null;
    } else if (msg.type === LIBRESQL_LOAD) {
      (event.source as WindowClient | null)?.postMessage({
        type: LIBRESQL_BLOB,
        payload: this.blob,
      } satisfies LibreSQLSWMessage);
    }
  }
}

// ---------------------------------------------------------------------------
// Page side
// ---------------------------------------------------------------------------

/**
 * Sends an encrypted blob to the Service Worker for safe-keeping.
 *
 * The transfer is zero-copy: the underlying `ArrayBuffer` is transferred
 * (not copied) to the SW.
 *
 * @param blob - Encrypted blob returned by `db.encrypt()`.
 */
export function saveToServiceWorker(blob: Uint8Array): void {
  const controller = navigator.serviceWorker?.controller;
  if (!controller) return;
  // Explicit ArrayBuffer copy to satisfy the MessagePort transfer constraint
  const buffer = new ArrayBuffer(blob.byteLength);
  new Uint8Array(buffer).set(blob);
  controller.postMessage(
    { type: LIBRESQL_SAVE, payload: buffer } satisfies LibreSQLSWMessage,
    [buffer],
  );
}

/**
 * Requests the last saved encrypted blob from the Service Worker.
 *
 * Returns `null` if the SW has no cached blob (e.g. on first load or after
 * the SW was restarted).
 *
 * @example
 * ```ts
 * const cached = await loadFromServiceWorker();
 * const db = cached
 *   ? await LibreSQL.fromBuffer(cached, { key })
 *   : await LibreSQL.fromURL('/api/db.lsql', { key });
 * ```
 */
export async function loadFromServiceWorker(): Promise<Uint8Array | null> {
  const controller = navigator.serviceWorker?.controller;
  if (!controller) return null;

  return new Promise<Uint8Array | null>((resolve) => {
    const handler = (event: MessageEvent<LibreSQLSWMessage>) => {
      if (event.data?.type === LIBRESQL_BLOB) {
        navigator.serviceWorker.removeEventListener('message', handler);
        resolve(event.data.payload ? new Uint8Array(event.data.payload) : null);
      }
    };
    navigator.serviceWorker.addEventListener('message', handler);
    controller.postMessage({ type: LIBRESQL_LOAD } satisfies LibreSQLSWMessage);
  });
}
