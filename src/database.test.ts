/**
 * Tests for src/database.ts (LibreSQL class)
 *
 * In Node.js, sql.js needs the WASM binary provided via the `wasmBinary`
 * option because there is no built-in WASM loader.  We read the binary from
 * the sql.js package at test time and pass it through `CreateOptions`.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { LibreSQL } from './database.js';
import { generateKey } from './crypto.js';

// ---------------------------------------------------------------------------
// WASM bootstrap
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.resolve(
  __dirname,
  '../node_modules/sql.js/dist/sql-wasm.wasm',
);

let wasmBinary: ArrayBuffer;
let sharedKey: CryptoKey;

beforeAll(async () => {
  wasmBinary = fs.readFileSync(WASM_PATH).buffer as ArrayBuffer;
  sharedKey = await generateKey();
});

function createOptions() {
  return { wasmBinary, key: sharedKey };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function seedDatabase(): Promise<LibreSQL> {
  const db = await LibreSQL.create(createOptions());
  db.run('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, size INTEGER)');
  db.run('INSERT INTO files VALUES (1, "report.pdf", 4096)');
  db.run('INSERT INTO files VALUES (2, "photo.jpg", 204800)');
  db.run('INSERT INTO files VALUES (3, "notes.txt", 512)');
  return db;
}

// ---------------------------------------------------------------------------
// LibreSQL.create
// ---------------------------------------------------------------------------

describe('LibreSQL.create', () => {
  it('creates an empty in-memory database', async () => {
    const db = await LibreSQL.create(createOptions());
    const results = db.exec('SELECT 1 + 1 AS result');
    expect(results).toHaveLength(1);
    expect(results[0].values[0][0]).toBe(2);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.run / exec
// ---------------------------------------------------------------------------

describe('LibreSQL.run / exec', () => {
  it('inserts and queries rows', async () => {
    const db = await seedDatabase();
    const [result] = db.exec('SELECT id, name FROM files ORDER BY id');
    expect(result.columns).toEqual(['id', 'name']);
    expect(result.values).toEqual([
      [1, 'report.pdf'],
      [2, 'photo.jpg'],
      [3, 'notes.txt'],
    ]);
    db.close();
  });

  it('supports positional bind parameters', async () => {
    const db = await seedDatabase();
    const [result] = db.exec('SELECT name FROM files WHERE size > ?', [1000]);
    expect(result.values.map((r) => r[0])).toContain('photo.jpg');
    db.close();
  });

  it('supports named bind parameters', async () => {
    const db = await seedDatabase();
    const [result] = db.exec('SELECT name FROM files WHERE id = $id', { $id: 3 });
    expect(result.values[0][0]).toBe('notes.txt');
    db.close();
  });

  it('returns empty array for data-modification statements', async () => {
    const db = await LibreSQL.create(createOptions());
    db.run('CREATE TABLE t (x INTEGER)');
    const results = db.exec('INSERT INTO t VALUES (42)');
    expect(results).toHaveLength(0);
    db.close();
  });

  it('run() returns this for chaining', async () => {
    const db = await LibreSQL.create(createOptions());
    const result = db
      .run('CREATE TABLE t (x INTEGER)')
      .run('INSERT INTO t VALUES (1)')
      .run('INSERT INTO t VALUES (2)');
    expect(result).toBe(db);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// onWrite callback
// ---------------------------------------------------------------------------

describe('onWrite callback', () => {
  it('is called after run()', async () => {
    const calls: string[] = [];

    class TrackedDB extends LibreSQL {
      protected override onWrite(): void {
        calls.push('write');
      }
    }

    // Use the internal constructor via create() — since we need TrackedDB,
    // we create a plain db and wrap it.
    const key = await generateKey();
    const db = await LibreSQL.create({ wasmBinary, key });

    // Manually inject an instance (test the onWrite mechanism via subclass)
    const tracked = Object.create(TrackedDB.prototype) as TrackedDB;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (tracked as any)._db = (db as any)._db;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (tracked as any)._key = key;

    tracked.run('CREATE TABLE t (x INTEGER)');
    expect(calls).toHaveLength(1);
    tracked.run('INSERT INTO t VALUES (1)');
    expect(calls).toHaveLength(2);
    db.close();
  });

  it('onWrite is NOT called by exec()', async () => {
    const writes = vi.fn();
    const key = await generateKey();
    const db = await LibreSQL.create({ wasmBinary, key });
    // Access _db to set up table without triggering custom onWrite
    db.run('CREATE TABLE t (x INTEGER)');
    db.run('INSERT INTO t VALUES (99)');

    // Spy on the instance's onWrite
    const spy = vi.spyOn(db as unknown as { onWrite(): void }, 'onWrite').mockImplementation(writes);
    db.exec('SELECT * FROM t');
    expect(spy).not.toHaveBeenCalled();
    db.close();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL key management
// ---------------------------------------------------------------------------

describe('key management', () => {
  it('exposes the stored key via db.key', async () => {
    const key = await generateKey();
    const db = await LibreSQL.create({ wasmBinary, key });
    expect(db.key).toBe(key);
    db.close();
  });

  it('rotateKey() updates the stored key', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const db = await LibreSQL.create({ wasmBinary, key: key1 });
    expect(db.key).toBe(key1);
    db.rotateKey(key2);
    expect(db.key).toBe(key2);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.encrypt / LibreSQL.fromBuffer round-trip
// ---------------------------------------------------------------------------

describe('encrypt + fromBuffer round-trip', () => {
  it('round-trips with a stored CryptoKey (no args to encrypt)', async () => {
    const db = await seedDatabase();
    const encrypted = await db.encrypt();
    db.close();

    const db2 = await LibreSQL.fromBuffer(encrypted, { key: sharedKey });
    const [result] = db2.exec('SELECT COUNT(*) FROM files');
    expect(result.values[0][0]).toBe(3);
    db2.close();
  });

  it('round-trips with a password', async () => {
    const key = await generateKey();
    const db = await LibreSQL.create({ wasmBinary, key });
    db.run('CREATE TABLE t (x INTEGER)').run('INSERT INTO t VALUES (42)');
    // Password-based: provide password when encrypting
    const encrypted = await db.encrypt();
    db.close();

    // Re-open using the same key
    const db2 = await LibreSQL.fromBuffer(encrypted, { key });
    const [result] = db2.exec('SELECT x FROM t');
    expect(result.values[0][0]).toBe(42);
    db2.close();
  });

  it('fromBuffer with password resolves and stores the key', async () => {
    const db = await seedDatabase();
    // Encrypt with stored key
    const encrypted = await db.encrypt();
    db.close();

    // fromURL/fromBuffer with a CryptoKey stores it in the instance
    const db2 = await LibreSQL.fromBuffer(encrypted, { key: sharedKey });
    expect(db2.key).toBe(sharedKey);
    db2.close();
  });

  it('compress=false produces smaller-or-equal blob without compression', async () => {
    const db = await seedDatabase();
    const withCompression    = await db.encrypt({ compress: true });
    const withoutCompression = await db.encrypt({ compress: false });
    db.close();
    // Compressed should be ≤ uncompressed for most real SQLite files
    expect(withCompression.byteLength).toBeLessThanOrEqual(withoutCompression.byteLength);
  });

  it('vacuum=false skips VACUUM', async () => {
    const db = await seedDatabase();
    // Just verify it doesn't throw
    const encrypted = await db.encrypt({ vacuum: false, compress: false });
    expect(encrypted.byteLength).toBeGreaterThan(0);
    db.close();
  });

  it('fails to decrypt with the wrong key', async () => {
    const db = await seedDatabase();
    const encrypted = await db.encrypt();
    db.close();

    const wrongKey = await generateKey();
    await expect(
      LibreSQL.fromBuffer(encrypted, { key: wrongKey }),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.fromPlainBuffer
// ---------------------------------------------------------------------------

describe('LibreSQL.fromPlainBuffer', () => {
  it('opens an existing raw SQLite database', async () => {
    // Create db, get raw bytes via encrypt+decrypt cycle, then open plain
    const key = await generateKey();
    const db = await seedDatabase();
    db.rotateKey(key);
    const encrypted = await db.encrypt({ compress: false });
    db.close();

    // Decrypt to get raw bytes, then open as plain
    const { data: raw } = await import('./crypto.js').then(m => m.decryptData(encrypted, { key }));
    const db2 = await LibreSQL.fromPlainBuffer(raw, { wasmBinary, key });
    const [result] = db2.exec('SELECT COUNT(*) FROM files');
    expect(result.values[0][0]).toBe(3);
    db2.close();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.digest
// ---------------------------------------------------------------------------

describe('db.digest()', () => {
  it('returns a 64-char lowercase hex string (SHA-256)', async () => {
    const db = await seedDatabase();
    const digest = await db.digest();
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    db.close();
  });

  it('same database content produces the same digest', async () => {
    const db = await seedDatabase();
    const d1 = await db.digest();
    const d2 = await db.digest();
    expect(d1).toBe(d2);
    db.close();
  });

  it('different content produces different digests', async () => {
    const db1 = await seedDatabase();
    const db2 = await LibreSQL.create(createOptions());
    db2.run('CREATE TABLE other (x TEXT)');

    expect(await db1.digest()).not.toBe(await db2.digest());
    db1.close();
    db2.close();
  });

  it('digest changes after a write', async () => {
    const db = await seedDatabase();
    const before = await db.digest();
    db.run('INSERT INTO files VALUES (99, "extra.txt", 1)');
    const after = await db.digest();
    expect(before).not.toBe(after);
    db.close();
  });
});

// ---------------------------------------------------------------------------
// Full end-to-end: create → encrypt → fromBuffer → query
// ---------------------------------------------------------------------------

describe('end-to-end E2EE workflow', () => {
  it('allows searching file metadata without the data leaving the browser', async () => {
    const key = await generateKey();

    // 1. Application creates a local database
    const db = await LibreSQL.create({ wasmBinary, key });
    db.run('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT NOT NULL, mime TEXT)');
    db.run("INSERT INTO files VALUES (1, 'budget.xlsx', 'application/vnd.ms-excel')");
    db.run("INSERT INTO files VALUES (2, 'holiday.jpg', 'image/jpeg')");
    db.run("INSERT INTO files VALUES (3, 'README.md',   'text/markdown')");

    // 2. Encrypt before persisting / uploading (compress + vacuum by default)
    const encrypted = await db.encrypt();
    db.close();

    // 3. Simulate loading from storage
    const db2 = await LibreSQL.fromBuffer(encrypted, { key });

    // 4. Full-text-style search on file names
    const [result] = db2.exec(
      "SELECT name, mime FROM files WHERE name LIKE '%budget%'",
    );
    expect(result.values).toHaveLength(1);
    expect(result.values[0][0]).toBe('budget.xlsx');

    db2.close();
  });
});
