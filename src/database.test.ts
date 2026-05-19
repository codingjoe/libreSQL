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
import { beforeAll, describe, expect, it } from 'vitest';
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

beforeAll(() => {
  wasmBinary = fs.readFileSync(WASM_PATH).buffer;
});

function createOptions() {
  return { wasmBinary };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Creates an empty LibreSQL database with a simple `files` table and a few
 * rows, using the provided wasmBinary.
 */
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
// LibreSQL.export
// ---------------------------------------------------------------------------

describe('LibreSQL.export', () => {
  it('exports a non-empty Uint8Array', async () => {
    const db = await seedDatabase();
    const bytes = db.export();
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.byteLength).toBeGreaterThan(0);
    db.close();
  });

  it('exported bytes begin with the SQLite magic header', async () => {
    const db = await seedDatabase();
    const bytes = db.export();
    // SQLite files start with "SQLite format 3\0"
    const magic = new TextDecoder().decode(bytes.slice(0, 15));
    expect(magic).toBe('SQLite format 3');
    db.close();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.encrypt / LibreSQL.fromBuffer round-trip
// ---------------------------------------------------------------------------

describe('encrypt + fromBuffer round-trip', () => {
  it('round-trips with a password', async () => {
    const db = await seedDatabase();
    const encrypted = await db.encrypt({ password: 'hunter2', iterations: 1000 });
    db.close();

    const db2 = await LibreSQL.fromBuffer(encrypted, { password: 'hunter2' });
    const [result] = db2.exec('SELECT COUNT(*) FROM files');
    expect(result.values[0][0]).toBe(3);
    db2.close();
  });

  it('round-trips with a CryptoKey', async () => {
    const db = await seedDatabase();
    const key = await generateKey();
    const encrypted = await db.encrypt({ key });
    db.close();

    const db2 = await LibreSQL.fromBuffer(encrypted, { key });
    const [result] = db2.exec('SELECT name FROM files WHERE id = 1');
    expect(result.values[0][0]).toBe('report.pdf');
    db2.close();
  });

  it('fails to decrypt with the wrong password', async () => {
    const db = await seedDatabase();
    const encrypted = await db.encrypt({ password: 'correct', iterations: 1000 });
    db.close();

    await expect(
      LibreSQL.fromBuffer(encrypted, { password: 'wrong' }),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// LibreSQL.fromPlainBuffer
// ---------------------------------------------------------------------------

describe('LibreSQL.fromPlainBuffer', () => {
  it('opens an existing raw SQLite database', async () => {
    // First, create and export
    const db = await seedDatabase();
    const raw = db.export();
    db.close();

    // Re-open from raw bytes
    const db2 = await LibreSQL.fromPlainBuffer(raw, createOptions());
    const [result] = db2.exec('SELECT COUNT(*) FROM files');
    expect(result.values[0][0]).toBe(3);
    db2.close();
  });
});

// ---------------------------------------------------------------------------
// Full end-to-end: create → encrypt → fromBuffer → query
// ---------------------------------------------------------------------------

describe('end-to-end E2EE workflow', () => {
  it('allows searching file metadata without the data leaving the browser', async () => {
    // 1. Application creates a local database
    const db = await LibreSQL.create(createOptions());
    db.run('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT NOT NULL, mime TEXT)');
    db.run("INSERT INTO files VALUES (1, 'budget.xlsx', 'application/vnd.ms-excel')");
    db.run("INSERT INTO files VALUES (2, 'holiday.jpg', 'image/jpeg')");
    db.run("INSERT INTO files VALUES (3, 'README.md',   'text/markdown')");

    // 2. Encrypt before persisting / uploading
    const encrypted = await db.encrypt({ password: 's3cr3t', iterations: 1000 });
    db.close();

    // 3. Simulate loading from storage (encrypted blob)
    const db2 = await LibreSQL.fromBuffer(encrypted, { password: 's3cr3t' });

    // 4. Full-text-style search on file names
    const [result] = db2.exec(
      "SELECT name, mime FROM files WHERE name LIKE '%budget%'",
    );
    expect(result.values).toHaveLength(1);
    expect(result.values[0][0]).toBe('budget.xlsx');

    db2.close();
  });
});
