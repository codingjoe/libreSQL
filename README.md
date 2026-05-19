# libreSQL

**Browser-based E2EE SQLite database for end-to-end encrypted SaaS applications.**

libreSQL lets you load, query, and persist AES-256-GCM encrypted SQLite databases entirely inside the browser. The plaintext SQL data **never leaves the browser context** — only the encrypted blob is transmitted or stored, so your backend never sees the raw data.

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────┐
│  Browser (trusted)                                                    │
│                                                                       │
│   Password ──► PBKDF2-SHA256 ──► AES-256-GCM key                    │
│                                       │                              │
│   fetch("https://…/store.lsql")       │  decrypt in memory           │
│       │ encrypted blob ◄──────────────┘                              │
│       └──────────────────────────────► sql.js (WASM) ──► SQL queries │
└──────────────────────────────────────────────────────────────────────┘
         ▲ only ciphertext crosses the network boundary
```

### Encrypted file format

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 B | Magic bytes `LSQL` |
| 4 | 1 B | File format version (`0x01`) |
| 5 | 1 B | KDF identifier (`0x00` = PBKDF2-SHA256) |
| 6 | 4 B | PBKDF2 iteration count (big-endian uint32) |
| 10 | 32 B | PBKDF2 salt (random, unique per encryption) |
| 42 | 12 B | AES-GCM nonce / IV (random, unique per encryption) |
| 54 | … | AES-GCM ciphertext (SQLite bytes + 16-byte auth tag) |

---

## Installation

```bash
npm install libresql sql.js
```

> `sql.js` is a **peer dependency** — you must install it alongside libreSQL.

---

## Quick start

### Load an encrypted database from a URL

```ts
import { LibreSQL } from 'libresql';

const db = await LibreSQL.fromURL('https://cdn.example.com/files.lsql', {
  password: 'correct horse battery staple',
});

// Full-text-style search on file metadata — entirely in the browser
const [result] = db.exec(
  "SELECT id, name FROM files WHERE name LIKE ? ORDER BY name",
  ['%.pdf'],
);

for (const [id, name] of result.values) {
  console.log(id, name);
}

db.close(); // frees WASM memory
```

### Load from a `<input type="file">` picker

```ts
input.addEventListener('change', async () => {
  const [file] = input.files;
  const db = await LibreSQL.fromFile(file, { password: userPassword });
  // query as normal …
  db.close();
});
```

### Create a database and encrypt it for upload

```ts
import { LibreSQL } from 'libresql';

const db = await LibreSQL.create();
db.run('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, size INTEGER)');
db.run('INSERT INTO files VALUES (?, ?, ?)', [1, 'report.pdf', 4096]);

// Encrypt and upload — the server only ever receives ciphertext
const encrypted = await db.encrypt({ password: 'hunter2' });
await fetch('/api/db', { method: 'PUT', body: encrypted });

db.close();
```

### Using a `CryptoKey` directly (advanced)

```ts
import { LibreSQL, generateKey } from 'libresql';

// Generate once and store securely (e.g. via the Web Crypto key store)
const key = await generateKey();

const encrypted = await db.encrypt({ key });
const db2 = await LibreSQL.fromBuffer(encrypted, { key });
```

---

## API reference

### `LibreSQL` class

#### Factory methods (open encrypted)

| Method | Description |
|--------|-------------|
| `LibreSQL.fromURL(url, options, init?)` | Fetch an encrypted blob from a URL and open it. |
| `LibreSQL.fromFile(file, options)` | Open an encrypted `File` (e.g. from `<input type="file">`). |
| `LibreSQL.fromBuffer(buffer, options)` | Open an encrypted `ArrayBuffer` or `Uint8Array`. |

All `options` accept either `{ password: string }` or `{ key: CryptoKey }`.

#### Factory methods (plaintext / bootstrapping)

| Method | Description |
|--------|-------------|
| `LibreSQL.create(options?)` | Create a new, empty in-memory SQLite database. |
| `LibreSQL.fromPlainBuffer(buffer, options?)` | Open a raw (unencrypted) SQLite file. |

#### Instance methods

| Method | Description |
|--------|-------------|
| `db.exec(sql, params?)` | Execute SQL, returns `QueryResult[]`. |
| `db.run(sql, params?)` | Execute a data-modification statement (returns `this` for chaining). |
| `db.export()` | Export as raw (unencrypted) SQLite `Uint8Array`. |
| `db.encrypt(options)` | Export as an encrypted LibreSQL `Uint8Array`. |
| `db.close()` | Close the database and free WASM memory. |

### Crypto helpers

```ts
import {
  deriveKey,    // PBKDF2-SHA256 key derivation
  generateKey,  // random AES-256-GCM key
  importRawKey, // import 32 raw bytes as a CryptoKey
  encryptData,  // encrypt arbitrary bytes → LibreSQL blob
  decryptData,  // decrypt a LibreSQL blob → plaintext bytes
} from 'libresql';
```

---

## Security design

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM — IND-CCA2 secure |
| Integrity / authenticity | AES-GCM 128-bit authentication tag (tamper detection) |
| Key derivation | PBKDF2-SHA256, 600 000 iterations (OWASP 2023 minimum) |
| Random values | `crypto.getRandomValues` — cryptographically secure |
| Key isolation | All crypto via Web Crypto API — keys are non-extractable |
| Data residency | SQLite bytes exist only in WASM memory; never serialised to the network |

The design is inspired by the approaches used by [Proton](https://proton.me/security) and [Ente](https://ente.io/blog/e2ee/): encrypt data client-side before it leaves the device, with keys derived from user-owned secrets.

---

## Browser compatibility

libreSQL requires:
- **Web Crypto API** (`crypto.subtle`) — all modern browsers + Node.js 20+
- **WebAssembly** (for sql.js) — all modern browsers

---

## License

BSD 2-Clause © Johannes Maron
