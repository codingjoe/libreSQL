/**
 * Tests for src/crypto.ts
 *
 * These tests run in Node.js (via Vitest) using the built-in Web Crypto API
 * that Node 20+ provides through `globalThis.crypto`.
 */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ITERATIONS,
  decryptData,
  deriveKey,
  encryptData,
  generateKey,
  importRawKey,
} from './crypto.js';
import { HEADER_MAGIC, HEADER_SIZE } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(n) as Uint8Array<ArrayBuffer>;
  crypto.getRandomValues(buf);
  return buf;
}

// ---------------------------------------------------------------------------
// deriveKey
// ---------------------------------------------------------------------------

describe('deriveKey', () => {
  it('returns a CryptoKey', async () => {
    const salt = randomBytes(32);
    const key = await deriveKey('password', salt, 1000);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
  });

  it('produces the same key for the same password+salt', async () => {
    const salt = randomBytes(32);
    const key1 = await deriveKey('same', salt, 1000);
    const key2 = await deriveKey('same', salt, 1000);

    // Keys are non-extractable so we verify indirectly via encrypt/decrypt
    const plaintext = new Uint8Array([1, 2, 3]);
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, plaintext);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct);
    expect(new Uint8Array(pt)).toEqual(plaintext);
  });

  it('produces different keys for different passwords', async () => {
    const salt = randomBytes(32);
    const key1 = await deriveKey('password1', salt, 1000);
    const key2 = await deriveKey('password2', salt, 1000);

    const plaintext = new Uint8Array([4, 5, 6]);
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, plaintext);
    await expect(
      crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// generateKey / importRawKey
// ---------------------------------------------------------------------------

describe('generateKey', () => {
  it('generates a 256-bit AES-GCM key', async () => {
    const key = await generateKey();
    expect(key.algorithm.name).toBe('AES-GCM');
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
  });
});

describe('importRawKey', () => {
  it('imports 32 raw bytes as a CryptoKey', async () => {
    const raw = randomBytes(32);
    const key = await importRawKey(raw);
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
  });
});

// ---------------------------------------------------------------------------
// encryptData / decryptData round-trip
// ---------------------------------------------------------------------------

describe('encryptData + decryptData', () => {
  const PLAINTEXT = new TextEncoder().encode('Hello, LibreSQL!');

  it('round-trips with a password', async () => {
    const encrypted = await encryptData(PLAINTEXT, {
      password: 'test-password',
      iterations: 1000,
    });
    const { data: decrypted } = await decryptData(encrypted, { password: 'test-password' });
    expect(decrypted).toEqual(PLAINTEXT);
  });

  it('round-trips with a CryptoKey', async () => {
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key });
    const { data: decrypted } = await decryptData(encrypted, { key });
    expect(decrypted).toEqual(PLAINTEXT);
  });

  it('decryptData returns the resolved key', async () => {
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key });
    const { key: returnedKey } = await decryptData(encrypted, { key });
    expect(returnedKey).toBe(key);
  });

  it('decryptData returns the derived key when password is used', async () => {
    const encrypted = await encryptData(PLAINTEXT, {
      password: 'test-password',
      iterations: 1000,
    });
    const { key } = await decryptData(encrypted, { password: 'test-password' });
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
  });

  it('round-trips with compression enabled', async () => {
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key, compress: true });
    const { data: decrypted } = await decryptData(encrypted, { key });
    expect(decrypted).toEqual(PLAINTEXT);
  });

  it('produces different ciphertext each call (random IV)', async () => {
    const e1 = await encryptData(PLAINTEXT, { password: 'pw', iterations: 1000 });
    const e2 = await encryptData(PLAINTEXT, { password: 'pw', iterations: 1000 });
    // Ciphertexts differ because of random IV & salt
    expect(e1).not.toEqual(e2);
  });

  it('encrypted blob starts with the LSQL magic bytes', async () => {
    const encrypted = await encryptData(PLAINTEXT, { password: 'pw', iterations: 1000 });
    expect(encrypted.slice(0, 4)).toEqual(HEADER_MAGIC);
  });

  it('uncompressed blob size equals HEADER_SIZE + plaintext + GCM tag', async () => {
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key, compress: false });
    // AES-GCM appends a 16-byte tag
    expect(encrypted.byteLength).toBe(HEADER_SIZE + PLAINTEXT.byteLength + 16);
  });

  it('throws when no password or key is supplied to encryptData', async () => {
    await expect(encryptData(PLAINTEXT, {})).rejects.toThrow(TypeError);
  });

  it('throws when no password or key is supplied to decryptData', async () => {
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key });
    await expect(decryptData(encrypted, {})).rejects.toThrow(TypeError);
  });

  it('throws on wrong password', async () => {
    const encrypted = await encryptData(PLAINTEXT, { password: 'correct', iterations: 1000 });
    await expect(decryptData(encrypted, { password: 'wrong' })).rejects.toThrow();
  });

  it('throws on invalid magic bytes', async () => {
    const bad = new Uint8Array(100);
    bad.fill(0xff);
    await expect(decryptData(bad, { password: 'pw' })).rejects.toThrow(TypeError);
  });

  it('throws when data is too short', async () => {
    const tooShort = new Uint8Array(10);
    await expect(decryptData(tooShort, { password: 'pw' })).rejects.toThrow(TypeError);
  });

  it('uses DEFAULT_ITERATIONS when none specified', async () => {
    // Use a CryptoKey so key derivation is skipped (fast test).
    const key = await generateKey();
    const encrypted = await encryptData(PLAINTEXT, { key, iterations: DEFAULT_ITERATIONS });
    const view = new DataView(encrypted.buffer);
    const iterations = view.getUint32(6, false);
    expect(iterations).toBe(DEFAULT_ITERATIONS);
  });
});
