/**
 * Tests for src/keystore.ts (KeyStore)
 */

import { afterEach, describe, expect, it } from 'vitest';
import { KeyStore } from './keystore.js';
import { generateKey } from './crypto.js';

afterEach(() => {
  KeyStore.clear();
});

describe('KeyStore', () => {
  it('stores and retrieves a CryptoKey by id', async () => {
    const key = await generateKey();
    KeyStore.set('main', key);
    expect(KeyStore.get('main')).toBe(key);
  });

  it('has() returns true when a key is present', async () => {
    const key = await generateKey();
    KeyStore.set('session', key);
    expect(KeyStore.has('session')).toBe(true);
  });

  it('has() returns false for an absent id', () => {
    expect(KeyStore.has('nonexistent')).toBe(false);
  });

  it('get() returns undefined for an absent id', () => {
    expect(KeyStore.get('nonexistent')).toBeUndefined();
  });

  it('delete() removes a key and returns true', async () => {
    const key = await generateKey();
    KeyStore.set('k', key);
    expect(KeyStore.delete('k')).toBe(true);
    expect(KeyStore.has('k')).toBe(false);
  });

  it('delete() returns false when key was not present', () => {
    expect(KeyStore.delete('ghost')).toBe(false);
  });

  it('clear() removes all keys', async () => {
    KeyStore.set('a', await generateKey());
    KeyStore.set('b', await generateKey());
    expect(KeyStore.size).toBe(2);
    KeyStore.clear();
    expect(KeyStore.size).toBe(0);
  });

  it('size reflects the current number of stored keys', async () => {
    expect(KeyStore.size).toBe(0);
    KeyStore.set('x', await generateKey());
    expect(KeyStore.size).toBe(1);
    KeyStore.set('y', await generateKey());
    expect(KeyStore.size).toBe(2);
    KeyStore.delete('x');
    expect(KeyStore.size).toBe(1);
  });

  it('does not bleed state between independent ids', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    KeyStore.set('id1', key1);
    KeyStore.set('id2', key2);
    expect(KeyStore.get('id1')).toBe(key1);
    expect(KeyStore.get('id2')).toBe(key2);
  });
});
