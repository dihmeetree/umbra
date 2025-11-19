import { describe, it, expect } from 'vitest';
import {
  randomBytes,
  toHex,
  fromHex,
  pad,
  createCoinPublicKey,
  generateNonce,
  generateSecretKey,
} from '../utils';

describe('Utils', () => {
  describe('randomBytes', () => {
    it('should generate bytes of correct length', () => {
      const bytes = randomBytes(32);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(32);
    });

    it('should generate different bytes on each call', () => {
      const bytes1 = randomBytes(32);
      const bytes2 = randomBytes(32);
      expect(bytes1).not.toEqual(bytes2);
    });
  });

  describe('toHex', () => {
    it('should convert bytes to hex string', () => {
      const bytes = new Uint8Array([0, 15, 255]);
      const hex = toHex(bytes);
      expect(hex).toBe('000fff');
    });

    it('should handle empty array', () => {
      const bytes = new Uint8Array([]);
      const hex = toHex(bytes);
      expect(hex).toBe('');
    });
  });

  describe('fromHex', () => {
    it('should convert hex string to bytes', () => {
      const hex = '000fff';
      const bytes = fromHex(hex);
      expect(bytes).toEqual(new Uint8Array([0, 15, 255]));
    });

    it('should handle 0x prefix', () => {
      const hex = '0x000fff';
      const bytes = fromHex(hex);
      expect(bytes).toEqual(new Uint8Array([0, 15, 255]));
    });

    it('should round trip with toHex', () => {
      const original = randomBytes(32);
      const hex = toHex(original);
      const restored = fromHex(hex);
      expect(restored).toEqual(original);
    });
  });

  describe('pad', () => {
    it('should pad string to correct length', () => {
      const padded = pad('test', 10);
      expect(padded.length).toBe(10);
      expect(padded[0]).toBe('t'.charCodeAt(0));
      expect(padded[1]).toBe('e'.charCodeAt(0));
      expect(padded[2]).toBe('s'.charCodeAt(0));
      expect(padded[3]).toBe('t'.charCodeAt(0));
      expect(padded[4]).toBe(0);
    });

    it('should truncate if string is longer', () => {
      const padded = pad('toolongstring', 5);
      expect(padded.length).toBe(5);
    });
  });

  describe('createCoinPublicKey', () => {
    it('should create zero-filled key if no input', () => {
      const key = createCoinPublicKey();
      expect(key).toBe('0'.repeat(64));
    });

    it('should pad short hex strings', () => {
      const key = createCoinPublicKey('abc');
      expect(key.length).toBe(64);
      expect(key.endsWith('abc')).toBe(true);
    });
  });

  describe('generateNonce', () => {
    it('should generate 32 bytes', () => {
      const nonce = generateNonce();
      expect(nonce.length).toBe(32);
    });

    it('should generate different nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toEqual(nonce2);
    });
  });

  describe('generateSecretKey', () => {
    it('should generate 32 bytes', () => {
      const key = generateSecretKey();
      expect(key.length).toBe(32);
    });

    it('should generate different keys', () => {
      const key1 = generateSecretKey();
      const key2 = generateSecretKey();
      expect(key1).not.toEqual(key2);
    });
  });
});
