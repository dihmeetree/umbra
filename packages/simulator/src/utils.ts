import { randomBytes as cryptoRandomBytes } from 'crypto';

/**
 * Generates cryptographically secure random bytes
 */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(cryptoRandomBytes(length));
}

/**
 * Converts a Uint8Array to a hexadecimal string
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a hexadecimal string to a Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  const normalized = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Pads a string to a specific length with null bytes
 */
export function pad(str: string, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  const encoded = new TextEncoder().encode(str);
  bytes.set(encoded.slice(0, length));
  return bytes;
}

/**
 * Creates a coin public key from a hex string or creates a zero-filled one
 */
export function createCoinPublicKey(hex?: string): string {
  if (hex) {
    return hex.padStart(64, '0');
  }
  return '0'.repeat(64);
}

/**
 * Generates a random nonce
 */
export function generateNonce(): Uint8Array {
  return randomBytes(32);
}

/**
 * Generates a random secret key
 */
export function generateSecretKey(): Uint8Array {
  return randomBytes(32);
}
