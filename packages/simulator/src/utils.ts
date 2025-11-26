/**
 * Generates cryptographically secure random bytes
 * Works in both browser (Web Crypto API) and Node.js environments
 */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  // Use Web Crypto API (works in browsers and modern Node.js)
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes)
    return bytes
  }
  // Fallback for older Node.js environments
  throw new Error('No cryptographic random number generator available')
}

/**
 * Converts a Uint8Array to a hexadecimal string
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Converts a hexadecimal string to a Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  const normalized = hex.replace(/^0x/, '')
  const bytes = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.substr(i, 2), 16)
  }
  return bytes
}

/**
 * Pads a string to a specific length with null bytes
 */
export function pad(str: string, length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  const encoded = new TextEncoder().encode(str)
  bytes.set(encoded.slice(0, length))
  return bytes
}

/**
 * Creates a coin public key from a hex string or creates a zero-filled one
 */
export function createCoinPublicKey(hex?: string): string {
  if (hex) {
    return hex.padStart(64, '0')
  }
  return '0'.repeat(64)
}

/**
 * Generates a random nonce
 */
export function generateNonce(): Uint8Array {
  return randomBytes(32)
}

/**
 * Generates a random secret key
 */
export function generateSecretKey(): Uint8Array {
  return randomBytes(32)
}
