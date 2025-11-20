import { randomBytes, toHex, pad, generateSecretKey } from './utils.js';

/**
 * Configuration for generating a mock oracle
 */
export interface MockOracleConfig {
  name?: string;
  publicKey?: Uint8Array;
}

/**
 * Configuration for generating a mock compliance token
 */
export interface MockComplianceConfig {
  did?: string;
  validUntil?: bigint;
  issuer?: string;
}

/**
 * A mock oracle public key
 */
export interface MockOracle {
  name: string;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

/**
 * A mock compliance token
 */
export interface MockComplianceToken {
  did: string;
  validUntil: bigint;
  issuer: string;
  signature: Uint8Array;
  // The actual token data that gets passed to circuits
  token: {
    holder: string;
    did: Uint8Array;
    validUntil: bigint;
    issuerSignature: Uint8Array;
  };
}

/**
 * Utilities for generating mock data for testing
 *
 * Provides easy creation of oracles, compliance tokens, and other
 * test data without manual construction
 *
 * @example
 * ```typescript
 * // Create a mock oracle
 * const oracle = MockGenerators.createOracle('PriceOracle');
 *
 * // Create a compliance token for a user
 * const token = MockGenerators.createComplianceToken(userWallet.coinPublicKey);
 *
 * // Create multiple oracles
 * const oracles = MockGenerators.createOracles(['Oracle1', 'Oracle2', 'Oracle3']);
 * ```
 */
export class MockGenerators {
  /**
   * Creates a mock oracle with a random public key
   *
   * @param name - Optional name for the oracle (for debugging)
   * @param config - Optional configuration
   * @returns Mock oracle object
   */
  static createOracle(name: string = 'TestOracle', config?: MockOracleConfig): MockOracle {
    const publicKey = config?.publicKey || generateSecretKey(); // Using secretKey as publicKey for simplicity
    const publicKeyHex = toHex(publicKey);

    return {
      name,
      publicKey,
      publicKeyHex,
    };
  }

  /**
   * Creates multiple mock oracles
   *
   * @param names - Array of oracle names
   * @returns Array of mock oracles
   */
  static createOracles(names: string[]): MockOracle[] {
    return names.map(name => MockGenerators.createOracle(name));
  }

  /**
   * Creates a map of named oracles
   *
   * @param names - Array of oracle names
   * @returns Map of oracle name to oracle object
   */
  static createOracleMap(names: string[]): Map<string, MockOracle> {
    const map = new Map<string, MockOracle>();
    for (const name of names) {
      map.set(name, MockGenerators.createOracle(name));
    }
    return map;
  }

  /**
   * Creates a mock compliance token for a user
   *
   * @param holderPublicKey - The user's coin public key
   * @param config - Optional configuration
   * @returns Mock compliance token
   */
  static createComplianceToken(
    holderPublicKey: string,
    config?: MockComplianceConfig
  ): MockComplianceToken {
    const did = config?.did || `did:mock:${toHex(randomBytes(16))}`;
    const validUntil = config?.validUntil || BigInt(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
    const issuer = config?.issuer || 'MockComplianceIssuer';
    const signature = randomBytes(64); // Mock signature

    return {
      did,
      validUntil,
      issuer,
      signature,
      token: {
        holder: holderPublicKey,
        did: pad(did, 32),
        validUntil,
        issuerSignature: signature,
      },
    };
  }

  /**
   * Creates compliance tokens for multiple users
   *
   * @param holderPublicKeys - Array of user coin public keys
   * @param config - Optional shared configuration
   * @returns Array of mock compliance tokens
   */
  static createComplianceTokens(
    holderPublicKeys: string[],
    config?: MockComplianceConfig
  ): MockComplianceToken[] {
    return holderPublicKeys.map(key => MockGenerators.createComplianceToken(key, config));
  }

  /**
   * Creates a map of compliance tokens by holder
   *
   * @param holderPublicKeys - Array of user coin public keys
   * @param config - Optional shared configuration
   * @returns Map of public key to compliance token
   */
  static createComplianceTokenMap(
    holderPublicKeys: string[],
    config?: MockComplianceConfig
  ): Map<string, MockComplianceToken> {
    const map = new Map<string, MockComplianceToken>();
    for (const key of holderPublicKeys) {
      map.set(key, MockGenerators.createComplianceToken(key, config));
    }
    return map;
  }

  /**
   * Creates a mock price feed value
   *
   * @param price - Price in smallest unit (e.g., cents or wei)
   * @param decimals - Number of decimals (default: 6 for $1.00 = 1_000_000)
   * @returns Price value as bigint
   */
  static createPrice(price: number, decimals: number = 6): bigint {
    return BigInt(Math.floor(price * Math.pow(10, decimals)));
  }

  /**
   * Creates a mock timestamp (current time + offset)
   *
   * @param offsetSeconds - Offset from current time in seconds (can be negative)
   * @returns Timestamp as bigint
   */
  static createTimestamp(offsetSeconds: number = 0): bigint {
    return BigInt(Math.floor(Date.now() / 1000) + offsetSeconds);
  }

  /**
   * Creates a mock metadata hash
   *
   * @param seed - Optional seed for deterministic generation
   * @returns 32-byte hash
   */
  static createMetadataHash(seed?: string): Uint8Array {
    if (seed) {
      // Deterministic hash based on seed
      const seedBytes = new TextEncoder().encode(seed);
      const hash = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        hash[i] = seedBytes[i % seedBytes.length] ^ (i * 7);
      }
      return hash;
    }
    // Random hash
    return randomBytes(32);
  }

  /**
   * Creates a mock nullifier
   *
   * @param seed - Optional seed for deterministic generation
   * @returns 32-byte nullifier
   */
  static createNullifier(seed?: string): Uint8Array {
    return MockGenerators.createMetadataHash(seed);
  }

  /**
   * Creates a mock commitment
   *
   * @param seed - Optional seed for deterministic generation
   * @returns 32-byte commitment
   */
  static createCommitment(seed?: string): Uint8Array {
    return MockGenerators.createMetadataHash(seed);
  }

  /**
   * Creates mock DID (Decentralized Identifier)
   *
   * @param method - DID method (default: 'mock')
   * @param identifier - Optional specific identifier
   * @returns DID string
   */
  static createDID(method: string = 'mock', identifier?: string): string {
    const id = identifier || toHex(randomBytes(16));
    return `did:${method}:${id}`;
  }

  /**
   * Creates a mock signature
   *
   * @param length - Length of signature in bytes (default: 64)
   * @returns Signature bytes
   */
  static createSignature(length: number = 64): Uint8Array {
    return randomBytes(length);
  }

  /**
   * Creates a mock address
   *
   * @param prefix - Optional prefix (e.g., '0x' for Ethereum-style)
   * @returns Address as hex string
   */
  static createAddress(prefix: string = ''): string {
    return prefix + toHex(randomBytes(20));
  }

  /**
   * Creates mock balance data for testing
   *
   * @param tokenSymbols - Array of token symbols
   * @param baseAmount - Base amount to use (will be randomized slightly)
   * @returns Map of token symbol to balance
   */
  static createBalances(
    tokenSymbols: string[],
    baseAmount: bigint = 1000n
  ): Map<string, bigint> {
    const balances = new Map<string, bigint>();
    for (const symbol of tokenSymbols) {
      // Add some randomness (±20%)
      const randomFactor = 0.8 + Math.random() * 0.4;
      const amount = BigInt(Math.floor(Number(baseAmount) * randomFactor));
      balances.set(symbol, amount);
    }
    return balances;
  }

  /**
   * Creates a random bigint within a range
   *
   * @param min - Minimum value (inclusive)
   * @param max - Maximum value (inclusive)
   * @returns Random bigint
   */
  static randomBigInt(min: bigint, max: bigint): bigint {
    const range = max - min + 1n;
    const randomBytes = Math.floor(Math.random() * Number(range));
    return min + BigInt(randomBytes);
  }

  /**
   * Creates a mock ID (useful for user IDs, position IDs, etc.)
   *
   * @param prefix - Optional prefix
   * @returns 32-byte ID
   */
  static createId(prefix?: string): Uint8Array {
    if (prefix) {
      const id = new Uint8Array(32);
      const prefixBytes = new TextEncoder().encode(prefix);
      id.set(prefixBytes.slice(0, 32));
      // Fill remaining with random
      const random = randomBytes(32 - prefixBytes.length);
      id.set(random, prefixBytes.length);
      return id;
    }
    return randomBytes(32);
  }
}

/**
 * Convenience functions that can be imported directly
 */

export const createOracle = MockGenerators.createOracle.bind(MockGenerators);
export const createOracles = MockGenerators.createOracles.bind(MockGenerators);
export const createComplianceToken = MockGenerators.createComplianceToken.bind(MockGenerators);
export const createComplianceTokens = MockGenerators.createComplianceTokens.bind(MockGenerators);
export const createPrice = MockGenerators.createPrice.bind(MockGenerators);
export const createTimestamp = MockGenerators.createTimestamp.bind(MockGenerators);
export const createMetadataHash = MockGenerators.createMetadataHash.bind(MockGenerators);
export const createNullifier = MockGenerators.createNullifier.bind(MockGenerators);
export const createCommitment = MockGenerators.createCommitment.bind(MockGenerators);
export const createDID = MockGenerators.createDID.bind(MockGenerators);
export const createSignature = MockGenerators.createSignature.bind(MockGenerators);
