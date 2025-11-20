import { tokenType, TokenType, sampleContractAddress } from '@midnight-ntwrk/compact-runtime';
import { pad } from './utils.js';

/**
 * Helper utilities for working with TokenTypes in tests
 */

/**
 * Creates a TokenType for testing purposes
 *
 * @param domainSeparator - Domain separator (e.g., 'ADA', 'sUSD')
 * @param contractAddress - Optional contract address (generates a sample one if not provided)
 * @returns A TokenType instance
 */
export function createTokenType(
  domainSeparator: string,
  contractAddress?: ReturnType<typeof sampleContractAddress>
): TokenType {
  const address = contractAddress || sampleContractAddress();
  return tokenType(pad(domainSeparator, 32), address);
}

/**
 * Creates a native token type (DUST)
 *
 * @returns The native TokenType
 */
export function createNativeTokenType(): TokenType {
  // Native token uses a special contract address of all zeros
  const zeroAddress = sampleContractAddress(); // This gives us a sample address structure
  return tokenType(new Uint8Array(32), zeroAddress);
}

/**
 * Compares two TokenTypes for equality
 *
 * @param a - First TokenType
 * @param b - Second TokenType
 * @returns True if the types are equal
 */
export function areTokenTypesEqual(a: TokenType, b: TokenType): boolean {
  return a.toString() === b.toString();
}

/**
 * Creates a registry of named token types for easy reference in tests
 */
export class TokenRegistry {
  private tokens: Map<string, TokenType> = new Map();

  /**
   * Registers a token type with a name
   *
   * @param name - Human-readable name for the token
   * @param tokenType - The TokenType instance
   */
  register(name: string, tokenType: TokenType): void {
    this.tokens.set(name, tokenType);
  }

  /**
   * Gets a token type by name
   *
   * @param name - The name of the token
   * @returns The TokenType, or undefined if not found
   */
  get(name: string): TokenType | undefined {
    return this.tokens.get(name);
  }

  /**
   * Gets a token type by name, throwing if not found
   *
   * @param name - The name of the token
   * @returns The TokenType
   * @throws If the token is not registered
   */
  require(name: string): TokenType {
    const token = this.tokens.get(name);
    if (!token) {
      throw new Error(`Token '${name}' not found in registry`);
    }
    return token;
  }

  /**
   * Gets all registered token names
   */
  getAllNames(): string[] {
    return Array.from(this.tokens.keys());
  }

  /**
   * Gets all registered tokens
   */
  getAllTokens(): Map<string, TokenType> {
    return new Map(this.tokens);
  }

  /**
   * Clears all registered tokens
   */
  clear(): void {
    this.tokens.clear();
  }

  /**
   * Creates a name-to-string mapping for display purposes
   */
  createDisplayMap(): Map<string, string> {
    const map = new Map<string, string>();
    this.tokens.forEach((tokenType, name) => {
      map.set(tokenType.toString(), name);
    });
    return map;
  }
}
