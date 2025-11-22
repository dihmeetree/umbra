import type { TokenType } from '@midnight-ntwrk/zswap'
import type * as ocrt from '@midnight-ntwrk/onchain-runtime'
import { generateNonce, toHex } from './utils.js'

/**
 * Fluent builder for creating coins in tests
 *
 * Simplifies coin creation with sensible defaults and a clean API
 *
 * @example
 * ```typescript
 * const coin = new CoinBuilder()
 *   .ofType(tokenType)
 *   .withValue(1000n)
 *   .build();
 *
 * // Or use the shorter form:
 * const coin = CoinBuilder.create(tokenType, 1000n);
 * ```
 */
export class CoinBuilder {
  private tokenType?: TokenType
  private value: bigint = 0n
  private nonceValue?: Uint8Array

  /**
   * Sets the token type for this coin
   */
  ofType(tokenType: TokenType): this {
    this.tokenType = tokenType
    return this
  }

  /**
   * Sets the value/amount for this coin
   */
  withValue(value: bigint): this {
    this.value = value
    return this
  }

  /**
   * Sets a specific nonce (auto-generated if not provided)
   */
  withNonce(nonce: Uint8Array): this {
    this.nonceValue = nonce
    return this
  }

  /**
   * Builds the coin
   * @throws If token type is not set
   */
  build(): ocrt.CoinInfo {
    if (!this.tokenType) {
      throw new Error(
        'CoinBuilder: token type is required. Use ofType() to set it.'
      )
    }

    const nonce = this.nonceValue || generateNonce()

    return {
      type: this.tokenType,
      value: this.value,
      nonce: toHex(nonce) as ocrt.Nonce
    }
  }

  /**
   * Quick factory method to create a coin with minimal syntax
   *
   * @param tokenType - The token type
   * @param value - The coin value
   * @param nonce - Optional nonce (auto-generated if not provided)
   * @returns A CoinInfo object
   */
  static create(
    tokenType: TokenType,
    value: bigint,
    nonce?: Uint8Array
  ): ocrt.CoinInfo {
    const builder = new CoinBuilder().ofType(tokenType).withValue(value)
    if (nonce) {
      builder.withNonce(nonce)
    }
    return builder.build()
  }

  /**
   * Creates multiple coins with the same token type but different values
   *
   * @param tokenType - The token type
   * @param values - Array of values for each coin
   * @returns Array of CoinInfo objects
   */
  static createBatch(tokenType: TokenType, values: bigint[]): ocrt.CoinInfo[] {
    return values.map((value) => CoinBuilder.create(tokenType, value))
  }

  /**
   * Creates a zero-value coin (useful for testing)
   *
   * @param tokenType - The token type
   * @returns A CoinInfo with value 0
   */
  static createEmpty(tokenType: TokenType): ocrt.CoinInfo {
    return CoinBuilder.create(tokenType, 0n)
  }
}

/**
 * Legacy format coin builder for contracts that use { nonce, color, value }
 * instead of { type, nonce, value }
 */
export class LegacyCoinBuilder {
  private color?: Uint8Array
  private value: bigint = 0n
  private nonce?: Uint8Array

  /**
   * Sets the color (token identifier) for this coin
   */
  withColor(color: Uint8Array): this {
    this.color = color
    return this
  }

  /**
   * Sets the value/amount for this coin
   */
  withValue(value: bigint): this {
    this.value = value
    return this
  }

  /**
   * Sets a specific nonce (auto-generated if not provided)
   */
  withNonce(nonce: Uint8Array): this {
    this.nonce = nonce
    return this
  }

  /**
   * Builds the legacy format coin
   * @throws If color is not set
   */
  build(): { nonce: Uint8Array; color: Uint8Array; value: bigint } {
    if (!this.color) {
      throw new Error(
        'LegacyCoinBuilder: color is required. Use withColor() to set it.'
      )
    }

    return {
      nonce: this.nonce || generateNonce(),
      color: this.color,
      value: this.value
    }
  }

  /**
   * Quick factory method for legacy coins
   */
  static create(color: Uint8Array, value: bigint, nonce?: Uint8Array): any {
    return new LegacyCoinBuilder()
      .withColor(color)
      .withValue(value)
      .withNonce(nonce || generateNonce())
      .build()
  }
}
