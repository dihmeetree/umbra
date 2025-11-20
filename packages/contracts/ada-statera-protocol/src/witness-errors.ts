/**
 * Custom error classes for witness functions
 *
 * Provides type-safe, descriptive errors for witness function failures
 * with context about what went wrong and how to fix it.
 */

export class WitnessError extends Error {
  constructor(message: string, public readonly context?: Record<string, any>) {
    super(message);
    this.name = 'WitnessError';
  }
}

export class MissingCoinError extends WitnessError {
  constructor(coinType: 'stake_pool' | 'reserve_pool', requiredAction: string) {
    super(
      `${coinType === 'stake_pool' ? 'Stake pool' : 'Reserve pool'} coin not found in private state. ${requiredAction}`,
      { coinType, requiredAction }
    );
    this.name = 'MissingCoinError';
  }
}

export class MissingMetadataError extends WitnessError {
  constructor(field: string) {
    super(
      `${field} not found in private state.`,
      { field }
    );
    this.name = 'MissingMetadataError';
  }
}

export class InvalidMetadataError extends WitnessError {
  constructor(field: string, value: any, expected: string) {
    super(
      `Invalid ${field}: ${value}. Expected: ${expected}`,
      { field, value, expected }
    );
    this.name = 'InvalidMetadataError';
  }
}

/**
 * Validation helpers for witness functions
 */
export const WitnessValidators = {
  /**
   * Validates that a value is defined and not null
   */
  requireDefined<T>(value: T | null | undefined, fieldName: string): T {
    if (value === null || value === undefined) {
      throw new MissingMetadataError(fieldName);
    }
    return value;
  },

  /**
   * Validates that a bigint is greater than zero
   */
  requirePositive(value: bigint, fieldName: string): bigint {
    if (value <= 0n) {
      throw new InvalidMetadataError(fieldName, value, 'greater than 0');
    }
    return value;
  },

  /**
   * Validates that a Uint8Array is not all zeros
   */
  requireNonZero(value: Uint8Array, fieldName: string): Uint8Array {
    if (value.every(byte => byte === 0)) {
      throw new InvalidMetadataError(fieldName, '0x00...', 'non-zero value');
    }
    return value;
  },

  /**
   * Validates array length
   */
  requireLength(value: any[], expectedLength: number, fieldName: string): any[] {
    if (value.length !== expectedLength) {
      throw new InvalidMetadataError(
        fieldName,
        `length ${value.length}`,
        `length ${expectedLength}`
      );
    }
    return value;
  },

  /**
   * Safe division that checks for zero divisor
   */
  safeDivision(dividend: bigint, divisor: bigint, context: string): bigint {
    if (divisor === 0n) {
      throw new WitnessError(
        `Division by zero in ${context}`,
        { dividend, divisor, context }
      );
    }
    return dividend / divisor;
  }
};
