import type * as ocrt from '@midnight-ntwrk/onchain-runtime';
import type { TokenType } from '@midnight-ntwrk/zswap';
import type { ContractSimulator } from './ContractSimulator.js';

/**
 * Assertion helpers for testing with the simulator
 *
 * These functions provide convenient ways to assert expected state in tests
 */

export interface BalanceAssertion {
  recipient: ocrt.CoinPublicKey;
  tokenType: TokenType;
  expected: bigint;
  actual?: bigint;
}

/**
 * Asserts that a wallet has the expected balance for a token
 *
 * @param simulator - The contract simulator
 * @param recipient - The wallet's coin public key
 * @param tokenType - The token type to check
 * @param expectedBalance - The expected balance
 * @throws If the balance doesn't match
 */
export function assertBalance<T>(
  simulator: ContractSimulator<T>,
  recipient: ocrt.CoinPublicKey,
  tokenType: TokenType,
  expectedBalance: bigint
): void {
  const actualBalance = simulator.getBalance(recipient, tokenType);
  if (actualBalance !== expectedBalance) {
    throw new Error(
      `Balance assertion failed for ${recipient.slice(0, 8)}...\n` +
      `  Expected: ${expectedBalance}\n` +
      `  Actual:   ${actualBalance}\n` +
      `  Difference: ${actualBalance - expectedBalance}`
    );
  }
}

/**
 * Asserts that a wallet has at least the specified balance
 *
 * @param simulator - The contract simulator
 * @param recipient - The wallet's coin public key
 * @param tokenType - The token type to check
 * @param minimumBalance - The minimum expected balance
 * @throws If the balance is less than the minimum
 */
export function assertBalanceAtLeast<T>(
  simulator: ContractSimulator<T>,
  recipient: ocrt.CoinPublicKey,
  tokenType: TokenType,
  minimumBalance: bigint
): void {
  const actualBalance = simulator.getBalance(recipient, tokenType);
  if (actualBalance < minimumBalance) {
    throw new Error(
      `Balance assertion failed for ${recipient.slice(0, 8)}...\n` +
      `  Expected at least: ${minimumBalance}\n` +
      `  Actual:            ${actualBalance}\n` +
      `  Shortfall:         ${minimumBalance - actualBalance}`
    );
  }
}

/**
 * Asserts that a wallet has zero balance for a token
 *
 * @param simulator - The contract simulator
 * @param recipient - The wallet's coin public key
 * @param tokenType - The token type to check
 * @throws If the balance is not zero
 */
export function assertZeroBalance<T>(
  simulator: ContractSimulator<T>,
  recipient: ocrt.CoinPublicKey,
  tokenType: TokenType
): void {
  assertBalance(simulator, recipient, tokenType, 0n);
}

/**
 * Asserts that a wallet has outputs
 *
 * @param simulator - The contract simulator
 * @param recipient - The wallet's coin public key
 * @param expectedCount - Optional expected count of outputs
 * @throws If no outputs are found or count doesn't match
 */
export function assertHasOutputs<T>(
  simulator: ContractSimulator<T>,
  recipient: ocrt.CoinPublicKey,
  expectedCount?: number
): void {
  const outputs = simulator.getOutputsByRecipient(recipient);

  if (outputs.length === 0) {
    throw new Error(`No outputs found for recipient ${recipient.slice(0, 8)}...`);
  }

  if (expectedCount !== undefined && outputs.length !== expectedCount) {
    throw new Error(
      `Output count assertion failed for ${recipient.slice(0, 8)}...\n` +
      `  Expected: ${expectedCount}\n` +
      `  Actual:   ${outputs.length}`
    );
  }
}

/**
 * Asserts that a wallet has no outputs
 *
 * @param simulator - The contract simulator
 * @param recipient - The wallet's coin public key
 * @throws If any outputs are found
 */
export function assertNoOutputs<T>(
  simulator: ContractSimulator<T>,
  recipient: ocrt.CoinPublicKey
): void {
  const outputs = simulator.getOutputsByRecipient(recipient);

  if (outputs.length > 0) {
    throw new Error(
      `Expected no outputs for ${recipient.slice(0, 8)}... but found ${outputs.length}`
    );
  }
}

/**
 * Asserts that the balance changed by the expected amount
 *
 * @param beforeBalance - Balance before the operation
 * @param afterBalance - Balance after the operation
 * @param expectedChange - Expected change (positive for increase, negative for decrease)
 * @param description - Optional description of what changed
 * @throws If the change doesn't match
 */
export function assertBalanceChange(
  beforeBalance: bigint,
  afterBalance: bigint,
  expectedChange: bigint,
  description?: string
): void {
  const actualChange = afterBalance - beforeBalance;

  if (actualChange !== expectedChange) {
    const prefix = description ? `${description}: ` : '';
    throw new Error(
      `${prefix}Balance change assertion failed\n` +
      `  Expected change: ${expectedChange}\n` +
      `  Actual change:   ${actualChange}\n` +
      `  Before:          ${beforeBalance}\n` +
      `  After:           ${afterBalance}`
    );
  }
}

/**
 * Asserts multiple balance conditions at once
 *
 * @param simulator - The contract simulator
 * @param assertions - Array of balance assertions to check
 * @throws If any assertion fails
 */
export function assertBalances<T>(
  simulator: ContractSimulator<T>,
  assertions: BalanceAssertion[]
): void {
  const failures: string[] = [];

  for (const assertion of assertions) {
    const actualBalance = simulator.getBalance(assertion.recipient, assertion.tokenType);

    if (actualBalance !== assertion.expected) {
      failures.push(
        `  ${assertion.recipient.slice(0, 8)}...: expected ${assertion.expected}, got ${actualBalance}`
      );
    }
  }

  if (failures.length > 0) {
    throw new Error(
      `Multiple balance assertions failed:\n${failures.join('\n')}`
    );
  }
}
