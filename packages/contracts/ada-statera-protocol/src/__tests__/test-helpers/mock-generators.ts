/**
 * Mock Data Generators
 *
 * Functions for generating mock oracles, compliance tokens, and other test data
 */

import { randomBytes, pad } from '@statera/simulator';
import { persistentCommit } from '@midnight-ntwrk/compact-runtime';
import type { Wallet } from '@statera/simulator';

/**
 * Creates a mock oracle public key
 */
export function createMockOraclePk(): Uint8Array {
  return randomBytes(32);
}

/**
 * Creates a mock compliance (KYC) token
 */
export function createMockComplianceToken(
  userPk: string,
  oraclePk: Uint8Array
): { user: Uint8Array; oracle: Uint8Array } {
  return {
    user: Buffer.from(userPk, 'hex'),
    oracle: oraclePk,
  };
}

/**
 * Creates a user ID from wallet (used for deposit IDs)
 */
export function createUserId(wallet: Wallet): Uint8Array {
  const pkBytes = Buffer.from(wallet.coinPublicKey, 'hex');
  return persistentCommit(pkBytes, wallet.secretKey);
}

/**
 * Creates a mint counter commitment
 */
export function createMintCounterCommitment(
  counter: bigint,
  secretKey: Uint8Array
): Uint8Array {
  // Simplified version - actual implementation would use persistentHash
  return new Uint8Array(32);
}

/**
 * Creates a metadata hash (placeholder for actual hashing logic)
 */
export function createMetadataHash(): Uint8Array {
  return new Uint8Array(32);
}
