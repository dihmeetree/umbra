/**
 * @statera/simulator - Midnight Compact Contract Testing Simulator
 *
 * A comprehensive testing framework for Midnight Compact contracts that provides:
 * - Easy contract deployment and initialization
 * - Wallet management with automatic key generation
 * - Balance tracking across multiple tokens and wallets
 * - Circuit execution with state management
 * - Utilities for testing and debugging
 *
 * @example
 * ```typescript
 * import { ContractSimulator, WalletManager, generateNonce } from '@statera/simulator';
 * import { MyContract } from './my-contract';
 *
 * // Create wallets
 * const walletManager = new WalletManager();
 * const adminWallet = walletManager.createWallet('admin');
 * const userWallet = walletManager.createWallet('user');
 *
 * // Deploy contract
 * const simulator = ContractSimulator.deploy(new MyContract.Contract({}), {
 *   initialPrivateState: { secretKey: adminWallet.secretKey },
 *   nonce: generateNonce(),
 *   coinPublicKey: adminWallet.coinPublicKey,
 *   constructorArgs: [initParam1, initParam2]
 * });
 *
 * // Execute circuits
 * simulator.as({ secretKey: adminWallet.secretKey })
 *   .executeImpureCircuit('mint', 1000n);
 *
 * // Check balances
 * const balance = simulator.getBalance(userWallet.coinPublicKey, tokenType);
 * ```
 */

export { ContractSimulator } from './ContractSimulator.js'
export { WalletManager } from './WalletManager.js'
export { BalanceTracker } from './BalanceTracker.js'

export {
  randomBytes,
  toHex,
  fromHex,
  pad,
  createCoinPublicKey,
  generateNonce,
  generateSecretKey
} from './utils.js'

// Logging
export {
  logger,
  LogLevel,
  enableDebugLogging,
  enableTraceLogging,
  disableLogging,
  setQuietMode
} from './logger.js'

// Errors
export {
  SimulatorError,
  SimulatorErrorCode,
  CircuitNotFoundError,
  MultipleOutputsError,
  OutputNotFoundError,
  WalletNotFoundError,
  CircuitExecutionError
} from './errors.js'

// Token helpers
export {
  createTokenType,
  createNativeTokenType,
  areTokenTypesEqual,
  TokenRegistry
} from './token-helpers.js'

// Assertions
export {
  assertBalance,
  assertBalanceAtLeast,
  assertZeroBalance,
  assertHasOutputs,
  assertNoOutputs,
  assertBalanceChange,
  assertBalances
} from './assertions.js'
export type { BalanceAssertion } from './assertions.js'

// Snapshots
export { SnapshotManager } from './snapshot.js'
export type { Snapshot } from './snapshot.js'

// Coin Builder
export { CoinBuilder, LegacyCoinBuilder } from './CoinBuilder.js'

// Ledger Inspector
export { LedgerInspector } from './LedgerInspector.js'
export type { MerkleTreeInfo } from './LedgerInspector.js'

// Mock Generators
export {
  MockGenerators,
  createOracle,
  createOracles,
  createComplianceToken,
  createComplianceTokens,
  createPrice,
  createTimestamp,
  createMetadataHash,
  createNullifier,
  createCommitment,
  createDID,
  createSignature
} from './MockGenerators.js'
export type {
  MockOracle,
  MockComplianceToken,
  MockOracleConfig,
  MockComplianceConfig
} from './MockGenerators.js'

export type {
  ContractWithCircuits,
  ContractConfig,
  Wallet,
  TokenBalance,
  OutputInfo,
  CircuitResult
} from './types.js'

// Simulator Extensions
export { SimulatorHistoryTracker, withHistory } from './SimulatorExtensions.js'
export type {
  HistoryEntry,
  ExecutionMetrics,
  EventLogEntry
} from './SimulatorExtensions.js'
