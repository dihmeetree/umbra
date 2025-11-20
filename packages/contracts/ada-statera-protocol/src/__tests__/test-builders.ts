/**
 * Test Builders and Helpers for Ada Statera Protocol Tests
 *
 * This file provides fluent builders and helpers to make tests more readable and maintainable.
 * It eliminates repetitive boilerplate and provides a consistent API for common test scenarios.
 */

import type { ContractSimulator } from '@statera/simulator';
import type { Wallet } from '@statera/simulator';
import type { TokenType } from '@midnight-ntwrk/zswap';
import type { StateraPrivateState } from '../index.js';
import {
  createPrivateStateForWallet,
  createCollateralCoin,
  createSUSDCoin,
  createMockComplianceToken,
  createMockOraclePk,
  prepareCoinForReceive,
  createMockReservePoolCoin,
  createMockStakePoolCoin,
  createUserId,
  asAdmin,
  type StateraTestFixture
} from './test-utils.js';

/**
 * StateManager - Centralized management of private states for multiple users
 *
 * Automatically tracks and preserves critical metadata (admin_secret, admin_metadata, stake_metadata)
 * across circuit executions, eliminating the need for manual state management in tests.
 */
export class StateManager {
  private states: Map<string, StateraPrivateState> = new Map();

  constructor(private simulator: ContractSimulator<StateraPrivateState>) {}

  /**
   * Get or create a private state for a wallet
   * Automatically preserves admin_secret and admin_metadata from simulator
   */
  getState(wallet: Wallet, key?: string): StateraPrivateState {
    const stateKey = key || wallet.coinPublicKey;

    if (!this.states.has(stateKey)) {
      // Create new state with proper admin metadata
      const state = createPrivateStateForWallet(wallet, this.simulator);
      this.states.set(stateKey, state);
    }

    return this.states.get(stateKey)!;
  }

  /**
   * Update a wallet's state with new data
   */
  updateState(wallet: Wallet, updates: Partial<StateraPrivateState>, key?: string): void {
    const stateKey = key || wallet.coinPublicKey;
    const currentState = this.getState(wallet, key);

    this.states.set(stateKey, {
      ...currentState,
      ...updates
    });
  }

  /**
   * Capture state after a circuit execution
   * Useful for preserving stake_metadata after deposits
   */
  captureState(wallet: Wallet, key?: string): void {
    const stateKey = key || wallet.coinPublicKey;
    const simulatorState = this.simulator.getPrivateState();

    this.states.set(stateKey, {
      ...simulatorState,
      secret_key: wallet.secretKey
    });
  }

  /**
   * Clear all cached states (useful between tests)
   */
  clear(): void {
    this.states.clear();
  }
}

/**
 * DepositBuilder - Fluent builder for deposit operations
 *
 * Example:
 * ```ts
 * new DepositBuilder(simulator, fixture)
 *   .forUser(user)
 *   .amount(1000n)
 *   .withCompliance(oraclePk)
 *   .execute();
 * ```
 */
export class DepositBuilder {
  private wallet?: Wallet;
  private depositAmount: bigint = 1000n;
  private oraclePk?: Uint8Array;

  constructor(
    private simulator: ContractSimulator<StateraPrivateState>,
    private fixture: StateraTestFixture
  ) {}

  forUser(wallet: Wallet): this {
    this.wallet = wallet;
    return this;
  }

  amount(amount: bigint): this {
    this.depositAmount = amount;
    return this;
  }

  withCompliance(oraclePk: Uint8Array): this {
    this.oraclePk = oraclePk;
    return this;
  }

  execute(): void {
    if (!this.wallet) {
      throw new Error('Wallet must be specified with forUser()');
    }

    const oracle = this.oraclePk || createMockOraclePk();
    const mockCoin = createCollateralCoin(this.depositAmount);
    const complianceToken = createMockComplianceToken(this.wallet.coinPublicKey, oracle);

    prepareCoinForReceive(this.simulator, mockCoin, this.fixture.collateralTokenType);

    this.simulator
      .as(createPrivateStateForWallet(this.wallet, this.simulator), this.wallet.coinPublicKey)
      .executeImpureCircuit(
        'depositToCollateralPool',
        mockCoin,
        this.depositAmount,
        complianceToken
      );
  }
}

/**
 * MintBuilder - Fluent builder for minting sUSD
 *
 * Example:
 * ```ts
 * new MintBuilder(simulator, fixture)
 *   .forUser(user)
 *   .withCollateral(1000n)
 *   .amount(700n)
 *   .execute();
 * ```
 */
export class MintBuilder {
  private wallet?: Wallet;
  private collateralAmount: bigint = 1000n;
  private mintAmount: bigint = 700n;

  constructor(
    private simulator: ContractSimulator<StateraPrivateState>,
    private fixture: StateraTestFixture
  ) {}

  forUser(wallet: Wallet): this {
    this.wallet = wallet;
    return this;
  }

  withCollateral(amount: bigint): this {
    this.collateralAmount = amount;
    return this;
  }

  amount(amount: bigint): this {
    this.mintAmount = amount;
    return this;
  }

  execute(): void {
    if (!this.wallet) {
      throw new Error('Wallet must be specified with forUser()');
    }

    const privateState = this.getPrivateStateAfterDeposit();

    this.simulator
      .as(privateState, this.wallet.coinPublicKey)
      .executeImpureCircuit('mint_sUSD', this.mintAmount);
  }

  private getPrivateStateAfterDeposit(): StateraPrivateState {
    const currentState = this.simulator.getPrivateState();

    return {
      ...currentState,
      secret_key: this.wallet!.secretKey,
      mint_metadata: {
        collateral: this.collateralAmount,
        debt: 0n
      }
    };
  }
}

/**
 * StakeBuilder - Fluent builder for stability pool operations
 *
 * Example:
 * ```ts
 * new StakeBuilder(simulator, fixture)
 *   .forUser(staker)
 *   .amount(10000n)
 *   .execute();
 * ```
 */
export class StakeBuilder {
  private wallet?: Wallet;
  private stakeAmount: bigint = 10000n;

  constructor(
    private simulator: ContractSimulator<StateraPrivateState>,
    private fixture: StateraTestFixture
  ) {}

  forUser(wallet: Wallet): this {
    this.wallet = wallet;
    return this;
  }

  amount(amount: bigint): this {
    this.stakeAmount = amount;
    return this;
  }

  execute(): StateraPrivateState {
    if (!this.wallet) {
      throw new Error('Wallet must be specified with forUser()');
    }

    const stakeCoin = createSUSDCoin(this.stakeAmount, this.fixture.sSUSDTokenType);
    prepareCoinForReceive(this.simulator, stakeCoin, this.fixture.sSUSDTokenType);

    this.simulator
      .as(createPrivateStateForWallet(this.wallet, this.simulator), this.wallet.coinPublicKey)
      .executeImpureCircuit('depositToStabilityPool', stakeCoin);

    // Return the updated stake metadata for caller to preserve
    return this.simulator.getPrivateState();
  }
}

/**
 * LiquidationBuilder - Fluent builder for liquidation operations
 *
 * Example:
 * ```ts
 * new LiquidationBuilder(simulator, fixture)
 *   .forTarget(borrower)
 *   .byLiquidator(liquidator)
 *   .withCollateral(1000n)
 *   .withDebt(703n)
 *   .liquidateAmount(703n)
 *   .execute();
 * ```
 */
export class LiquidationBuilder {
  private targetWallet?: Wallet;
  private liquidatorWallet?: Wallet;
  private totalCollateral: bigint = 1000n;
  private totalDebt: bigint = 703n;
  private debtToLiquidate: bigint = 703n;

  constructor(
    private simulator: ContractSimulator<StateraPrivateState>,
    private fixture: StateraTestFixture
  ) {}

  forTarget(wallet: Wallet): this {
    this.targetWallet = wallet;
    return this;
  }

  byLiquidator(wallet: Wallet): this {
    this.liquidatorWallet = wallet;
    return this;
  }

  withCollateral(amount: bigint): this {
    this.totalCollateral = amount;
    return this;
  }

  withDebt(amount: bigint): this {
    this.totalDebt = amount;
    return this;
  }

  liquidateAmount(amount: bigint): this {
    this.debtToLiquidate = amount;
    return this;
  }

  execute(): void {
    if (!this.targetWallet || !this.liquidatorWallet) {
      throw new Error('Both target and liquidator wallets must be specified');
    }

    const depositId = createUserId(this.targetWallet);

    const liquidatorState: StateraPrivateState = {
      ...createPrivateStateForWallet(this.liquidatorWallet, this.simulator),
      stake_pool_coin: createMockStakePoolCoin(this.fixture.sSUSDTokenType),
      reserve_pool_coin: createMockReservePoolCoin(this.fixture.collateralTokenType)
    };

    this.simulator
      .as(liquidatorState, this.liquidatorWallet.coinPublicKey)
      .executeImpureCircuit(
        'liquidateDebtPosition',
        this.totalCollateral,
        this.totalDebt,
        this.debtToLiquidate,
        depositId
      );
  }
}

/**
 * AdminBuilder - Fluent builder for admin operations
 *
 * Example:
 * ```ts
 * new AdminBuilder(simulator, fixture)
 *   .addOracle(oraclePk)
 *   .resetConfig(70n, 68n, 120n)
 *   .togglePause();
 * ```
 */
export class AdminBuilder {
  constructor(
    private simulator: ContractSimulator<StateraPrivateState>,
    private adminWallet: Wallet
  ) {}

  addOracle(oraclePk: Uint8Array): this {
    asAdmin(this.simulator, this.adminWallet)
      .executeImpureCircuit('addTrustedOracle', oraclePk);
    return this;
  }

  resetConfig(liquidationThreshold: bigint, lvt: bigint, mcr: bigint): this {
    asAdmin(this.simulator, this.adminWallet)
      .executeImpureCircuit('resetProtocolConfig', liquidationThreshold, lvt, mcr);
    return this;
  }

  togglePause(): this {
    asAdmin(this.simulator, this.adminWallet)
      .executeImpureCircuit('togglePause');
    return this;
  }

  withdrawFees(amount: bigint, collateralTokenType: TokenType): this {
    const adminState = {
      ...createPrivateStateForWallet(this.adminWallet, this.simulator),
      reserve_pool_coin: createMockReservePoolCoin(collateralTokenType)
    };

    this.simulator
      .as(adminState, this.adminWallet.coinPublicKey)
      .executeImpureCircuit('withdrawProtocolFees', amount);

    return this;
  }
}

/**
 * TestScenarioBuilder - High-level builder for complete test scenarios
 *
 * Example:
 * ```ts
 * const scenario = new TestScenarioBuilder(fixture)
 *   .setupOracle()
 *   .createBorrower(user, 1000n, 700n)
 *   .createStaker(staker, 10000n)
 *   .createLiquidation(liquidator, user, 1000n, 703n)
 *   .build();
 * ```
 */
export class TestScenarioBuilder {
  private stateManager: StateManager;
  private oraclePk?: Uint8Array;

  constructor(private fixture: StateraTestFixture) {
    this.stateManager = new StateManager(fixture.simulator);
  }

  /**
   * Setup oracle for the protocol
   */
  setupOracle(oraclePk?: Uint8Array): this {
    this.oraclePk = oraclePk || createMockOraclePk();

    new AdminBuilder(this.fixture.simulator, this.fixture.adminWallet)
      .addOracle(this.oraclePk);

    return this;
  }

  /**
   * Create a borrower with deposit and mint
   */
  createBorrower(wallet: Wallet, collateral: bigint, mintAmount: bigint): this {
    if (!this.oraclePk) {
      throw new Error('Oracle must be setup first with setupOracle()');
    }

    // Deposit
    new DepositBuilder(this.fixture.simulator, this.fixture)
      .forUser(wallet)
      .amount(collateral)
      .withCompliance(this.oraclePk)
      .execute();

    // Mint
    new MintBuilder(this.fixture.simulator, this.fixture)
      .forUser(wallet)
      .withCollateral(collateral)
      .amount(mintAmount)
      .execute();

    return this;
  }

  /**
   * Create a staker with deposit to stability pool
   */
  createStaker(wallet: Wallet, stakeAmount: bigint): this {
    const stakeMetadata = new StakeBuilder(this.fixture.simulator, this.fixture)
      .forUser(wallet)
      .amount(stakeAmount)
      .execute();

    // Preserve the stake metadata
    this.stateManager.captureState(wallet);

    return this;
  }

  /**
   * Setup admin configuration changes
   */
  adminResetConfig(liquidationThreshold: bigint, lvt: bigint, mcr: bigint): this {
    new AdminBuilder(this.fixture.simulator, this.fixture.adminWallet)
      .resetConfig(liquidationThreshold, lvt, mcr);

    return this;
  }

  /**
   * Get the state manager for accessing preserved states
   */
  getStateManager(): StateManager {
    return this.stateManager;
  }

  /**
   * Build and return the scenario context
   */
  build(): { stateManager: StateManager; fixture: StateraTestFixture } {
    return {
      stateManager: this.stateManager,
      fixture: this.fixture
    };
  }
}
