/**
 * Test Data Factories and Constants
 *
 * Centralized test data management for consistent and maintainable tests.
 * All magic numbers and test constants should be defined here.
 */

/**
 * Common deposit amounts for different test scenarios
 */
export const DepositAmounts = {
  /** Minimal deposit for testing edge cases (100 ADA) */
  MINIMAL: 100n,

  /** Small deposit for basic tests (500 ADA) */
  SMALL: 500n,

  /** Standard deposit amount used in most tests (1000 ADA) */
  STANDARD: 1000n,

  /** Medium deposit for multi-user scenarios (2000 ADA) */
  MEDIUM: 2000n,

  /** Large deposit for liquidation tests (5000 ADA) */
  LARGE: 5000n,

  /** Very large deposit for stress tests (10000 ADA) */
  VERY_LARGE: 10000n,
} as const;

/**
 * Common mint amounts for different test scenarios
 */
export const MintAmounts = {
  /** Minimal mint below minimum debt threshold */
  BELOW_MINIMUM: 50n,

  /** Exactly at minimum debt (100 sUSD) */
  MINIMUM: 100n,

  /** Small mint amount (300 sUSD) */
  SMALL: 300n,

  /** Standard mint at 50% LVT from 1000 collateral (500 sUSD) */
  STANDARD: 500n,

  /** At 70% LVT from 1000 collateral (700 sUSD) */
  AT_LVT: 700n,

  /** Medium mint (1000 sUSD) */
  MEDIUM: 1000n,

  /** Large mint (5000 sUSD) */
  LARGE: 5000n,
} as const;

/**
 * Common stake amounts for stability pool
 */
export const StakeAmounts = {
  /** Minimal stake (1000 sUSD) */
  MINIMAL: 1000n,

  /** Small stake (5000 sUSD) */
  SMALL: 5000n,

  /** Standard stake (10000 sUSD) */
  STANDARD: 10000n,

  /** Large stake (50000 sUSD) */
  LARGE: 50000n,
} as const;

/**
 * Protocol fee configuration (basis points - 1 bp = 0.01%)
 */
export const Fees = {
  /** Default borrowing fee: 0.5% (50 basis points) */
  BORROWING_FEE_BPS: 50n,

  /** Default redemption fee: 0.5% (50 basis points) */
  REDEMPTION_FEE_BPS: 50n,

  /** Default liquidation incentive: 5% (500 basis points) */
  LIQUIDATION_INCENTIVE_BPS: 500n,

  /** Maximum allowed redemption fee: 1% (100 basis points) */
  MAX_REDEMPTION_FEE_BPS: 100n,

  /** Convert basis points to percentage */
  bpsToPercentage: (bps: bigint): number => Number(bps) / 100,

  /** Calculate fee amount from principal */
  calculateFee: (principal: bigint, feeBps: bigint): bigint => {
    return (principal * feeBps) / 10000n;
  },
} as const;

/**
 * Protocol threshold configuration
 */
export const Thresholds = {
  /** Default Loan-to-Value ratio: 70% */
  DEFAULT_LVT: 70n,

  /** Conservative LVT for safer positions: 50% */
  CONSERVATIVE_LVT: 50n,

  /** Aggressive LVT near max: 68% */
  AGGRESSIVE_LVT: 68n,

  /** Default liquidation threshold: 80% */
  DEFAULT_LIQUIDATION: 80n,

  /** Lower liquidation threshold for testing: 70% */
  LOW_LIQUIDATION: 70n,

  /** High liquidation threshold: 90% */
  HIGH_LIQUIDATION: 90n,

  /** Default Minimum Collateral Ratio: 110% */
  DEFAULT_MCR: 110n,

  /** Conservative MCR: 150% */
  CONSERVATIVE_MCR: 150n,

  /** Minimum debt threshold: 100 sUSD */
  MINIMUM_DEBT: 100n,

  /** Calculate health factor */
  calculateHealthFactor: (collateral: bigint, debt: bigint, liquidationThreshold: bigint): bigint => {
    if (debt === 0n) return 999999n; // Infinite health factor
    return (collateral * liquidationThreshold) / (debt * 100n);
  },

  /** Check if position is healthy (HF >= 1) */
  isHealthy: (collateral: bigint, debt: bigint, liquidationThreshold: bigint): boolean => {
    const hf = Thresholds.calculateHealthFactor(collateral, debt, liquidationThreshold);
    return hf >= 1n;
  },
} as const;

/**
 * Unit conversion constants
 */
export const Units = {
  /** SPECK per tDUST (Midnight's smallest unit conversion) */
  SPECK_PER_TDUST: 1000000n,

  /** Convert tDUST to SPECK */
  toSpeck: (tdust: bigint): bigint => tdust * Units.SPECK_PER_TDUST,

  /** Convert SPECK to tDUST */
  toTDust: (speck: bigint): bigint => speck / Units.SPECK_PER_TDUST,
} as const;

/**
 * Test scenario configurations
 */
export const Scenarios = {
  /** Healthy position that won't be liquidated */
  HEALTHY_POSITION: {
    collateral: DepositAmounts.STANDARD,
    mint: MintAmounts.STANDARD,
    lvt: Thresholds.DEFAULT_LVT,
    liquidationThreshold: Thresholds.DEFAULT_LIQUIDATION,
    description: '1000 ADA collateral, 500 sUSD debt at 70% LVT, 80% liquidation threshold',
  },

  /** Position at exact liquidation boundary */
  AT_LIQUIDATION_BOUNDARY: {
    collateral: DepositAmounts.STANDARD,
    mint: MintAmounts.AT_LVT,
    lvt: Thresholds.DEFAULT_LVT,
    liquidationThreshold: Thresholds.LOW_LIQUIDATION, // Set to 70% to make 70% debt ratio liquidatable
    description: '1000 ADA collateral, 700 sUSD debt, becomes liquidatable when threshold lowered to 70%',
  },

  /** Underwater position ready for liquidation */
  LIQUIDATABLE_POSITION: {
    collateral: DepositAmounts.STANDARD,
    mint: MintAmounts.AT_LVT,
    lvt: Thresholds.DEFAULT_LVT,
    liquidationThreshold: Thresholds.LOW_LIQUIDATION,
    description: '1000 ADA collateral, 703.5 sUSD debt (with fee), HF < 1',
  },

  /** Small position for testing minimums */
  MINIMAL_POSITION: {
    collateral: DepositAmounts.MINIMAL,
    mint: MintAmounts.MINIMUM,
    lvt: Thresholds.DEFAULT_LVT,
    liquidationThreshold: Thresholds.DEFAULT_LIQUIDATION,
    description: '100 ADA collateral, 100 sUSD debt (minimum)',
  },

  /** Large position for stress testing */
  LARGE_POSITION: {
    collateral: DepositAmounts.VERY_LARGE,
    mint: MintAmounts.LARGE,
    lvt: Thresholds.DEFAULT_LVT,
    liquidationThreshold: Thresholds.DEFAULT_LIQUIDATION,
    description: '10000 ADA collateral, 5000 sUSD debt',
  },
} as const;

/**
 * Oracle price configurations (in SPECK per ADA)
 */
export const OraclePrices = {
  /** Standard oracle price: $1.00 per ADA */
  STANDARD: 1000000n,

  /** High price: $2.00 per ADA (price increase) */
  HIGH: 2000000n,

  /** Low price: $0.50 per ADA (price decrease) */
  LOW: 500000n,

  /** Very low price for testing liquidations: $0.30 per ADA */
  VERY_LOW: 300000n,
} as const;

/**
 * Time-based constants
 */
export const Time = {
  /** One day in seconds */
  ONE_DAY: 86400n,

  /** One week in seconds */
  ONE_WEEK: 604800n,

  /** One month in seconds (30 days) */
  ONE_MONTH: 2592000n,
} as const;

/**
 * Helper to calculate expected values
 */
export const Calculations = {
  /**
   * Calculate expected debt with borrowing fee
   */
  calculateTotalDebt: (mintAmount: bigint, feeBps: bigint = Fees.BORROWING_FEE_BPS): bigint => {
    const fee = Fees.calculateFee(mintAmount, feeBps);
    return mintAmount + fee;
  },

  /**
   * Calculate maximum mintable amount at given LVT
   */
  calculateMaxMint: (collateral: bigint, lvt: bigint): bigint => {
    return (collateral * lvt) / 100n;
  },

  /**
   * Calculate collateral to seize in liquidation
   */
  calculateLiquidationCollateral: (
    totalCollateral: bigint,
    totalDebt: bigint,
    debtToLiquidate: bigint
  ): bigint => {
    return (totalCollateral * debtToLiquidate) / totalDebt;
  },

  /**
   * Calculate liquidator incentive
   */
  calculateLiquidatorIncentive: (
    collateralSeized: bigint,
    incentiveBps: bigint = Fees.LIQUIDATION_INCENTIVE_BPS
  ): bigint => {
    const collateralInSpeck = Units.toSpeck(collateralSeized);
    return (collateralInSpeck * incentiveBps) / 10000n;
  },
} as const;

/**
 * Pre-configured test wallets identifiers
 */
export const TestWallets = {
  ADMIN: 'admin',
  USER_1: 'user_0',
  USER_2: 'user_1',
  USER_3: 'user_2',
  BORROWER: 'user_0',
  STAKER: 'user_1',
  LIQUIDATOR: 'user_2',
  REDEEMER: 'user_3',
} as const;

/**
 * Export a convenience object with all test data
 */
export const TestData = {
  deposits: DepositAmounts,
  mints: MintAmounts,
  stakes: StakeAmounts,
  fees: Fees,
  thresholds: Thresholds,
  units: Units,
  scenarios: Scenarios,
  prices: OraclePrices,
  time: Time,
  calc: Calculations,
  wallets: TestWallets,
} as const;

// Type export for scenarios
export type TestScenario = typeof Scenarios[keyof typeof Scenarios];
