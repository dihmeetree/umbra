import { describe, it, expect, beforeEach } from 'vitest';
import {
  createStateraTestFixture,
  createPrivateStateForWallet,
  createSUSDCoin,
  createMockOraclePk,
  prepareCoinForReceive,
  createMockReservePoolCoin,
  createMockStakePoolCoin,
  getPrivateStateAfterStake,
  getPrivateStateAfterDeposit,
  createAdminPrivateState,
  createCollateralCoin,
  createMockComplianceToken,
  createUserId,
  asAdmin,
  type StateraTestFixture
} from './test-utils.js';
import {
  DepositBuilder,
  MintBuilder,
  StakeBuilder,
  LiquidationBuilder,
  AdminBuilder,
  TestScenarioBuilder,
  StateManager
} from './test-builders.js';
import { TestData } from './test-data.js';

describe('Ada Statera Protocol - Full Integration Tests', () => {
  let fixture: StateraTestFixture;

  beforeEach(() => {
    fixture = createStateraTestFixture(5);
  });

  describe('Complete Deposit → Mint → Repay Flow', () => {
    it('should allow user to deposit collateral, mint sUSD, and repay debt', () => {
      const { simulator, adminWallet, userWallets, sSUSDTokenType } = fixture;
      const user = userWallets[0];
      const oraclePk = createMockOraclePk();

      // Step 1: Admin adds trusted oracle
      new AdminBuilder(simulator, adminWallet)
        .addOracle(oraclePk);

      // Step 2: User deposits collateral
      const depositAmount = TestData.deposits.STANDARD;
      new DepositBuilder(simulator, fixture)
        .forUser(user)
        .amount(depositAmount)
        .withCompliance(oraclePk)
        .execute();

      // Step 3: User mints sUSD (at 70% LVT, can mint up to 700 sUSD from 1000 ADA)
      const mintAmount = TestData.mints.STANDARD;
      expect(() => {
        new MintBuilder(simulator, fixture)
          .forUser(user)
          .withCollateral(depositAmount)
          .amount(mintAmount)
          .execute();
      }).not.toThrow();

      // Step 4: User repays debt
      const repayAmount = 200n;
      const mockSUSDCoin = createSUSDCoin(repayAmount, sSUSDTokenType);
      prepareCoinForReceive(simulator, mockSUSDCoin, sSUSDTokenType);

      const totalDebt = TestData.calc.calculateTotalDebt(mintAmount);

      expect(() => {
        simulator
          .as({
            ...createPrivateStateForWallet(user, simulator),
            mint_metadata: { collateral: depositAmount, debt: totalDebt }
          })
          .executeImpureCircuit('repay', mockSUSDCoin, repayAmount);
      }).not.toThrow();
    });
  });

  describe('Stability Pool Operations', () => {
    it('should allow staking to stability pool', () => {
      const { simulator, userWallets } = fixture;
      const staker = userWallets[0];

      expect(() => {
        new StakeBuilder(simulator, fixture)
          .forUser(staker)
          .amount(5000n)
          .execute();
      }).not.toThrow();
    });

    it('should check and withdraw stake rewards', () => {
      const { simulator, adminWallet, userWallets, collateralTokenType, sSUSDTokenType } = fixture;
      const staker = userWallets[0];
      const borrower = userWallets[1];
      const liquidator = userWallets[2];
      const oraclePk = createMockOraclePk();
      const stateManager = new StateManager(simulator);

      // Setup: Admin adds oracle
      new AdminBuilder(simulator, adminWallet)
        .addOracle(oraclePk);

      // Step 1: Staker deposits to stability pool
      new StakeBuilder(simulator, fixture)
        .forUser(staker)
        .amount(TestData.stakes.STANDARD)
        .execute();

      // Capture staker's metadata for later use
      stateManager.captureState(staker, 'after-stake');

      // Step 2-3: Borrower deposits and mints
      const depositAmount = TestData.deposits.STANDARD;
      const mintAmount = TestData.mints.AT_LVT;

      new DepositBuilder(simulator, fixture)
        .forUser(borrower)
        .amount(depositAmount)
        .withCompliance(oraclePk)
        .execute();

      new MintBuilder(simulator, fixture)
        .forUser(borrower)
        .withCollateral(depositAmount)
        .amount(mintAmount)
        .execute();

      const totalDebt = TestData.calc.calculateTotalDebt(mintAmount);

      // Step 4: Admin lowers liquidation threshold
      new AdminBuilder(simulator, adminWallet)
        .resetConfig(70n, 68n, 120n);

      // Step 5: Execute liquidation
      new LiquidationBuilder(simulator, fixture)
        .forTarget(borrower)
        .byLiquidator(liquidator)
        .withCollateral(1000n)
        .withDebt(totalDebt)
        .liquidateAmount(totalDebt)
        .execute();

      // Step 6: Check rewards
      const stakerMetadata = stateManager.getState(staker, 'after-stake').stake_metadata;

      expect(() => {
        simulator
          .as({
            ...stateManager.getState(staker),
            stake_metadata: stakerMetadata,
            stake_pool_coin: createMockStakePoolCoin(sSUSDTokenType)
          }, staker.coinPublicKey)
          .executeCircuit('checkStakeReward');
      }).not.toThrow();

      // Step 7: Withdraw rewards if available
      const updatedMetadata = simulator.getPrivateState().stake_metadata;

      if (updatedMetadata.stakeReward > 0n) {
        const withdrawAmount = updatedMetadata.stakeReward > 100n ? 100n : updatedMetadata.stakeReward;

        expect(() => {
          simulator
            .as({
              ...stateManager.getState(staker),
              stake_metadata: updatedMetadata,
              stake_pool_coin: createMockStakePoolCoin(sSUSDTokenType),
              reserve_pool_coin: createMockReservePoolCoin(collateralTokenType)
            }, staker.coinPublicKey)
            .executeImpureCircuit('withdrawStakeReward', withdrawAmount);
        }).not.toThrow();
      }
    });

    it('should allow withdrawing stake', () => {
      const { simulator, userWallets, sSUSDTokenType } = fixture;
      const staker = userWallets[0];

      // Setup: deposit first
      const stakeAmount = 5000n;
      const mockCoin = createSUSDCoin(stakeAmount, sSUSDTokenType);

      // Prepare coin for receive()
      prepareCoinForReceive(simulator, mockCoin, sSUSDTokenType);

      simulator
        .as(createPrivateStateForWallet(staker, simulator), staker.coinPublicKey)
        .executeImpureCircuit('depositToStabilityPool', mockCoin);

      // Withdraw - need stake pool coin
      expect(() => {
        simulator
          .as(getPrivateStateAfterStake(simulator, staker, stakeAmount, sSUSDTokenType), staker.coinPublicKey)
          .executeImpureCircuit('withdrawStake', 1000n);
      }).not.toThrow();
    });
  });

  describe('Liquidation Flow', () => {
    it('should liquidate under-collateralized position', () => {
      const { simulator, adminWallet, userWallets, collateralTokenType, sSUSDTokenType } = fixture;
      const targetUser = userWallets[0];  // User whose position will be liquidated
      const staker = userWallets[1];      // Staker providing funds to stability pool
      const liquidator = userWallets[2];  // Liquidator executing the liquidation
      const oraclePk = createMockOraclePk();

      // Setup: Add oracle
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // Step 1: Staker deposits to stability pool FIRST
      const stakeAmount = 10000n;
      const stakeCoin = createSUSDCoin(stakeAmount, sSUSDTokenType);
      prepareCoinForReceive(simulator, stakeCoin, sSUSDTokenType);

      simulator
        .as(createPrivateStateForWallet(staker, simulator), staker.coinPublicKey)
        .executeImpureCircuit('depositToStabilityPool', stakeCoin);

      // Step 2: Target user deposits collateral with INITIAL safe parameters (LVT=70%, Liquidation=80%)
      const depositAmount = 1000n;
      const mockCoin = createCollateralCoin(depositAmount);
      const complianceToken = createMockComplianceToken(targetUser.coinPublicKey, oraclePk);

      prepareCoinForReceive(simulator, mockCoin, collateralTokenType);

      simulator
        .as(createPrivateStateForWallet(targetUser, simulator), targetUser.coinPublicKey)
        .executeImpureCircuit(
          'depositToCollateralPool',
          mockCoin,
          depositAmount,
          complianceToken
        );

      // Step 3: Target user mints at 70% LVT with 0.5% fee
      // This is healthy at the time of minting (HF > 1)
      const mintAmount = 700n;
      simulator
        .as(getPrivateStateAfterDeposit(simulator, targetUser, depositAmount), targetUser.coinPublicKey)
        .executeImpureCircuit('mint_sUSD', mintAmount);

      const borrowingFee = (mintAmount * 50n) / 10000n; // 0.5% default fee
      const totalDebt = mintAmount + borrowingFee; // 703n
      const debtToLiquidate = 300n; // Partial liquidation

      // Step 4: Admin LOWERS liquidation threshold to make position liquidatable
      // Simulates external price change or policy update that makes position undercollateralized
      // New liquidation threshold: 70% (debt ratio is ~70.3%, so HF < 1)
      //
      // IMPORTANT: After mint_sUSD executed, simulator's state has updated protocolFeePool
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('resetProtocolConfig', 70n, 68n, 120n);

      // Generate the depositId using the same logic as the contract
      // Contract uses: generateUserId(secret_key) = persistentCommit(ownPublicKey().bytes, sk)
      const depositId = createUserId(targetUser);

      // Liquidator executes liquidation with the target user's deposit ID
      // IMPORTANT: Liquidator needs both stake_pool_coin and reserve_pool_coin for liquidation
      const liquidatorState = {
        ...createPrivateStateForWallet(liquidator, simulator),
        stake_pool_coin: createMockStakePoolCoin(sSUSDTokenType),
        reserve_pool_coin: createMockReservePoolCoin(collateralTokenType)
      };

      expect(() => {
        simulator
          .as(liquidatorState, liquidator.coinPublicKey)
          .executeImpureCircuit(
            'liquidateDebtPosition',
            depositAmount,      // Total collateral
            totalDebt,          // Total debt
            debtToLiquidate,    // Amount to liquidate
            depositId           // Deposit ID from generateUserId
          );
      }).not.toThrow();
    });
  });

  describe('Redemption Flow', () => {
    it('should allow sUSD redemption for collateral', () => {
      const { simulator, adminWallet, userWallets, sSUSDTokenType } = fixture;
      const redeemer = userWallets[0];
      const oraclePk = createMockOraclePk();

      // Add oracle first
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // Redeem sUSD for ADA
      const redemptionAmount = 1000n;
      const oraclePrice = 1000000n; // $1.00 per ADA
      const mockSUSDCoin = createSUSDCoin(redemptionAmount, sSUSDTokenType);

      // Prepare coin for receive()
      prepareCoinForReceive(simulator, mockSUSDCoin, sSUSDTokenType);

      // Redeemer needs reserve pool coin in private state
      const redeemerState = {
        ...createPrivateStateForWallet(redeemer, simulator),
        reserve_pool_coin: createMockReservePoolCoin(fixture.collateralTokenType)
      };

      expect(() => {
        simulator
          .as(redeemerState)
          .executeImpureCircuit(
            'redeemSUSD',
            mockSUSDCoin,
            redemptionAmount,
            oraclePrice,
            oraclePk
          );
      }).not.toThrow();
    });
  });

  describe('Collateral Withdrawal', () => {
    it('should allow withdrawing excess collateral', () => {
      const { simulator, adminWallet, userWallets, collateralTokenType } = fixture;
      const user = userWallets[0];
      const oraclePk = createMockOraclePk();

      // Add oracle
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // First, user must deposit collateral
      const depositAmount = 2000n;
      const mockCoin = createCollateralCoin(depositAmount);
      const complianceToken = createMockComplianceToken(user.coinPublicKey, oraclePk);

      prepareCoinForReceive(simulator, mockCoin, collateralTokenType);

      simulator
        .as(createPrivateStateForWallet(user, simulator), user.coinPublicKey)
        .executeImpureCircuit(
          'depositToCollateralPool',
          mockCoin,
          depositAmount,
          complianceToken
        );

      // Now withdraw excess collateral - reconstruct depositor leaf after deposit
      const withdrawAmount = 100n;
      const oraclePrice = 1000000n; // $1.00 per ADA

      expect(() => {
        simulator
          .as(getPrivateStateAfterDeposit(simulator, user, depositAmount, collateralTokenType), user.coinPublicKey)
          .executeImpureCircuit(
            'withdrawCollateral',
            withdrawAmount,
            oraclePrice,
            oraclePk
          );
      }).not.toThrow();
    });
  });

  describe('Protocol Pause Functionality', () => {
    it('should prevent operations when paused', () => {
      const { simulator, adminWallet, userWallets } = fixture;
      const user = userWallets[0];

      // Pause protocol
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('togglePause');

      // Attempt to mint (should fail when paused)
      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user, simulator))
          .executeImpureCircuit('mint_sUSD', 100n);
      }).toThrow();
    });

    it('should allow operations after unpausing', () => {
      const { simulator, adminWallet } = fixture;

      // Pause
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('togglePause');

      // Unpause
      expect(() => {
        asAdmin(simulator, adminWallet)
          .executeImpureCircuit('togglePause');
      }).not.toThrow();
    });
  });

  describe('Multi-User Scenarios', () => {
    it('should handle multiple users with different positions', () => {
      const { simulator, adminWallet, userWallets, collateralTokenType, sSUSDTokenType } = fixture;
      const oraclePk = createMockOraclePk();

      // Setup: Add oracle
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // User 1: Deposits and mints
      const user1 = userWallets[0];
      const user1Deposit = 2000n;
      const user1Coin = createCollateralCoin(user1Deposit);
      const user1Compliance = createMockComplianceToken(user1.coinPublicKey, oraclePk);

      // Prepare coin for receive()
      prepareCoinForReceive(simulator, user1Coin, collateralTokenType);

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user1, simulator), user1.coinPublicKey)
          .executeImpureCircuit(
            'depositToCollateralPool',
            user1Coin,
            user1Deposit,
            user1Compliance
          );
      }).not.toThrow();

      // User 2: Deposits different amount
      const user2 = userWallets[1];
      const user2Deposit = 3000n;
      const user2Coin = createCollateralCoin(user2Deposit);
      const user2Compliance = createMockComplianceToken(user2.coinPublicKey, oraclePk);

      // Prepare coin for receive()
      prepareCoinForReceive(simulator, user2Coin, collateralTokenType);

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user2, simulator), user2.coinPublicKey)
          .executeImpureCircuit(
            'depositToCollateralPool',
            user2Coin,
            user2Deposit,
            user2Compliance
          );
      }).not.toThrow();

      // User 3: Stakes in stability pool
      const user3 = userWallets[2];
      const user3Stake = 5000n;
      const user3Coin = createSUSDCoin(user3Stake, sSUSDTokenType);

      // Prepare coin for receive()
      prepareCoinForReceive(simulator, user3Coin, sSUSDTokenType);

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user3, simulator), user3.coinPublicKey)
          .executeImpureCircuit('depositToStabilityPool', user3Coin);
      }).not.toThrow();
    });
  });

  describe('Edge Cases and Validations', () => {
    it('should reject minting below minimum debt', () => {
      const { simulator, userWallets } = fixture;
      const user = userWallets[0];

      // Try to mint less than minimumDebt (100 sUSD from constructor)
      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user, simulator))
          .executeImpureCircuit('mint_sUSD', 50n); // Below minimum
      }).toThrow();
    });

    it('should reject withdrawal that would leave position under-collateralized', () => {
      const { simulator, adminWallet, userWallets } = fixture;
      const user = userWallets[0];
      const oraclePk = createMockOraclePk();

      // Add oracle
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // Try to withdraw more than allowed
      expect(() => {
        simulator
          .as(createPrivateStateForWallet(user, simulator))
          .executeImpureCircuit(
            'withdrawCollateral',
            99999n, // Excessive amount
            1000000n,
            oraclePk
          );
      }).toThrow();
    });
  });

  describe('Protocol Fee Accumulation', () => {
    it('should accumulate fees from borrowing and redemption', () => {
      const { simulator, adminWallet, userWallets, collateralTokenType, sSUSDTokenType } = fixture;
      const user = userWallets[0];
      const oraclePk = createMockOraclePk();

      // Setup: Add oracle
      asAdmin(simulator, adminWallet)
        .executeImpureCircuit('addTrustedOracle', oraclePk);

      // User deposits collateral (generates borrowing fee when minting)
      const depositCoin = createCollateralCoin(5000n);
      const userCompliance = createMockComplianceToken(user.coinPublicKey, oraclePk);

      // Prepare deposit coin
      prepareCoinForReceive(simulator, depositCoin, collateralTokenType);

      simulator
        .as(createPrivateStateForWallet(user, simulator), user.coinPublicKey)
        .executeImpureCircuit(
          'depositToCollateralPool',
          depositCoin,
          5000n,
          userCompliance
        );

      // Mint sUSD - get private state after deposit
      simulator
        .as(getPrivateStateAfterDeposit(simulator, user, 5000n), user.coinPublicKey)
        .executeImpureCircuit('mint_sUSD', 1000n);

      // User redeems (generates redemption fee)
      const redeemCoin = createSUSDCoin(500n, sSUSDTokenType);

      // Prepare redeem coin
      prepareCoinForReceive(simulator, redeemCoin, sSUSDTokenType);

      // Need reserve pool coin for redemption
      const userRedeemState = {
        ...createPrivateStateForWallet(user, simulator),
        reserve_pool_coin: createMockReservePoolCoin(collateralTokenType)
      };

      simulator
        .as(userRedeemState)
        .executeImpureCircuit('redeemSUSD', redeemCoin, 500n, 1000000n, oraclePk);

      // Admin withdraws accumulated fees after operations
      // Borrowing fee from mint: 1000 * 0.5% = 5 sUSD
      // Redemption fee from redeem: 500 * 0.5% = 2.5 sUSD (in tDUST units)
      // Total fees: ~7.5 sUSD

      // Admin needs proper state with reserve_pool_coin for withdrawal
      // IMPORTANT: After mint and redeem executed, simulator's state already has updated protocolFeePool
      const adminWithdrawState = {
        ...createAdminPrivateState(simulator, adminWallet),
        reserve_pool_coin: createMockReservePoolCoin(collateralTokenType)
      };

      expect(() => {
        simulator
          .as(adminWithdrawState, adminWallet.coinPublicKey)
          .executeImpureCircuit('withdrawProtocolFees', 5n); // Withdraw some fees
      }).not.toThrow();
    });
  });
});
