import { describe, it, expect, beforeEach } from 'vitest';
import {
  createStateraTestFixture,
  createPrivateStateForWallet,
  type StateraTestFixture
} from './test-utils';

describe('Ada Statera Protocol - Basic Tests', () => {
  let fixture: StateraTestFixture;

  beforeEach(() => {
    fixture = createStateraTestFixture(3);
  });

  describe('Contract Deployment', () => {
    it('should deploy contract successfully', () => {
      const { simulator, contractAddress } = fixture;

      expect(simulator).toBeDefined();
      expect(contractAddress).toBeDefined();
      expect(simulator.contractAddress).toEqual(contractAddress);
    });

    it('should have correct initial private state', () => {
      const { simulator } = fixture;

      const privateState = simulator.getPrivateState();

      expect(privateState).toBeDefined();
      expect(privateState.secret_key).toBeDefined();
      expect(privateState.mint_metadata).toEqual({
        collateral: 0n,
        debt: 0n
      });
      expect(privateState.stake_metadata).toEqual({
        effectiveBalance: 0n,
        stakeReward: 0n,
        entry_ADA_SUSD_index: 0n,
        entry_scale_factor: 0n
      });
      expect(privateState.mint_counter).toBe(0n);
    });

    it('should have initial ledger state', () => {
      const { simulator } = fixture;

      const ledger = simulator.getLedger();

      expect(ledger).toBeDefined();
    });
  });

  describe('Wallet Management', () => {
    it('should have admin wallet', () => {
      const { adminWallet } = fixture;

      expect(adminWallet).toBeDefined();
      expect(adminWallet.secretKey).toBeInstanceOf(Uint8Array);
      expect(adminWallet.secretKey.length).toBe(32);
      expect(adminWallet.coinPublicKey).toBeTruthy();
    });

    it('should have user wallets', () => {
      const { userWallets } = fixture;

      expect(userWallets.length).toBe(3);
      userWallets.forEach((wallet) => {
        expect(wallet.secretKey).toBeInstanceOf(Uint8Array);
        expect(wallet.secretKey.length).toBe(32);
        expect(wallet.coinPublicKey).toBeTruthy();
      });
    });

    it('should retrieve wallets by name', () => {
      const { walletManager } = fixture;

      const admin = walletManager.getWallet('admin');
      const user0 = walletManager.getWallet('user0');
      const user1 = walletManager.getWallet('user1');
      const user2 = walletManager.getWallet('user2');

      expect(admin).toBeDefined();
      expect(user0).toBeDefined();
      expect(user1).toBeDefined();
      expect(user2).toBeDefined();
    });
  });

  describe('Context Switching', () => {
    it('should switch between different user contexts', () => {
      const { simulator, adminWallet, userWallets } = fixture;

      const adminPrivateState = createPrivateStateForWallet(adminWallet);
      simulator.as(adminPrivateState);

      let currentState = simulator.getPrivateState();
      expect(currentState.secret_key).toEqual(adminWallet.secretKey);

      const userPrivateState = createPrivateStateForWallet(userWallets[0]);
      simulator.as(userPrivateState);

      currentState = simulator.getPrivateState();
      expect(currentState.secret_key).toEqual(userWallets[0].secretKey);
    });
  });

  describe('Token Types', () => {
    it('should have correct sSUSD token type', () => {
      const { sSUSDTokenType } = fixture;

      expect(sSUSDTokenType).toBeDefined();
      expect(sSUSDTokenType.toString()).toBeTruthy();
      expect(sSUSDTokenType.toString().length).toBeGreaterThan(0);
    });

    it('should have correct sADA token type', () => {
      const { sADATokenType } = fixture;

      expect(sADATokenType).toBeDefined();
      expect(sADATokenType.toString()).toBeTruthy();
      expect(sADATokenType.toString().length).toBeGreaterThan(0);
    });

    it('should have different token types for sSUSD and sADA', () => {
      const { sSUSDTokenType, sADATokenType } = fixture;

      expect(sSUSDTokenType.toString()).not.toEqual(sADATokenType.toString());
    });
  });

  describe('Balance Tracking', () => {
    it('should track balances for wallets', () => {
      const { balanceTracker, adminWallet, sSUSDTokenType } = fixture;

      balanceTracker.setBalance(adminWallet.coinPublicKey, sSUSDTokenType, 1000n);

      const balance = balanceTracker.getBalance(adminWallet.coinPublicKey, sSUSDTokenType);
      expect(balance).toBe(1000n);
    });

    it('should return zero for non-existent balances', () => {
      const { balanceTracker, userWallets, sSUSDTokenType } = fixture;

      const balance = balanceTracker.getBalance(userWallets[0].coinPublicKey, sSUSDTokenType);
      expect(balance).toBe(0n);
    });

    it('should track multiple tokens per wallet', () => {
      const { balanceTracker, adminWallet, sSUSDTokenType, sADATokenType } = fixture;

      balanceTracker.setBalance(adminWallet.coinPublicKey, sSUSDTokenType, 1000n);
      balanceTracker.setBalance(adminWallet.coinPublicKey, sADATokenType, 500n);

      const sSUSDBalance = balanceTracker.getBalance(adminWallet.coinPublicKey, sSUSDTokenType);
      const sADABalance = balanceTracker.getBalance(adminWallet.coinPublicKey, sADATokenType);

      expect(sSUSDBalance).toBe(1000n);
      expect(sADABalance).toBe(500n);
    });
  });

  describe('Private State Management', () => {
    it('should create private state for wallet', () => {
      const { userWallets } = fixture;

      const privateState = createPrivateStateForWallet(userWallets[0]);

      expect(privateState.secret_key).toEqual(userWallets[0].secretKey);
      expect(privateState.mint_metadata.collateral).toBe(0n);
      expect(privateState.mint_metadata.debt).toBe(0n);
    });

    it('should have correct initial admin metadata', () => {
      const { simulator } = fixture;

      const privateState = simulator.getPrivateState();

      expect(privateState.admin_metadata.protocolFeePool).toBe(0n);
      expect(privateState.admin_metadata.admin_count).toBe(0n);
      expect(privateState.admin_metadata.admins.length).toBe(10);
    });

    it('should have null pool coins initially', () => {
      const { simulator } = fixture;

      const privateState = simulator.getPrivateState();

      expect(privateState.stake_pool_coin).toBeNull();
      expect(privateState.reserve_pool_coin).toBeNull();
    });

  });
});
