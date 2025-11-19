import { describe, it, expect, beforeEach } from 'vitest';
import { BalanceTracker } from '../BalanceTracker';
import { tokenType } from '@midnight-ntwrk/ledger';
import { sampleContractAddress } from '@midnight-ntwrk/compact-runtime';
import { pad } from '../utils';

describe('BalanceTracker', () => {
  let tracker: BalanceTracker;
  let tokenType1: any;
  let tokenType2: any;

  beforeEach(() => {
    tracker = new BalanceTracker();
    const addr1 = sampleContractAddress();
    const addr2 = sampleContractAddress();
    tokenType1 = tokenType(pad('token1', 32), addr1);
    tokenType2 = tokenType(pad('token2', 32), addr2);
  });

  describe('setBalance and getBalance', () => {
    it('should set and get balance', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      const balance = tracker.getBalance('wallet1', tokenType1);
      expect(balance).toBe(1000n);
    });

    it('should return 0 for non-existent balance', () => {
      const balance = tracker.getBalance('wallet1', tokenType1);
      expect(balance).toBe(0n);
    });

    it('should handle multiple tokens per wallet', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet1', tokenType2, 500n);

      expect(tracker.getBalance('wallet1', tokenType1)).toBe(1000n);
      expect(tracker.getBalance('wallet1', tokenType2)).toBe(500n);
    });

    it('should handle multiple wallets', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet2', tokenType1, 500n);

      expect(tracker.getBalance('wallet1', tokenType1)).toBe(1000n);
      expect(tracker.getBalance('wallet2', tokenType1)).toBe(500n);
    });

    it('should update existing balance', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet1', tokenType1, 2000n);

      expect(tracker.getBalance('wallet1', tokenType1)).toBe(2000n);
    });
  });

  describe('getAllBalances', () => {
    it('should return empty object for non-existent wallet', () => {
      const balances = tracker.getAllBalances('wallet1');
      expect(balances).toEqual({});
    });

    it('should return all balances for wallet', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet1', tokenType2, 500n);

      const balances = tracker.getAllBalances('wallet1');
      expect(Object.keys(balances).length).toBe(2);
    });
  });

  describe('getWallets', () => {
    it('should return empty array initially', () => {
      expect(tracker.getWallets()).toEqual([]);
    });

    it('should return all wallet keys', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet2', tokenType1, 500n);

      const wallets = tracker.getWallets();
      expect(wallets).toContain('wallet1');
      expect(wallets).toContain('wallet2');
      expect(wallets.length).toBe(2);
    });
  });

  describe('clear', () => {
    it('should clear all balances', () => {
      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet2', tokenType2, 500n);

      tracker.clear();

      expect(tracker.getWallets()).toEqual([]);
      expect(tracker.getBalance('wallet1', tokenType1)).toBe(0n);
    });
  });

  describe('getBalanceChanges', () => {
    it('should calculate positive changes', () => {
      const previous = {
        [tokenType1.toString()]: 1000n,
      };

      tracker.setBalance('wallet1', tokenType1, 1500n);
      const changes = tracker.getBalanceChanges('wallet1', previous);

      expect(changes[tokenType1.toString()]).toBe(500n);
    });

    it('should calculate negative changes', () => {
      const previous = {
        [tokenType1.toString()]: 1000n,
      };

      tracker.setBalance('wallet1', tokenType1, 500n);
      const changes = tracker.getBalanceChanges('wallet1', previous);

      expect(changes[tokenType1.toString()]).toBe(-500n);
    });

    it('should detect new tokens', () => {
      const previous = {
        [tokenType1.toString()]: 1000n,
      };

      tracker.setBalance('wallet1', tokenType1, 1000n);
      tracker.setBalance('wallet1', tokenType2, 500n);
      const changes = tracker.getBalanceChanges('wallet1', previous);

      expect(changes[tokenType2.toString()]).toBe(500n);
    });

    it('should detect removed tokens', () => {
      const previous = {
        [tokenType1.toString()]: 1000n,
        [tokenType2.toString()]: 500n,
      };

      tracker.setBalance('wallet1', tokenType1, 1000n);
      const changes = tracker.getBalanceChanges('wallet1', previous);

      expect(changes[tokenType2.toString()]).toBe(-500n);
    });

    it('should ignore unchanged balances', () => {
      const previous = {
        [tokenType1.toString()]: 1000n,
      };

      tracker.setBalance('wallet1', tokenType1, 1000n);
      const changes = tracker.getBalanceChanges('wallet1', previous);

      expect(Object.keys(changes).length).toBe(0);
    });
  });
});
