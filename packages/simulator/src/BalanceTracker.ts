import type * as ocrt from '@midnight-ntwrk/onchain-runtime';
import type { TokenType } from '@midnight-ntwrk/zswap';
import type { ContractSimulator } from './ContractSimulator.js';

/**
 * Tracks and manages token balances across multiple wallets
 *
 * This utility class makes it easy to track balances for testing purposes,
 * providing a convenient interface for checking and displaying wallet balances.
 */
export class BalanceTracker {
  private balances: Map<string, Map<string, bigint>> = new Map();

  /**
   * Records the balance for a wallet and token type
   *
   * @param walletKey - Identifier for the wallet (usually the coin public key)
   * @param tokenType - The token type
   * @param amount - The balance amount
   */
  setBalance(walletKey: string, tokenType: TokenType, amount: bigint): void {
    let walletBalances = this.balances.get(walletKey);
    if (!walletBalances) {
      walletBalances = new Map();
      this.balances.set(walletKey, walletBalances);
    }

    walletBalances.set(tokenType.toString(), amount);
  }

  /**
   * Gets the balance for a wallet and token type
   *
   * @param walletKey - Identifier for the wallet
   * @param tokenType - The token type
   * @returns The balance amount, or 0n if not found
   */
  getBalance(walletKey: string, tokenType: TokenType): bigint {
    const walletBalances = this.balances.get(walletKey);
    if (!walletBalances) {
      return 0n;
    }

    return walletBalances.get(tokenType.toString()) || 0n;
  }

  /**
   * Gets all balances for a wallet
   *
   * @param walletKey - Identifier for the wallet
   * @returns A record mapping token types to balances
   */
  getAllBalances(walletKey: string): Record<string, bigint> {
    const walletBalances = this.balances.get(walletKey);
    if (!walletBalances) {
      return {};
    }

    const result: Record<string, bigint> = {};
    walletBalances.forEach((balance, tokenType) => {
      result[tokenType] = balance;
    });

    return result;
  }

  /**
   * Updates balances from a simulator's current state
   *
   * @param simulator - The contract simulator to read from
   * @param recipient - The wallet's coin public key
   * @param walletKey - Optional identifier for the wallet (defaults to recipient)
   */
  updateFromSimulator<T>(
    simulator: ContractSimulator<T>,
    recipient: ocrt.CoinPublicKey,
    walletKey?: string
  ): void {
    const key = walletKey || recipient;
    const balances = simulator.getAllBalances(recipient);

    for (const [tokenType, amount] of Object.entries(balances)) {
      let walletBalances = this.balances.get(key);
      if (!walletBalances) {
        walletBalances = new Map();
        this.balances.set(key, walletBalances);
      }
      walletBalances.set(tokenType, amount);
    }
  }

  /**
   * Clears all tracked balances
   */
  clear(): void {
    this.balances.clear();
  }

  /**
   * Gets all tracked wallets
   */
  getWallets(): string[] {
    return Array.from(this.balances.keys());
  }

  /**
   * Prints a formatted balance sheet for a wallet
   *
   * @param walletKey - Identifier for the wallet
   * @param tokenNames - Optional mapping of token types to human-readable names
   */
  printBalances(walletKey: string, tokenNames?: Map<string, string>): void {
    const balances = this.getAllBalances(walletKey);
    console.log(`\n=== Balances for ${walletKey} ===`);

    if (Object.keys(balances).length === 0) {
      console.log('  No balances');
      return;
    }

    for (const [tokenType, amount] of Object.entries(balances)) {
      const name = tokenNames?.get(tokenType) || tokenType.substring(0, 8);
      console.log(`  ${name}: ${amount}`);
    }
    console.log('');
  }

  /**
   * Prints balance sheets for all tracked wallets
   *
   * @param tokenNames - Optional mapping of token types to human-readable names
   */
  printAllBalances(tokenNames?: Map<string, string>): void {
    console.log('\n=== All Wallet Balances ===');
    for (const walletKey of this.getWallets()) {
      this.printBalances(walletKey, tokenNames);
    }
  }

  /**
   * Calculates the difference between current and previous balances
   *
   * @param walletKey - Identifier for the wallet
   * @param previousBalances - Previous balance state to compare against
   * @returns A record showing the changes in balances
   */
  getBalanceChanges(
    walletKey: string,
    previousBalances: Record<string, bigint>
  ): Record<string, bigint> {
    const currentBalances = this.getAllBalances(walletKey);
    const changes: Record<string, bigint> = {};

    // Check for changes in existing tokens
    for (const [tokenType, currentAmount] of Object.entries(currentBalances)) {
      const previousAmount = previousBalances[tokenType] || 0n;
      const change = currentAmount - previousAmount;
      if (change !== 0n) {
        changes[tokenType] = change;
      }
    }

    // Check for tokens that existed before but don't now
    for (const [tokenType, previousAmount] of Object.entries(previousBalances)) {
      if (!(tokenType in currentBalances) && previousAmount !== 0n) {
        changes[tokenType] = -previousAmount;
      }
    }

    return changes;
  }
}
