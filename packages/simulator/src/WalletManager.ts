import type { Wallet } from './types.js'
import { generateSecretKey, createCoinPublicKey, toHex } from './utils.js'

/**
 * Manages wallets and their associated keys for testing
 *
 * This class provides convenient methods for creating and managing test wallets,
 * including generating keys, loading balances, and tracking wallet states.
 */
export class WalletManager {
  private wallets: Map<string, Wallet> = new Map()

  /**
   * Creates a new wallet with a random secret key
   *
   * @param name - Optional name to identify the wallet
   * @returns The created wallet
   */
  createWallet(name?: string): Wallet {
    const secretKey = generateSecretKey()
    const coinPublicKey = createCoinPublicKey(toHex(secretKey).substring(0, 64))

    const wallet: Wallet = {
      secretKey,
      coinPublicKey
    }

    if (name) {
      this.wallets.set(name, wallet)
    }

    return wallet
  }

  /**
   * Creates a wallet with a specific secret key
   *
   * @param secretKey - The secret key for the wallet
   * @param name - Optional name to identify the wallet
   * @returns The created wallet
   */
  createWalletFromKey(secretKey: Uint8Array, name?: string): Wallet {
    const coinPublicKey = createCoinPublicKey(toHex(secretKey).substring(0, 64))

    const wallet: Wallet = {
      secretKey,
      coinPublicKey
    }

    if (name) {
      this.wallets.set(name, wallet)
    }

    return wallet
  }

  /**
   * Gets a wallet by name
   *
   * @param name - The name of the wallet
   * @returns The wallet, or undefined if not found
   */
  getWallet(name: string): Wallet | undefined {
    return this.wallets.get(name)
  }

  /**
   * Gets all registered wallets
   *
   * @returns A map of wallet names to wallet objects
   */
  getAllWallets(): Map<string, Wallet> {
    return new Map(this.wallets)
  }

  /**
   * Removes a wallet by name
   *
   * @param name - The name of the wallet to remove
   * @returns True if the wallet was removed, false if it didn't exist
   */
  removeWallet(name: string): boolean {
    return this.wallets.delete(name)
  }

  /**
   * Clears all wallets
   */
  clear(): void {
    this.wallets.clear()
  }

  /**
   * Gets the number of registered wallets
   */
  get count(): number {
    return this.wallets.size
  }

  /**
   * Creates a private state object for a wallet
   * This is useful for contracts that use secretKey in their private state
   *
   * @param wallet - The wallet to create private state for
   * @returns An object with the secretKey property
   */
  static createPrivateState<T extends { secretKey: Uint8Array }>(
    wallet: Wallet
  ): T {
    return {
      secretKey: wallet.secretKey
    } as T
  }

  /**
   * Creates multiple wallets at once
   *
   * @param count - Number of wallets to create
   * @param namePrefix - Optional prefix for wallet names (e.g., "user" creates "user0", "user1", etc.)
   * @returns Array of created wallets
   */
  createWallets(count: number, namePrefix?: string): Wallet[] {
    const wallets: Wallet[] = []

    for (let i = 0; i < count; i++) {
      const name = namePrefix ? `${namePrefix}${i}` : undefined
      wallets.push(this.createWallet(name))
    }

    return wallets
  }
}
