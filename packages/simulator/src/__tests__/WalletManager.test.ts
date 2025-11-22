import { describe, it, expect, beforeEach } from 'vitest'
import { WalletManager } from '../WalletManager'
import { generateSecretKey } from '../utils'

describe('WalletManager', () => {
  let walletManager: WalletManager

  beforeEach(() => {
    walletManager = new WalletManager()
  })

  describe('createWallet', () => {
    it('should create a wallet with random keys', () => {
      const wallet = walletManager.createWallet()
      expect(wallet.secretKey).toBeInstanceOf(Uint8Array)
      expect(wallet.secretKey.length).toBe(32)
      expect(wallet.coinPublicKey).toBeTruthy()
      expect(wallet.coinPublicKey.length).toBe(64)
    })

    it('should store wallet with name', () => {
      walletManager.createWallet('test')
      const retrieved = walletManager.getWallet('test')
      expect(retrieved).toBeDefined()
    })

    it('should create different wallets', () => {
      const wallet1 = walletManager.createWallet()
      const wallet2 = walletManager.createWallet()
      expect(wallet1.secretKey).not.toEqual(wallet2.secretKey)
    })
  })

  describe('createWalletFromKey', () => {
    it('should create wallet from provided key', () => {
      const secretKey = generateSecretKey()
      const wallet = walletManager.createWalletFromKey(secretKey)
      expect(wallet.secretKey).toEqual(secretKey)
    })

    it('should store wallet with name', () => {
      const secretKey = generateSecretKey()
      walletManager.createWalletFromKey(secretKey, 'custom')
      const retrieved = walletManager.getWallet('custom')
      expect(retrieved?.secretKey).toEqual(secretKey)
    })
  })

  describe('getWallet', () => {
    it('should return undefined for non-existent wallet', () => {
      const wallet = walletManager.getWallet('nonexistent')
      expect(wallet).toBeUndefined()
    })

    it('should return stored wallet', () => {
      const created = walletManager.createWallet('test')
      const retrieved = walletManager.getWallet('test')
      expect(retrieved).toEqual(created)
    })
  })

  describe('removeWallet', () => {
    it('should remove existing wallet', () => {
      walletManager.createWallet('test')
      const removed = walletManager.removeWallet('test')
      expect(removed).toBe(true)
      expect(walletManager.getWallet('test')).toBeUndefined()
    })

    it('should return false for non-existent wallet', () => {
      const removed = walletManager.removeWallet('nonexistent')
      expect(removed).toBe(false)
    })
  })

  describe('clear', () => {
    it('should remove all wallets', () => {
      walletManager.createWallet('test1')
      walletManager.createWallet('test2')
      walletManager.createWallet('test3')
      expect(walletManager.count).toBe(3)

      walletManager.clear()
      expect(walletManager.count).toBe(0)
    })
  })

  describe('createWallets', () => {
    it('should create multiple wallets', () => {
      const wallets = walletManager.createWallets(5)
      expect(wallets.length).toBe(5)
      expect(walletManager.count).toBe(0) // Not stored without prefix
    })

    it('should create and store wallets with prefix', () => {
      const wallets = walletManager.createWallets(3, 'user')
      expect(wallets.length).toBe(3)
      expect(walletManager.count).toBe(3)
      expect(walletManager.getWallet('user0')).toBeDefined()
      expect(walletManager.getWallet('user1')).toBeDefined()
      expect(walletManager.getWallet('user2')).toBeDefined()
    })
  })

  describe('getAllWallets', () => {
    it('should return all wallets', () => {
      walletManager.createWallet('test1')
      walletManager.createWallet('test2')
      const all = walletManager.getAllWallets()
      expect(all.size).toBe(2)
      expect(all.has('test1')).toBe(true)
      expect(all.has('test2')).toBe(true)
    })
  })

  describe('createPrivateState', () => {
    it('should create private state from wallet', () => {
      const wallet = walletManager.createWallet()
      const privateState = WalletManager.createPrivateState<{
        secretKey: Uint8Array
      }>(wallet)
      expect(privateState.secretKey).toEqual(wallet.secretKey)
    })
  })
})
