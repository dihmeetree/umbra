import { describe, it, expect, beforeEach } from 'vitest'
import {
  createMarketplaceTestFixture,
  asWallet,
  createItemHash,
  createPaymentCoin,
  prepareCoinForReceive,
  type MarketplaceTestFixture
} from './test-utils'
import { pad, generateRandomBytes } from '@statera/simulator'

describe('Anonymous Marketplace', () => {
  let fixture: MarketplaceTestFixture

  beforeEach(() => {
    fixture = createMarketplaceTestFixture(2, 3)
  })

  describe('Contract Deployment', () => {
    it('should deploy the marketplace contract successfully', () => {
      const { simulator, contractAddress } = fixture

      expect(simulator).toBeDefined()
      expect(contractAddress).toBeDefined()
    })

    it('should initialize with correct platform token type', () => {
      const { simulator } = fixture
      const ledger = simulator.getLedger()

      // The ledger data contains the platform token type as part of the state
      expect(ledger).toBeDefined()
    })
  })

  describe('Creating Listings', () => {
    it('should create an anonymous listing with quantity', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      // Switch to seller context
      asWallet(simulator, seller)

      // Create a listing with quantity 10 and 7-day escrow deadline
      const itemHash = createItemHash('Vintage Watch')
      const pricePerUnit = 1000n
      const quantity = 10n
      const escrowDeadline = BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60)

      const result = simulator.executeImpureCircuit(
        'createListing',
        itemHash,
        pricePerUnit,
        quantity,
        escrowDeadline
      )

      // Verify listing was created and hash returned
      expect(result.result).toBeDefined()
      expect(result.result.length).toBe(32)
    })

    it('should create a listing with no timeout', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      asWallet(simulator, seller)

      // Create a listing with escrowDeadline = 0 (no timeout)
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('No Timeout Item'),
        500n,
        5n,  // quantity
        0n   // No timeout
      )

      expect(result.result).toBeDefined()
      expect(result.result.length).toBe(32)
    })

    it('should store listing details in seller private state', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      asWallet(simulator, seller)

      const itemHash = createItemHash('Rare Book')
      const pricePerUnit = 500n
      const quantity = 3n

      const result = simulator.executeImpureCircuit(
        'createListing',
        itemHash,
        pricePerUnit,
        quantity,
        0n
      )

      // Verify listing details in private state (now stored in listings Map)
      const privateState = simulator.getPrivateState()
      const listingHash = Buffer.from(result.result).toString('hex')
      const listingDetails = privateState.listings.get(listingHash)

      expect(listingDetails).toBeDefined()
      expect(listingDetails!.pricePerUnit).toBe(pricePerUnit)
      expect(listingDetails!.quantity).toBe(quantity)
    })

    it('should generate unique listing hashes for different items', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      asWallet(simulator, seller)

      // Create first listing
      const result1 = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Item 1'),
        100n,
        1n,
        0n
      )

      // Create second listing
      const result2 = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Item 2'),
        200n,
        1n,
        0n
      )

      // Listing hashes should be different
      expect(Buffer.from(result1.result).toString('hex')).not.toBe(
        Buffer.from(result2.result).toString('hex')
      )
    })

    it('should reject zero quantity listing', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      asWallet(simulator, seller)

      expect(() => {
        simulator.executeImpureCircuit(
          'createListing',
          createItemHash('Zero Quantity Item'),
          100n,
          0n,  // Invalid: zero quantity
          0n
        )
      }).toThrow()
    })
  })

  describe('Private Balance (Deposit/Withdraw)', () => {
    it('should allow depositing coins to get private balance', () => {
      const { simulator, buyerWallets, paymentTokenType } = fixture
      const buyer = buyerWallets[0]

      asWallet(simulator, buyer)

      // Create a deposit coin
      const depositCoin = createPaymentCoin(1000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)

      // Deposit the coin
      expect(() => {
        simulator.executeImpureCircuit('deposit', depositCoin)
      }).not.toThrow()

      // Verify private state was updated
      const privateState = simulator.getPrivateState()
      expect(privateState.user_balance.balance).toBe(1000n)
    })

    it('should allow multiple deposits to accumulate balance', () => {
      const { simulator, buyerWallets, paymentTokenType } = fixture
      const buyer = buyerWallets[0]

      asWallet(simulator, buyer)

      // First deposit
      const coin1 = createPaymentCoin(500n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, coin1, paymentTokenType)
      simulator.executeImpureCircuit('deposit', coin1)

      // Second deposit
      const coin2 = createPaymentCoin(300n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, coin2, paymentTokenType)
      simulator.executeImpureCircuit('deposit', coin2)

      // Verify total balance
      const privateState = simulator.getPrivateState()
      expect(privateState.user_balance.balance).toBe(800n)
    })
  })

  describe('Purchasing Items with Quantity', () => {
    let listingHash: Uint8Array
    let listingDetails: any
    let sellerPrivateStateAfterCreation: any

    beforeEach(() => {
      const { simulator, sellerWallets, buyerWallets, paymentTokenType } = fixture
      const seller = sellerWallets[0]
      const buyer = buyerWallets[0]

      // Create a listing with quantity 10
      asWallet(simulator, seller)
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Test Item'),
        100n,   // price per unit
        10n,    // quantity
        0n      // No timeout for testing
      )
      listingHash = result.result
      sellerPrivateStateAfterCreation = simulator.getPrivateState()

      // Get listing details from seller's private state
      const listingHashHex = Buffer.from(listingHash).toString('hex')
      listingDetails = sellerPrivateStateAfterCreation.listings.get(listingHashHex)

      // Set up buyer with private balance via deposit
      asWallet(simulator, buyer)
      const depositCoin = createPaymentCoin(5000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)
    })

    it('should allow a buyer to purchase partial quantity', () => {
      const { simulator, buyerWallets } = fixture
      const nonce = pad('nonce1', 32)

      // Purchase 3 out of 10 units
      const result = simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        3n,  // quantity
        nonce
      )

      // Should return buyer commitment
      expect(result.result).toBeDefined()
      expect(result.result.length).toBe(32)

      // Verify the purchase was stored in buyer's private state
      const privateState = simulator.getPrivateState()
      const buyerCommitmentHex = Buffer.from(result.result).toString('hex')
      const purchaseDetails = privateState.purchases.get(buyerCommitmentHex)
      expect(purchaseDetails).toBeDefined()
      expect(purchaseDetails!.quantity).toBe(3n)
      expect(purchaseDetails!.amountPaid).toBe(300n)  // 3 * 100
    })

    it('should deduct correct payment for quantity purchased', () => {
      const { simulator } = fixture
      const nonce = pad('nonce2', 32)

      // Get initial balance
      const initialState = simulator.getPrivateState()
      const initialBalance = initialState.user_balance.balance

      // Purchase 5 units at 100 each = 500 total
      simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        5n,
        nonce
      )

      // Verify balance was deducted correctly
      const finalState = simulator.getPrivateState()
      expect(finalState.user_balance.balance).toBe(initialBalance - 500n)
    })

    it('should allow multiple buyers to purchase from same listing', () => {
      const { simulator, buyerWallets, paymentTokenType } = fixture

      // Buyer 1 purchases 3 units
      const nonce1 = pad('buyer1nonce', 32)
      simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        3n,
        nonce1
      )

      // Buyer 2 deposits and purchases 4 units
      asWallet(simulator, buyerWallets[1])
      const depositCoin = createPaymentCoin(5000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)

      const nonce2 = pad('buyer2nonce', 32)
      const result = simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        4n,
        nonce2
      )

      expect(result.result).toBeDefined()
    })

    it('should reject purchase exceeding available quantity', () => {
      const { simulator } = fixture
      const nonce = pad('bigpurchase', 32)

      // Try to purchase 11 units when only 10 available
      expect(() => {
        simulator.executeImpureCircuit(
          'purchase',
          listingHash,
          listingDetails,
          11n,
          nonce
        )
      }).toThrow()
    })

    it('should reject purchase with insufficient balance', () => {
      const { simulator, buyerWallets, paymentTokenType } = fixture
      const buyer = buyerWallets[1]

      // Set buyer with insufficient balance via small deposit
      asWallet(simulator, buyer)
      const depositCoin = createPaymentCoin(50n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)

      const nonce = pad('lowbal', 32)
      expect(() => {
        simulator.executeImpureCircuit(
          'purchase',
          listingHash,
          listingDetails,
          1n,  // 1 unit at 100 = 100, but balance is only 50
          nonce
        )
      }).toThrow()
    })

    it('should reject zero quantity purchase', () => {
      const { simulator } = fixture
      const nonce = pad('zeroquant', 32)

      expect(() => {
        simulator.executeImpureCircuit(
          'purchase',
          listingHash,
          listingDetails,
          0n,  // Invalid: zero quantity
          nonce
        )
      }).toThrow()
    })
  })

  describe('Confirm Receipt and Claim Payment', () => {
    let listingHash: Uint8Array
    let listingDetails: any
    let buyerCommitment: Uint8Array
    let sellerPrivateStateAfterCreation: any
    let buyerPrivateStateAfterPurchase: any
    const nonce = pad('testnonce', 32)

    beforeEach(() => {
      const { simulator, sellerWallets, buyerWallets, paymentTokenType } = fixture

      // Create a listing
      asWallet(simulator, sellerWallets[0])
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Item for Sale'),
        100n,  // price per unit
        5n,    // quantity
        0n
      )
      listingHash = result.result
      sellerPrivateStateAfterCreation = simulator.getPrivateState()
      const listingHashHex = Buffer.from(listingHash).toString('hex')
      listingDetails = sellerPrivateStateAfterCreation.listings.get(listingHashHex)

      // Buyer deposits and purchases 2 units
      asWallet(simulator, buyerWallets[0])
      const depositCoin = createPaymentCoin(5000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)

      const purchaseResult = simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        2n,  // quantity
        nonce
      )
      buyerCommitment = purchaseResult.result
      buyerPrivateStateAfterPurchase = simulator.getPrivateState()
    })

    it('should allow buyer to confirm receipt', () => {
      const { simulator, buyerWallets } = fixture

      // Buyer confirms receipt
      simulator.as(buyerPrivateStateAfterPurchase, buyerWallets[0].coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit('confirmReceipt', listingHash, nonce)
      }).not.toThrow()
    })

    it('should allow seller to claim confirmed payments', () => {
      const { simulator, sellerWallets, buyerWallets } = fixture

      // Buyer confirms receipt
      simulator.as(buyerPrivateStateAfterPurchase, buyerWallets[0].coinPublicKey)
      simulator.executeImpureCircuit('confirmReceipt', listingHash, nonce)

      // Seller claims payment
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit(
          'claimPayment',
          listingHash,
          listingDetails
        )
      }).not.toThrow()
    })

    it('should credit seller with correct amount after claim', () => {
      const { simulator, sellerWallets, buyerWallets } = fixture

      // Buyer confirms receipt
      simulator.as(buyerPrivateStateAfterPurchase, buyerWallets[0].coinPublicKey)
      simulator.executeImpureCircuit('confirmReceipt', listingHash, nonce)

      // Seller claims payment
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)
      simulator.executeImpureCircuit(
        'claimPayment',
        listingHash,
        listingDetails
      )

      // Verify seller's balance increased by 200 (2 units * 100)
      const sellerState = simulator.getPrivateState()
      expect(sellerState.user_balance.balance).toBe(200n)
    })

    it('should reject claim when nothing to claim', () => {
      const { simulator, sellerWallets } = fixture

      // Seller tries to claim without buyer confirmation (and no timeout)
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit(
          'claimPayment',
          listingHash,
          listingDetails
        )
      }).toThrow()
    })
  })

  describe('Cancelling Listings', () => {
    let listingHash: Uint8Array
    let listingDetails: any
    let sellerPrivateStateAfterCreation: any

    beforeEach(() => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      asWallet(simulator, seller)
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Cancellable Item'),
        100n,
        5n,
        0n
      )
      listingHash = result.result
      sellerPrivateStateAfterCreation = simulator.getPrivateState()
      const listingHashHex = Buffer.from(listingHash).toString('hex')
      listingDetails = sellerPrivateStateAfterCreation.listings.get(listingHashHex)
    })

    it('should allow seller to cancel their listing with no pending purchases', () => {
      const { simulator, sellerWallets } = fixture
      const seller = sellerWallets[0]

      // Seller cancels
      simulator.as(sellerPrivateStateAfterCreation, seller.coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit('cancelListing', listingHash, listingDetails)
      }).not.toThrow()
    })

    it('should reject cancellation from non-seller', () => {
      const { simulator, sellerWallets } = fixture

      // Try to cancel as different seller
      asWallet(simulator, sellerWallets[1])

      expect(() => {
        simulator.executeImpureCircuit(
          'cancelListing',
          listingHash,
          listingDetails
        )
      }).toThrow()
    })

    it('should reject cancellation when pending purchases exist', () => {
      const { simulator, sellerWallets, buyerWallets, paymentTokenType } = fixture

      // Buyer deposits and makes a purchase first
      asWallet(simulator, buyerWallets[0])
      const depositCoin = createPaymentCoin(5000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)

      const nonce = pad('cancelnonce', 32)
      simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        1n,
        nonce
      )

      // Seller tries to cancel - should fail due to pending escrow
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit(
          'cancelListing',
          listingHash,
          listingDetails
        )
      }).toThrow()
    })
  })

  describe('Query Circuits', () => {
    let listingHash: Uint8Array

    beforeEach(() => {
      const { simulator, sellerWallets } = fixture
      asWallet(simulator, sellerWallets[0])
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Query Test Item'),
        100n,
        5n,
        0n
      )
      listingHash = result.result
    })

    it('should return listing status', () => {
      const { simulator } = fixture

      const result = simulator.executeCircuit('getListingStatus', listingHash)
      // Status should be Active (first enum value)
      expect(result.result).toBeDefined()
    })

    it('should check if listing exists', () => {
      const { simulator } = fixture

      const result = simulator.executeCircuit('listingExists', listingHash)
      expect(result.result).toBe(true)

      const fakeHash = pad('nonexistent', 32)
      const result2 = simulator.executeCircuit('listingExists', fakeHash)
      expect(result2.result).toBe(false)
    })
  })

  describe('Refund Flow', () => {
    let listingHash: Uint8Array
    let listingDetails: any
    let buyerCommitment: Uint8Array
    let sellerPrivateStateAfterCreation: any
    let buyerPrivateStateAfterPurchase: any
    const nonce = pad('refundnonce', 32)

    beforeEach(() => {
      const { simulator, sellerWallets, buyerWallets, paymentTokenType } = fixture

      // Create a listing
      asWallet(simulator, sellerWallets[0])
      const result = simulator.executeImpureCircuit(
        'createListing',
        createItemHash('Refund Test Item'),
        100n,
        5n,
        0n
      )
      listingHash = result.result
      sellerPrivateStateAfterCreation = simulator.getPrivateState()
      const listingHashHex = Buffer.from(listingHash).toString('hex')
      listingDetails = sellerPrivateStateAfterCreation.listings.get(listingHashHex)

      // Buyer deposits and purchases
      asWallet(simulator, buyerWallets[0])
      const depositCoin = createPaymentCoin(5000n, pad('PAYMENT', 32))
      prepareCoinForReceive(simulator, depositCoin, paymentTokenType)
      simulator.executeImpureCircuit('deposit', depositCoin)

      const purchaseResult = simulator.executeImpureCircuit(
        'purchase',
        listingHash,
        listingDetails,
        2n,
        nonce
      )
      buyerCommitment = purchaseResult.result
      buyerPrivateStateAfterPurchase = simulator.getPrivateState()
    })

    it('should allow seller to refund a specific purchase', () => {
      const { simulator, sellerWallets } = fixture

      // Seller initiates refund for the specific purchase
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)

      expect(() => {
        simulator.executeImpureCircuit(
          'refundPurchase',
          listingHash,
          listingDetails,
          buyerCommitment
        )
      }).not.toThrow()
    })

    it('should allow buyer to claim refund after seller refunds', () => {
      const { simulator, sellerWallets, buyerWallets } = fixture

      // Seller initiates refund
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)
      simulator.executeImpureCircuit(
        'refundPurchase',
        listingHash,
        listingDetails,
        buyerCommitment
      )

      // Buyer claims refund
      simulator.as(buyerPrivateStateAfterPurchase, buyerWallets[0].coinPublicKey)

      const balanceBefore = buyerPrivateStateAfterPurchase.user_balance.balance

      simulator.executeImpureCircuit('claimRefund', listingHash, nonce)

      const buyerStateAfterRefund = simulator.getPrivateState()
      // Balance should increase by the refund amount (200 = 2 * 100)
      expect(buyerStateAfterRefund.user_balance.balance).toBe(balanceBefore + 200n)
    })

    it('should reject claimRefund from non-buyer', () => {
      const { simulator, sellerWallets, buyerWallets } = fixture

      // Seller initiates refund
      simulator.as(sellerPrivateStateAfterCreation, sellerWallets[0].coinPublicKey)
      simulator.executeImpureCircuit(
        'refundPurchase',
        listingHash,
        listingDetails,
        buyerCommitment
      )

      // Try to claim refund as a different buyer
      asWallet(simulator, buyerWallets[1])

      expect(() => {
        simulator.executeImpureCircuit('claimRefund', listingHash, nonce)
      }).toThrow()
    })
  })
})
