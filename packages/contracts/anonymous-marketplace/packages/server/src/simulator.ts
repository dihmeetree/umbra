import {
  ContractSimulator,
  WalletManager,
  generateNonce,
  pad,
  type Wallet,
  LegacyCoinBuilder
} from '@statera/simulator'
import { tokenType } from '@midnight-ntwrk/ledger'
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id'
import { sampleContractAddress } from '@midnight-ntwrk/compact-runtime'
import type { TokenType, ContractAddress } from '@midnight-ntwrk/zswap'

// Import from the built dist - the workspace package
import {
  Contract,
  witnesses,
  createMarketplacePrivateState,
  type MarketplacePrivateState,
  type ListingDetails
} from '@statera/anonymous-marketplace'

// Set network ID
setNetworkId(NetworkId.Undeployed)

export interface StoredWallet {
  name: string
  wallet: Wallet
  coinPublicKey: string
  privateState: MarketplacePrivateState
  privateBalance: bigint  // pUSDM balance (private tokens)
  publicBalance: bigint   // USDM balance (public tokens, for depositing)
}

export interface StoredListing {
  listingHash: string
  itemDescription: string
  pricePerUnit: string
  quantity: string
  remainingQuantity: string
  escrowDeadline: string  // Unix timestamp string
  status: 'Active' | 'Sold' | 'Completed' | 'Claimed' | 'Cancelled' | 'Refunded'
  sellerWallet: string
  details: ListingDetails
}

// Serializable version for API responses (no BigInt or Uint8Array)
export interface SerializableListing {
  listingHash: string
  itemDescription: string
  pricePerUnit: string
  quantity: string
  remainingQuantity: string
  escrowDeadline: string
  status: 'Active' | 'Sold' | 'Completed' | 'Claimed' | 'Cancelled' | 'Refunded'
}

function toSerializableListing(listing: StoredListing): SerializableListing {
  return {
    listingHash: listing.listingHash,
    itemDescription: listing.itemDescription,
    pricePerUnit: listing.pricePerUnit,
    quantity: listing.quantity,
    remainingQuantity: listing.remainingQuantity,
    escrowDeadline: listing.escrowDeadline,
    status: listing.status
  }
}

// Serializable version of ListingDetails for API
export interface SerializableListingDetails {
  listingId: string
  itemHash: string
  pricePerUnit: string
  quantity: string
  sellerRandomizer: string
}

function toSerializableListingDetails(details: ListingDetails): SerializableListingDetails {
  return {
    listingId: Buffer.from(details.listingId).toString('hex'),
    itemHash: Buffer.from(details.itemHash).toString('hex'),
    pricePerUnit: details.pricePerUnit.toString(),
    quantity: details.quantity.toString(),
    sellerRandomizer: Buffer.from(details.sellerRandomizer).toString('hex')
  }
}

function fromSerializableListingDetails(details: SerializableListingDetails): ListingDetails {
  return {
    listingId: Buffer.from(details.listingId, 'hex'),
    itemHash: Buffer.from(details.itemHash, 'hex'),
    pricePerUnit: BigInt(details.pricePerUnit),
    quantity: BigInt(details.quantity),
    sellerRandomizer: Buffer.from(details.sellerRandomizer, 'hex')
  }
}

export interface StoredPurchase {
  listingHash: string
  itemDescription: string
  pricePerUnit: string
  quantity: string
  totalPrice: string
  purchasedAt: number
  status: 'Pending' | 'Confirmed' | 'Refunded'
  buyerCommitment: string
  nonce: string
}

/**
 * MarketplaceSimulator wraps the contract simulator and provides
 * a simplified API for the HTTP server
 */
export class MarketplaceSimulator {
  private simulator: ContractSimulator<MarketplacePrivateState>
  private walletManager: WalletManager
  private wallets: Map<string, StoredWallet> = new Map()
  private listings: Map<string, StoredListing> = new Map()
  private purchases: Map<string, StoredPurchase[]> = new Map()
  private contractAddress: ContractAddress
  private paymentTokenType: TokenType
  private reservePoolBalance: bigint = 0n  // Track total deposits in reserve pool

  constructor() {
    this.walletManager = new WalletManager()
    this.contractAddress = sampleContractAddress()
    this.paymentTokenType = tokenType(pad('PAYMENT', 32), this.contractAddress)

    // Create initial deployer wallet
    const deployerWallet = this.walletManager.createWallet('deployer')
    const deployerPrivateState = createMarketplacePrivateState(deployerWallet.secretKey)

    // Deploy the contract
    this.simulator = new ContractSimulator<MarketplacePrivateState>(
      new Contract(witnesses) as any,
      {
        contractAddress: this.contractAddress,
        initialPrivateState: deployerPrivateState,
        nonce: generateNonce(),
        coinPublicKey: deployerWallet.coinPublicKey,
        constructorArgs: [pad('PAYMENT', 32)]
      }
    )

    const INITIAL_PUBLIC_BALANCE = 10000n // Give each wallet 10000 public tokens to start

    // Store deployer wallet
    this.wallets.set('deployer', {
      name: 'deployer',
      wallet: deployerWallet,
      coinPublicKey: deployerWallet.coinPublicKey,
      privateState: deployerPrivateState,
      privateBalance: 0n,  // No private balance initially
      publicBalance: INITIAL_PUBLIC_BALANCE
    })
  }

  /**
   * Create a new wallet with initial public balance (for depositing)
   */
  createWallet(name: string): StoredWallet {
    if (this.wallets.has(name)) {
      throw new Error(`Wallet "${name}" already exists`)
    }

    const INITIAL_PUBLIC_BALANCE = 10000n // Give each wallet 10000 public tokens to start

    const wallet = this.walletManager.createWallet(name)
    const privateState = createMarketplacePrivateState(wallet.secretKey)

    const storedWallet: StoredWallet = {
      name,
      wallet,
      coinPublicKey: wallet.coinPublicKey,
      privateState,
      privateBalance: 0n,  // No private balance initially - must deposit
      publicBalance: INITIAL_PUBLIC_BALANCE
    }

    this.wallets.set(name, storedWallet)
    return storedWallet
  }

  /**
   * Deposit public USDM tokens to receive private pUSDM balance
   */
  deposit(walletName: string, amount: bigint): { newPrivateBalance: bigint; newPublicBalance: bigint } {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new Error(`Wallet "${walletName}" not found`)
    }

    if (wallet.publicBalance < amount) {
      throw new Error(`Insufficient public balance. Have ${wallet.publicBalance}, need ${amount}`)
    }

    // Switch to wallet context
    this.asWallet(wallet)

    // Create the deposit coin
    const depositCoin = LegacyCoinBuilder.create(pad('PAYMENT', 32), amount)

    // Prepare coin for receive
    const runtimeCoin: any = {
      type: this.paymentTokenType,
      nonce: depositCoin.nonce,
      value: depositCoin.value
    }
    this.simulator.addCoinInput(runtimeCoin)

    // Execute deposit circuit
    this.simulator.executeImpureCircuit('deposit', depositCoin)

    // Update wallet state
    wallet.privateState = this.simulator.getPrivateState()
    wallet.publicBalance -= amount
    wallet.privateBalance += amount

    return {
      newPrivateBalance: wallet.privateBalance,
      newPublicBalance: wallet.publicBalance
    }
  }

  /**
   * Withdraw private pUSDM to receive public USDM tokens
   */
  withdraw(walletName: string, amount: bigint): { newPrivateBalance: bigint; newPublicBalance: bigint } {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new Error(`Wallet "${walletName}" not found`)
    }

    if (wallet.privateBalance < amount) {
      throw new Error(`Insufficient private balance. Have ${wallet.privateBalance}, need ${amount}`)
    }

    // Switch to wallet context
    this.asWallet(wallet)

    // Execute withdraw circuit
    this.simulator.executeImpureCircuit('withdraw', amount)

    // Update wallet state
    wallet.privateState = this.simulator.getPrivateState()
    wallet.privateBalance -= amount
    wallet.publicBalance += amount

    return {
      newPrivateBalance: wallet.privateBalance,
      newPublicBalance: wallet.publicBalance
    }
  }

  /**
   * Get wallet's private balance
   */
  getPrivateBalance(walletName: string): bigint {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new Error(`Wallet "${walletName}" not found`)
    }
    return wallet.privateBalance
  }

  /**
   * Get a wallet by name
   */
  getWallet(name: string): StoredWallet | undefined {
    return this.wallets.get(name)
  }

  /**
   * List all wallets
   */
  listWallets(): StoredWallet[] {
    return Array.from(this.wallets.values())
  }

  /**
   * Switch simulator context to a specific wallet
   */
  private asWallet(storedWallet: StoredWallet): void {
    this.simulator.as(storedWallet.privateState, storedWallet.wallet.coinPublicKey)
  }

  /**
   * Create a new listing with quantity support
   * @param pricePerUnit - Price per unit in smallest token units
   * @param quantity - Total quantity available for sale
   * @param escrowDeadline - Unix timestamp (seconds) after which seller can claim without buyer confirmation. 0 = no timeout.
   */
  createListing(
    walletName: string,
    itemDescription: string,
    pricePerUnit: bigint,
    quantity: bigint = 1n,
    escrowDeadline: bigint = 0n
  ): { listingHash: string; details: ListingDetails } {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new Error(`Wallet "${walletName}" not found`)
    }

    // Switch to seller context
    this.asWallet(wallet)

    // Create item hash from description
    const itemHash = pad(itemDescription, 32)

    // Execute createListing circuit with quantity and escrowDeadline
    const result = this.simulator.executeImpureCircuit(
      'createListing',
      itemHash,
      pricePerUnit,
      quantity,
      escrowDeadline
    )

    const listingHash = Buffer.from(result.result).toString('hex')

    // Get listing details from updated private state
    const updatedPrivateState = this.simulator.getPrivateState()
    // Get the details from the listings map using the listing hash
    const listingHashKey = listingHash
    const details = updatedPrivateState.listings.get(listingHashKey)!

    // Update wallet's private state
    wallet.privateState = updatedPrivateState

    // Store listing
    const storedListing: StoredListing = {
      listingHash,
      itemDescription,
      pricePerUnit: pricePerUnit.toString(),
      quantity: quantity.toString(),
      remainingQuantity: quantity.toString(),
      escrowDeadline: escrowDeadline.toString(),
      status: 'Active',
      sellerWallet: walletName,
      details
    }
    this.listings.set(listingHash, storedListing)

    return { listingHash, details }
  }

  /**
   * Get a listing by hash (returns serializable version for API)
   */
  getListing(listingHash: string): SerializableListing | undefined {
    const listing = this.listings.get(listingHash)
    return listing ? toSerializableListing(listing) : undefined
  }

  /**
   * Get listing details for a buyer (simulates seller sharing details)
   * Returns serializable version for API
   */
  getListingDetails(
    listingHash: string,
    sellerWalletName: string
  ): SerializableListingDetails | null {
    const listing = this.listings.get(listingHash)
    if (!listing || listing.sellerWallet !== sellerWalletName) {
      return null
    }
    return toSerializableListingDetails(listing.details)
  }

  /**
   * Get all listings for a wallet (returns serializable version for API)
   */
  getWalletListings(walletName: string): SerializableListing[] {
    return Array.from(this.listings.values())
      .filter((l) => l.sellerWallet === walletName)
      .map(toSerializableListing)
  }

  /**
   * Purchase a listing using private balance (pUSDM)
   * Supports partial quantity purchases
   * @param purchaseQuantity - How many units to purchase (defaults to 1)
   * @param nonce - Unique nonce for this purchase (allows multiple purchases from same buyer)
   */
  purchaseListing(
    listingHash: string,
    buyerWalletName: string,
    serializableDetails: SerializableListingDetails,
    purchaseQuantity: bigint = 1n,
    nonce?: string
  ): { success: boolean; buyerCommitment: string; nonce: string } {
    const buyerWallet = this.wallets.get(buyerWalletName)
    if (!buyerWallet) {
      throw new Error(`Wallet "${buyerWalletName}" not found`)
    }

    const listing = this.listings.get(listingHash)
    if (!listing) {
      throw new Error('Listing not found')
    }

    if (listing.status !== 'Active') {
      throw new Error(`Listing is not active (status: ${listing.status})`)
    }

    const remainingQty = BigInt(listing.remainingQuantity)
    if (purchaseQuantity > remainingQty) {
      throw new Error(`Insufficient quantity. Requested ${purchaseQuantity}, available ${remainingQty}`)
    }

    const pricePerUnit = BigInt(listing.pricePerUnit)
    const totalPrice = pricePerUnit * purchaseQuantity

    // Check buyer has sufficient private balance
    if (buyerWallet.privateBalance < totalPrice) {
      throw new Error(`Insufficient private balance. Have ${buyerWallet.privateBalance}, need ${totalPrice}. Deposit funds first.`)
    }

    // Convert serializable details back to ListingDetails
    const listingDetails = fromSerializableListingDetails(serializableDetails)

    // Generate nonce if not provided
    const purchaseNonce = nonce || Buffer.from(generateNonce()).toString('hex')
    const nonceBytes = pad(purchaseNonce, 32)

    // Switch to buyer context
    this.asWallet(buyerWallet)

    // Execute purchase with quantity and nonce
    const listingHashBytes = Buffer.from(listingHash, 'hex')
    const result = this.simulator.executeImpureCircuit(
      'purchase',
      listingHashBytes,
      listingDetails,
      purchaseQuantity,
      nonceBytes
    )

    // Get the buyer commitment from the result
    const buyerCommitment = Buffer.from(result.result).toString('hex')

    // Update buyer's private state
    buyerWallet.privateState = this.simulator.getPrivateState()

    // Update balances - buyer's private balance decreases
    buyerWallet.privateBalance -= totalPrice

    // Update listing quantity
    const newRemainingQty = remainingQty - purchaseQuantity
    listing.remainingQuantity = newRemainingQty.toString()

    // If quantity reaches 0, mark as Sold
    if (newRemainingQty === 0n) {
      listing.status = 'Sold'
    }

    // Store purchase
    const walletPurchases = this.purchases.get(buyerWalletName) || []
    walletPurchases.push({
      listingHash,
      itemDescription: listing.itemDescription,
      pricePerUnit: listing.pricePerUnit,
      quantity: purchaseQuantity.toString(),
      totalPrice: totalPrice.toString(),
      purchasedAt: Date.now(),
      status: 'Pending',
      buyerCommitment,
      nonce: purchaseNonce
    })
    this.purchases.set(buyerWalletName, walletPurchases)

    return {
      success: true,
      buyerCommitment,
      nonce: purchaseNonce
    }
  }

  /**
   * Buyer confirms receipt of item (releases funds to seller)
   * @param nonce - The nonce used when making the purchase
   */
  confirmReceipt(listingHash: string, buyerWalletName: string, nonce: string): void {
    const buyerWallet = this.wallets.get(buyerWalletName)
    if (!buyerWallet) {
      throw new Error(`Wallet "${buyerWalletName}" not found`)
    }

    const listing = this.listings.get(listingHash)
    if (!listing) {
      throw new Error('Listing not found')
    }

    // Find the purchase by nonce
    const walletPurchases = this.purchases.get(buyerWalletName) || []
    const purchase = walletPurchases.find(p => p.listingHash === listingHash && p.nonce === nonce)
    if (!purchase) {
      throw new Error('Purchase not found for this wallet')
    }

    if (purchase.status !== 'Pending') {
      throw new Error(`Cannot confirm receipt for purchase with status: ${purchase.status}`)
    }

    // Switch to buyer context
    this.simulator.as(buyerWallet.privateState, buyerWallet.wallet.coinPublicKey)

    // Execute confirmReceipt circuit with nonce
    const listingHashBytes = Buffer.from(listingHash, 'hex')
    const nonceBytes = pad(nonce, 32)
    this.simulator.executeImpureCircuit(
      'confirmReceipt',
      listingHashBytes,
      nonceBytes
    )

    // Update purchase status to Confirmed
    purchase.status = 'Confirmed'

    // Update buyer's private state
    buyerWallet.privateState = this.simulator.getPrivateState()
  }

  /**
   * Claim payment for a listing (seller receives pUSDM)
   * Claims all confirmed payment amounts for this listing.
   * Can also claim escrowed amounts after timeout passes.
   */
  claimPayment(listingHash: string, sellerWalletName: string): void {
    const sellerWallet = this.wallets.get(sellerWalletName)
    if (!sellerWallet) {
      throw new Error(`Wallet "${sellerWalletName}" not found`)
    }

    const listing = this.listings.get(listingHash)
    if (!listing) {
      throw new Error('Listing not found')
    }

    if (listing.sellerWallet !== sellerWalletName) {
      throw new Error('Only the seller can claim payment')
    }

    // Calculate total claimable amount from all confirmed purchases
    const allPurchases = Array.from(this.purchases.values()).flat()
    const confirmedPurchases = allPurchases.filter(
      p => p.listingHash === listingHash && p.status === 'Confirmed'
    )

    if (confirmedPurchases.length === 0) {
      throw new Error('No confirmed payments to claim')
    }

    const claimableAmount = confirmedPurchases.reduce(
      (sum, p) => sum + BigInt(p.totalPrice),
      0n
    )

    // Switch to seller context
    this.simulator.as(sellerWallet.privateState, sellerWallet.wallet.coinPublicKey)

    // Execute claimPayment circuit
    const listingHashBytes = Buffer.from(listingHash, 'hex')
    this.simulator.executeImpureCircuit(
      'claimPayment',
      listingHashBytes,
      listing.details
    )

    // Update listing status if all quantity sold
    if (listing.remainingQuantity === '0') {
      listing.status = 'Claimed'
    }

    // Credit seller's private balance
    sellerWallet.privateBalance += claimableAmount

    // Update seller's private state
    sellerWallet.privateState = this.simulator.getPrivateState()
  }

  /**
   * Mark a listing as claimed (alias for claimPayment for backwards compatibility)
   */
  markAsClaimed(listingHash: string, sellerWalletName: string): void {
    this.claimPayment(listingHash, sellerWalletName)
  }

  /**
   * Cancel a listing
   */
  cancelListing(listingHash: string, sellerWalletName: string): void {
    const sellerWallet = this.wallets.get(sellerWalletName)
    if (!sellerWallet) {
      throw new Error(`Wallet "${sellerWalletName}" not found`)
    }

    const listing = this.listings.get(listingHash)
    if (!listing) {
      throw new Error('Listing not found')
    }

    if (listing.sellerWallet !== sellerWalletName) {
      throw new Error('Only the seller can cancel a listing')
    }

    if (listing.status !== 'Active') {
      throw new Error(`Cannot cancel listing with status: ${listing.status}`)
    }

    // Switch to seller context
    this.simulator.as(sellerWallet.privateState, sellerWallet.wallet.coinPublicKey)

    // Execute cancelListing
    const listingHashBytes = Buffer.from(listingHash, 'hex')
    this.simulator.executeImpureCircuit(
      'cancelListing',
      listingHashBytes,
      listing.details
    )

    // Update listing status
    listing.status = 'Cancelled'

    // Update seller's private state
    sellerWallet.privateState = this.simulator.getPrivateState()
  }

  /**
   * Get purchases for a wallet
   */
  getWalletPurchases(walletName: string): StoredPurchase[] {
    return this.purchases.get(walletName) || []
  }

  /**
   * Get marketplace stats
   */
  getStats(): {
    totalWallets: number
    totalListings: number
    activeListings: number
    totalSales: number
  } {
    const allListings = Array.from(this.listings.values())
    return {
      totalWallets: this.wallets.size,
      totalListings: allListings.length,
      activeListings: allListings.filter((l) => l.status === 'Active').length,
      totalSales: allListings.filter(
        (l) => l.status === 'Sold' || l.status === 'Claimed'
      ).length
    }
  }
}
