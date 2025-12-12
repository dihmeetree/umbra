import { WitnessContext } from '@midnight-ntwrk/compact-runtime'
import type { Ledger } from './managed/anonymousMarketplace/contract/index.cjs'

// Type definitions for listing details (matches Compact struct)
export type ListingDetails = {
  listingId: Uint8Array
  itemHash: Uint8Array
  pricePerUnit: bigint
  quantity: bigint
  sellerRandomizer: Uint8Array
}

// Type definitions for purchase details
export type PurchaseDetails = {
  listingHash: Uint8Array
  quantity: bigint
  amountPaid: bigint
  buyerCommitment: Uint8Array
  buyerRandomizer: Uint8Array
}

// Qualified coin info for reserve pool
export type QualifiedCoinInfo = {
  nonce: Uint8Array
  color: Uint8Array
  value: bigint
  mt_index: bigint
}

// User balance with randomizer for commitment scheme
export type UserBalance = {
  balance: bigint
  randomizer: Uint8Array
}

// Private state structure for marketplace users
// Now supports multiple listings and purchases per wallet
export interface MarketplacePrivateState {
  readonly secret_key: Uint8Array
  // Map of listing hash -> listing details (supports multiple listings)
  readonly listings: Map<string, ListingDetails>
  // Map of buyer commitment -> purchase details (supports multiple purchases)
  readonly purchases: Map<string, PurchaseDetails>
  // Map of listing hash -> nullifier (supports multiple listings)
  readonly nullifiers: Map<string, Uint8Array>
  // User's private balance with randomizer for commitment verification
  readonly user_balance: UserBalance
  // Contract's coin pool (for withdrawals and claims)
  readonly contract_coins: QualifiedCoinInfo[]
}

/**
 * Creates an empty user balance
 */
export const createEmptyUserBalance = (): UserBalance => ({
  balance: 0n,
  randomizer: new Uint8Array(32)
})

/**
 * Creates a fresh marketplace private state
 */
export const createMarketplacePrivateState = (
  secret_key: Uint8Array
): MarketplacePrivateState => ({
  secret_key,
  listings: new Map(),
  purchases: new Map(),
  nullifiers: new Map(),
  user_balance: createEmptyUserBalance(),
  contract_coins: []
})

/**
 * Creates an empty listing details object
 */
export const createEmptyListingDetails = (): ListingDetails => ({
  listingId: new Uint8Array(32),
  itemHash: new Uint8Array(32),
  pricePerUnit: 0n,
  quantity: 0n,
  sellerRandomizer: new Uint8Array(32)
})

/**
 * Creates an empty purchase details object
 */
export const createEmptyPurchaseDetails = (): PurchaseDetails => ({
  listingHash: new Uint8Array(32),
  quantity: 0n,
  amountPaid: 0n,
  buyerCommitment: new Uint8Array(32),
  buyerRandomizer: new Uint8Array(32)
})

// Helper to convert Uint8Array to hex string for map keys
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex')

// Witness functions for the anonymous marketplace contract
export const witnesses = {
  /**
   * Returns the user's secret key stored off-chain in their private state
   */
  secret_key: ({
    privateState
  }: WitnessContext<any, MarketplacePrivateState>): [
    MarketplacePrivateState,
    Uint8Array
  ] => {
    if (!privateState || !privateState.secret_key) {
      throw new Error('Secret key not found in private state')
    }
    return [privateState, privateState.secret_key]
  },

  /**
   * Returns listing details by listing hash
   */
  get_listing_details_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    listingHash: Uint8Array
  ): [MarketplacePrivateState, ListingDetails] => {
    const key = toHex(listingHash)
    const details = privateState.listings.get(key)
    if (!details) {
      return [privateState, createEmptyListingDetails()]
    }
    return [privateState, details]
  },

  /**
   * Stores listing details by listing hash
   */
  set_listing_details_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    listingHash: Uint8Array,
    details: ListingDetails
  ): [MarketplacePrivateState, []] => {
    const key = toHex(listingHash)
    const newListings = new Map(privateState.listings)
    newListings.set(key, details)

    const newPrivateState: MarketplacePrivateState = {
      ...privateState,
      listings: newListings
    }

    return [newPrivateState, []]
  },

  /**
   * Returns purchase details by buyer commitment (unique per purchase)
   */
  get_purchase_details_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    buyerCommitment: Uint8Array
  ): [MarketplacePrivateState, PurchaseDetails] => {
    const key = toHex(buyerCommitment)
    const details = privateState.purchases.get(key)
    if (!details) {
      return [privateState, createEmptyPurchaseDetails()]
    }
    return [privateState, details]
  },

  /**
   * Stores purchase details by buyer commitment (unique per purchase)
   */
  set_purchase_details_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    buyerCommitment: Uint8Array,
    details: PurchaseDetails
  ): [MarketplacePrivateState, []] => {
    const key = toHex(buyerCommitment)
    const newPurchases = new Map(privateState.purchases)
    newPurchases.set(key, details)

    const newPrivateState: MarketplacePrivateState = {
      ...privateState,
      purchases: newPurchases
    }

    return [newPrivateState, []]
  },

  /**
   * Returns the nullifier for a specific listing
   */
  get_listing_nullifier_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    listingHash: Uint8Array
  ): [MarketplacePrivateState, Uint8Array] => {
    const key = toHex(listingHash)
    const nullifier = privateState.nullifiers.get(key)
    if (!nullifier) {
      return [privateState, new Uint8Array(32)]
    }
    return [privateState, nullifier]
  },

  /**
   * Stores the nullifier for a specific listing
   */
  set_listing_nullifier_by_hash: (
    { privateState }: WitnessContext<any, MarketplacePrivateState>,
    listingHash: Uint8Array,
    nullifier: Uint8Array
  ): [MarketplacePrivateState, []] => {
    const key = toHex(listingHash)
    const newNullifiers = new Map(privateState.nullifiers)
    newNullifiers.set(key, nullifier)

    const newPrivateState: MarketplacePrivateState = {
      ...privateState,
      nullifiers: newNullifiers
    }

    return [newPrivateState, []]
  },

  /**
   * Returns the user's balance with randomizer for commitment verification
   */
  get_user_balance: ({
    privateState
  }: WitnessContext<Ledger, MarketplacePrivateState>): [
    MarketplacePrivateState,
    UserBalance
  ] => {
    return [privateState, privateState.user_balance]
  },

  /**
   * Stores the user's balance with randomizer
   */
  set_user_balance: (
    { privateState }: WitnessContext<Ledger, MarketplacePrivateState>,
    balance: UserBalance
  ): [MarketplacePrivateState, []] => {
    const newPrivateState: MarketplacePrivateState = {
      ...privateState,
      user_balance: balance
    }

    return [newPrivateState, []]
  },

  /**
   * Returns a coin from the contract's coin pool for withdrawals
   * The coin's color must match the ledger's platformTokenType
   */
  get_contract_coin: ({
    privateState,
    ledger
  }: WitnessContext<Ledger, MarketplacePrivateState>): [
    MarketplacePrivateState,
    QualifiedCoinInfo
  ] => {
    // Get the platform token type from the ledger
    const platformTokenType = ledger.platformTokenType

    // Find a suitable coin from the contract's coin pool
    const coins = privateState.contract_coins || []

    // Find a coin with matching color
    const matchingCoin = coins.find(coin =>
      coin.color.length === platformTokenType.length &&
      coin.color.every((v, i) => v === platformTokenType[i])
    )

    if (matchingCoin) {
      return [privateState, matchingCoin]
    }

    // Return a default coin if none found (will fail validation in contract)
    return [privateState, {
      nonce: new Uint8Array(32),
      color: platformTokenType,
      value: 0n,
      mt_index: 0n
    }]
  },

}

// Helper to get a specific listing from private state by hash
export function getListingByHash(
  privateState: MarketplacePrivateState,
  listingHash: Uint8Array
): ListingDetails | null {
  const key = toHex(listingHash)
  return privateState.listings.get(key) || null
}

// Helper to get a specific purchase from private state by buyer commitment
export function getPurchaseByBuyerCommitment(
  privateState: MarketplacePrivateState,
  buyerCommitment: Uint8Array
): PurchaseDetails | null {
  const key = toHex(buyerCommitment)
  return privateState.purchases.get(key) || null
}

// Helper to list all listings in private state
export function getAllListings(
  privateState: MarketplacePrivateState
): ListingDetails[] {
  return Array.from(privateState.listings.values())
}

// Helper to list all purchases in private state
export function getAllPurchases(
  privateState: MarketplacePrivateState
): PurchaseDetails[] {
  return Array.from(privateState.purchases.values())
}
