import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad,
  type Wallet,
  LegacyCoinBuilder,
  disableLogging
} from '@statera/simulator'

// Disable debug logging for cleaner test output
disableLogging()

import { tokenType, encodeTokenType } from '@midnight-ntwrk/ledger'
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id'
import { sampleContractAddress } from '@midnight-ntwrk/compact-runtime'
import type { TokenType, ContractAddress } from '@midnight-ntwrk/zswap'
import {
  Contract,
  witnesses,
  createMarketplacePrivateState,
  type MarketplacePrivateState,
  type ListingDetails
} from '../index.js'

// Set network ID for testing
setNetworkId(NetworkId.Undeployed)

/**
 * Test fixture for Anonymous Marketplace testing
 */
export interface MarketplaceTestFixture {
  simulator: ContractSimulator<MarketplacePrivateState>
  walletManager: WalletManager
  balanceTracker: BalanceTracker
  sellerWallets: Wallet[]
  buyerWallets: Wallet[]
  contractAddress: ContractAddress
  paymentTokenType: TokenType
}

/**
 * Creates a test fixture for the Anonymous Marketplace
 *
 * @param numSellers - Number of seller wallets to create (default: 2)
 * @param numBuyers - Number of buyer wallets to create (default: 3)
 * @returns Complete test fixture
 */
export function createMarketplaceTestFixture(
  numSellers: number = 2,
  numBuyers: number = 3
): MarketplaceTestFixture {
  const walletManager = new WalletManager()

  // Create seller wallets
  const sellerWallets = walletManager.createWallets(numSellers, 'seller')

  // Create buyer wallets
  const buyerWallets = walletManager.createWallets(numBuyers, 'buyer')

  // Generate contract address
  const contractAddress = sampleContractAddress()

  // Create payment token type
  const paymentTokenType = tokenType(pad('PAYMENT', 32), contractAddress)

  // Create initial private state for the first seller (deployer)
  const deployerPrivateState = createMarketplacePrivateState(
    sellerWallets[0].secretKey
  )

  // Deploy simulator with the compiled contract
  const simulator = new ContractSimulator<MarketplacePrivateState>(
    new Contract(witnesses) as any,
    {
      contractAddress,
      initialPrivateState: deployerPrivateState,
      nonce: generateNonce(),
      coinPublicKey: sellerWallets[0].coinPublicKey,
      constructorArgs: [pad('PAYMENT', 32)]
    }
  )

  // Create balance tracker
  const balanceTracker = new BalanceTracker()

  return {
    simulator,
    walletManager,
    balanceTracker,
    sellerWallets,
    buyerWallets,
    contractAddress,
    paymentTokenType
  }
}

/**
 * Helper to create private state for a wallet
 */
export function createPrivateStateForWallet(
  wallet: Wallet
): MarketplacePrivateState {
  return createMarketplacePrivateState(wallet.secretKey)
}

/**
 * Helper to switch simulator context to a specific wallet
 */
export function asWallet(
  simulator: ContractSimulator<MarketplacePrivateState>,
  wallet: Wallet
): ContractSimulator<MarketplacePrivateState> {
  return simulator.as(
    createPrivateStateForWallet(wallet),
    wallet.coinPublicKey
  )
}

/**
 * Creates a mock payment coin
 * The color must match the paymentTokenType used in the listing (Bytes<32>)
 */
export function createPaymentCoin(
  value: bigint,
  paymentTokenColor: Uint8Array = pad('PAYMENT', 32)
): any {
  return LegacyCoinBuilder.create(paymentTokenColor, value)
}

/**
 * Helper to get listing details from seller's private state
 */
export function getListingFromPrivateState(
  simulator: ContractSimulator<MarketplacePrivateState>
): ListingDetails | null {
  return simulator.getPrivateState().listing_details
}

/**
 * Helper to generate a mock item hash
 */
export function createItemHash(description: string): Uint8Array {
  return pad(description, 32)
}

/**
 * Prepares a coin for receive() by adding it to the simulator's ZSwap inputs
 *
 * @param simulator - The contract simulator
 * @param mockCoin - The mock coin from createPaymentCoin()
 * @param tokenType - The token type for this coin
 */
export function prepareCoinForReceive<T>(
  simulator: ContractSimulator<T>,
  mockCoin: any,
  tokenType: TokenType
): void {
  // Convert the Compact CoinInfo (with color) to runtime CoinInfo (with type)
  const runtimeCoin: any = {
    type: tokenType,
    nonce: mockCoin.nonce,
    value: mockCoin.value
  }

  // Add to simulator inputs so receive() can find it
  simulator.addCoinInput(runtimeCoin)
}
