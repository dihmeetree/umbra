import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad,
  type Wallet,
  LegacyCoinBuilder,
  MockGenerators,
  disableLogging
} from '@statera/simulator'

// Disable debug logging for cleaner test output
disableLogging()
import { tokenType, encodeTokenType } from '@midnight-ntwrk/ledger'
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id'
import { encodeCoinPublicKey } from '@midnight-ntwrk/onchain-runtime'
import { sampleContractAddress } from '@midnight-ntwrk/compact-runtime'
import type { TokenType, ContractAddress } from '@midnight-ntwrk/zswap'
import {
  Contract,
  createPrivateStateraState,
  witnesses,
  type StateraPrivateState,
  ledger
} from '../index.js'
import { DebtPositionStatus } from '../managed/adaStateraProtocol/contract/index.cjs'

// Set network ID for testing
setNetworkId(NetworkId.Undeployed)

/**
 * Test fixture containing all necessary components for Ada Statera Protocol testing
 */
export interface StateraTestFixture {
  simulator: ContractSimulator<StateraPrivateState>
  walletManager: WalletManager
  balanceTracker: BalanceTracker
  adminWallet: Wallet
  userWallets: Wallet[]
  contractAddress: ContractAddress
  sSUSDTokenType: TokenType
  sADATokenType: TokenType
  collateralTokenType: TokenType
}

/**
 * Creates a complete test fixture for Ada Statera Protocol
 *
 * @param numUsers - Number of user wallets to create (default: 3)
 * @returns Complete test fixture
 */
export function createStateraTestFixture(
  numUsers: number = 3
): StateraTestFixture {
  // Create wallet manager
  const walletManager = new WalletManager()

  // Create admin wallet
  const adminWallet = walletManager.createWallet('admin')

  // Create user wallets
  const userWallets = walletManager.createWallets(numUsers, 'user')

  // Generate contract address
  const contractAddress = sampleContractAddress()

  // Create token types - MUST match what the contract uses in setSUSDTokenType circuit
  // Contract uses: tokenType(pad(32, "sUSD_token"), kernel.self())
  const sSUSDTokenType = tokenType(pad('sUSD_token', 32), contractAddress)
  const sADATokenType = tokenType(pad('statera:coin:sADA', 32), contractAddress)
  // Collateral token type (ADA)
  const collateralTokenType = tokenType(pad('ADA', 32), contractAddress)

  // Create initial private state for admin
  // IMPORTANT: Pass admin's secret key as BOTH secret_key AND admin_secret
  // This establishes the admin_secret that will be used for all admin metadata hashing
  const adminPrivateState = createPrivateStateraState(
    adminWallet.secretKey,
    adminWallet.secretKey
  )

  // Deploy simulator
  // Note: We pass constructorArgs without nonce since the contract doesn't have a nonce parameter
  const simulator = new ContractSimulator<StateraPrivateState>(
    new Contract(witnesses) as any, // Type assertion needed because contract doesn't have nonce parameter
    {
      contractAddress,
      initialPrivateState: adminPrivateState,
      nonce: generateNonce(), // Not used but required by ContractSimulator
      coinPublicKey: adminWallet.coinPublicKey,
      constructorArgs: [
        80n, // initLiquidationThreshold (80%)
        70n, // initialLVT (70%)
        110n, // initialMCR (110%)
        pad('ADA', 32), // validCollateralAssetType (Bytes<32>)
        50n, // initialRedemptionFee (0.5%)
        50n, // initialBorrowingFee (0.5%)
        5n, // initialLiquidationIncentive (5%)
        100n // initialMinimumDebt (100 sUSD)
      ]
    }
  )

  // After contract initialization, get the updated private state
  // The constructor sets up admin_metadata automatically with the hash
  const initializedState = simulator.getPrivateState()

  // Initialize sUSD token type by calling the circuit
  // This MUST be done before any operations that use sUSD tokens
  asAdmin(simulator, adminWallet).executeImpureCircuit('setSUSDTokenType')

  // Create balance tracker
  const balanceTracker = new BalanceTracker()

  return {
    simulator,
    walletManager,
    balanceTracker,
    adminWallet,
    userWallets,
    contractAddress,
    sSUSDTokenType,
    sADATokenType,
    collateralTokenType
  }
}

/**
 * Helper to create a private state for a wallet
 *
 * IMPORTANT: Always pass the simulator parameter to ensure admin_secret and admin_metadata are propagated!
 * This is required for circuits that update admin metadata (mint_sUSD, redeemSUSD, etc.)
 *
 * @param wallet - The wallet
 * @param simulator - Simulator to get admin_secret and admin_metadata from (REQUIRED for proper functionality)
 * @returns Private state for the wallet
 */
export function createPrivateStateForWallet(
  wallet: Wallet,
  simulator?: ContractSimulator<StateraPrivateState>
): StateraPrivateState {
  if (!simulator) {
    // If no simulator provided, create a basic state (won't work with admin operations)
    return createPrivateStateraState(wallet.secretKey, wallet.secretKey)
  }

  const currentState = simulator.getPrivateState()
  const baseState = createPrivateStateraState(
    wallet.secretKey,
    currentState.admin_secret
  )

  // CRITICAL: Copy admin_metadata from simulator to preserve super_admin and other admin fields
  return {
    ...baseState,
    admin_metadata: currentState.admin_metadata,
    admin_secret: currentState.admin_secret
  }
}

/**
 * Helper to execute a circuit as a specific wallet
 * This ensures both the private state AND the public key context are set correctly
 *
 * IMPORTANT: Use this instead of manually calling .as() to ensure ownPublicKey() works correctly
 *
 * @param simulator - The contract simulator
 * @param wallet - The wallet to execute as
 * @param privateState - Optional custom private state (defaults to basic state for wallet)
 * @returns Simulator configured for the wallet
 */
export function asWallet<T>(
  simulator: ContractSimulator<T>,
  wallet: Wallet,
  privateState?: T
): ContractSimulator<T> {
  // If no private state provided, create one with the admin_secret from simulator
  const currentState = simulator.getPrivateState() as any
  const state =
    privateState ||
    (createPrivateStateraState(
      wallet.secretKey,
      currentState?.admin_secret
    ) as any)
  return simulator.as(state, wallet.coinPublicKey)
}

/**
 * Helper to create a private state for a wallet with mint metadata
 * Use this after deposit to enable mint/withdraw operations
 *
 * @param wallet - The wallet
 * @param collateral - Collateral amount deposited
 * @param debt - Current debt amount (0 for new deposits)
 * @param adminSecret - Optional: the fixed admin secret from contract (get from simulator.getPrivateState().admin_secret)
 * @returns Private state with mint metadata
 */
export function createPrivateStateWithMintMetadata(
  wallet: Wallet,
  collateral: bigint = 1000n,
  debt: bigint = 0n,
  adminSecret?: Uint8Array
): StateraPrivateState {
  const baseState = createPrivateStateraState(wallet.secretKey, adminSecret)

  // Update private state with mint_metadata
  return {
    ...baseState,
    mint_metadata: {
      collateral,
      debt
    }
  }
}

/**
 * Helper to create admin private state with proper metadata from simulator
 * Use this when executing admin circuits that require admin authentication
 *
 * IMPORTANT: After fees have accumulated during user operations (mint_sUSD, redeemSUSD),
 * the admin_metadata in the simulator's private state is kept up-to-date via set_admin_metadata witness.
 *
 * @param simulator - The contract simulator with initialized admin state
 * @param adminWallet - The admin wallet
 * @returns Private state with correct admin metadata
 */
export function createAdminPrivateState(
  simulator: ContractSimulator<StateraPrivateState>,
  adminWallet: Wallet
): StateraPrivateState {
  // Get the current private state
  const currentState = simulator.getPrivateState()

  // Return admin state with admin's secret key but preserving admin_secret from initialization
  return {
    ...currentState,
    secret_key: adminWallet.secretKey,
    admin_secret: currentState.admin_secret // Preserve the fixed admin_secret
  }
}

/**
 * Helper to execute a circuit as admin with proper authentication
 * This ensures both the private state AND the public key context are set correctly for admin circuits
 *
 * IMPORTANT: Admin circuits check ownPublicKey() against adminMetadata.super_admin,
 * so we must pass the admin's coinPublicKey as the second parameter to .as()
 *
 * @param simulator - The contract simulator
 * @param adminWallet - The admin wallet
 * @returns Simulator configured for admin execution
 */
export function asAdmin(
  simulator: ContractSimulator<StateraPrivateState>,
  adminWallet: Wallet
): ContractSimulator<StateraPrivateState> {
  return simulator.as(
    createAdminPrivateState(simulator, adminWallet),
    adminWallet.coinPublicKey
  )
}

/**
 * Helper to print token balances with readable names
 */
export function printBalances(
  balanceTracker: BalanceTracker,
  walletKey: string,
  sSUSDTokenType: TokenType,
  sADATokenType: TokenType
): void {
  const tokenNames = new Map<string, string>([
    [sSUSDTokenType.toString(), 'sSUSD'],
    [sADATokenType.toString(), 'sADA']
  ])

  balanceTracker.printBalances(walletKey, tokenNames)
}

/**
 * Helper to print all balances with readable names
 */
export function printAllBalances(
  balanceTracker: BalanceTracker,
  sSUSDTokenType: TokenType,
  sADATokenType: TokenType
): void {
  const tokenNames = new Map<string, string>([
    [sSUSDTokenType.toString(), 'sSUSD'],
    [sADATokenType.toString(), 'sADA']
  ])

  balanceTracker.printAllBalances(tokenNames)
}

/**
 * Helper to update balances for all wallets in the fixture
 */
export function updateAllBalances(fixture: StateraTestFixture): void {
  const { simulator, balanceTracker, adminWallet, userWallets } = fixture

  // Update admin balance
  balanceTracker.updateFromSimulator(
    simulator,
    adminWallet.coinPublicKey,
    'admin'
  )

  // Update user balances
  userWallets.forEach((wallet, index) => {
    balanceTracker.updateFromSimulator(
      simulator,
      wallet.coinPublicKey,
      `user${index}`
    )
  })
}

/**
 * Creates a user ID from a wallet's secret key
 * This matches the contract's generateUserId function which does:
 * persistentCommit<Bytes<32>>(ownPublicKey().bytes, sk)
 */
export function createUserId(wallet: Wallet): Uint8Array {
  // The contract uses persistentCommit with public key and secret key
  // For testing, we need to replicate this
  // Import the persistentCommit function
  const { persistentCommit } = require('@midnight-ntwrk/compact-runtime')
  const { CompactTypeBytes } = require('@midnight-ntwrk/compact-runtime')

  const publicKeyBytes = encodeCoinPublicKey(wallet.coinPublicKey)
  const descriptor = new CompactTypeBytes(32)

  return persistentCommit(descriptor, publicKeyBytes, wallet.secretKey)
}

/**
 * Creates a metadata hash for testing
 * This is a simplified version for testing
 */
export function createMetadataHash(metadata: any): Uint8Array {
  // In production, this would use proper hashing
  const hash = new Uint8Array(32)
  hash.fill(0)
  return hash
}

/**
 * Creates a mint counter commitment for testing
 */
export function createMintCounterCommitment(counter: bigint): Uint8Array {
  // In production, this would use proper commitment scheme
  const commitment = new Uint8Array(32)
  commitment.fill(0)
  return commitment
}

/**
 * Creates a valid CoinInfo for testing
 *
 * IMPORTANT: For sUSD coins, use 'sUSD_token' as colorName to match contract's setSUSDTokenType
 *
 * @param value - The coin value in smallest units (SPECK)
 * @param colorName - The token type name
 */
export function createMockCoin(value: bigint, colorName: string = 'ADA'): any {
  return {
    nonce: generateNonce(),
    color: pad(colorName, 32),
    value
  }
}

/**
 * Creates a collateral coin for deposit with proper SPECK conversion
 * Contract uses SPECK_per_tDUST = 1000000 for ADA conversions
 *
 * @param amountInADA - Amount in ADA (or collateral token units)
 * @returns CoinInfo with value in SPECK
 */
export function createCollateralCoin(amountInADA: bigint): any {
  const SPECK_per_tDUST = 1000000n
  return LegacyCoinBuilder.create(pad('ADA', 32), amountInADA * SPECK_per_tDUST)
}

/**
 * Creates an sUSD coin with the correct token type color
 * Uses encodeTokenType to ensure the color matches what the contract expects
 *
 * @param value - The coin value in smallest units
 * @param sSUSDTokenType - The sUSD token type from fixture
 * @returns CoinInfo with encoded token type as color
 */
export function createSUSDCoin(value: bigint, sSUSDTokenType: TokenType): any {
  return LegacyCoinBuilder.create(encodeTokenType(sSUSDTokenType), value)
}

/**
 * Converts a hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  // Remove 0x prefix if present
  hex = hex.replace(/^0x/, '')

  // Pad to ensure even length
  if (hex.length % 2 !== 0) {
    hex = '0' + hex
  }

  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }

  // Pad to 32 bytes if needed
  if (bytes.length < 32) {
    const padded = new Uint8Array(32)
    padded.set(bytes)
    return padded
  }

  return bytes.slice(0, 32)
}

/**
 * Creates a mock ComplianceToken (KYC token) for testing
 * Accepts either string (hex) or Uint8Array for userPk
 */
export function createMockComplianceToken(
  userPk: string | Uint8Array,
  oraclePk: Uint8Array
): any {
  const currentTime = BigInt(Math.floor(Date.now() / 1000))

  // Convert userPk to Uint8Array if it's a string
  const userPkBytes = typeof userPk === 'string' ? hexToBytes(userPk) : userPk

  // Use MockGenerators but adapt to our specific format
  // Our contract expects a different structure, so we keep the custom format
  return {
    tokenData: {
      did: pad('mock-did', 32),
      userPk: userPkBytes,
      oraclePk: oraclePk,
      validityRange: {
        duration: 31536000n, // 1 year in seconds
        creationDate: currentTime
      }
    },
    oracleSignature: pad('mock-signature', 32)
  }
}

/**
 * Creates a mock oracle public key
 */
export function createMockOraclePk(): Uint8Array {
  return pad('trusted-oracle-1', 32)
}

/**
 * Prepares a coin for receive() by adding it to the simulator's ZSwap inputs
 * Converts Compact CoinInfo (with color: Bytes<32>) to runtime CoinInfo (with type: TokenType)
 *
 * IMPORTANT: Call this BEFORE executing a circuit that calls receive() on the coin
 *
 * @param simulator - The contract simulator
 * @param mockCoin - The mock coin from createMockCoin() or createCollateralCoin()
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

/**
 * Creates a mock reserve pool coin for testing withdrawal operations
 */
export function createMockReservePoolCoin(
  collateralTokenType: TokenType,
  amount: bigint = 100000000000n
): any {
  return {
    nonce: generateNonce(),
    color: encodeTokenType(collateralTokenType),
    value: amount,
    mt_index: 0n
  }
}

/**
 * Creates a mock stake pool coin for testing staking operations
 */
export function createMockStakePoolCoin(
  sSUSDTokenType: TokenType,
  amount: bigint = 100000000000n
): any {
  return {
    nonce: generateNonce(),
    color: encodeTokenType(sSUSDTokenType),
    value: amount,
    mt_index: 0n
  }
}

/**
 * Helper to get private state after a deposit
 * Much simpler now - just updates the mint_metadata
 *
 * @param simulator - The contract simulator (after deposit)
 * @param wallet - The user's wallet
 * @param depositAmount - Amount deposited
 * @param collateralTokenType - Optional: add reserve pool coin for withdrawals
 * @param sSUSDTokenType - Optional: add stake pool coin for liquidations
 * @returns Private state with mint metadata for subsequent operations
 */
export function getPrivateStateAfterDeposit(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  depositAmount: bigint,
  collateralTokenType?: TokenType,
  sSUSDTokenType?: TokenType
): StateraPrivateState {
  // Get the updated private state from simulator
  const currentState = simulator.getPrivateState()

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    admin_secret: currentState.admin_secret, // Preserve admin_secret from initialization
    admin_metadata: currentState.admin_metadata, // CRITICAL: Preserve admin_metadata including super_admin
    mint_metadata: {
      collateral: depositAmount,
      debt: 0n
    },
    reserve_pool_coin: collateralTokenType
      ? createMockReservePoolCoin(collateralTokenType)
      : currentState.reserve_pool_coin,
    stake_pool_coin: sSUSDTokenType
      ? createMockStakePoolCoin(sSUSDTokenType)
      : currentState.stake_pool_coin
  }
}

/**
 * Helper to get private state after staking
 * Updates the stake_metadata to match what's stored on-chain
 *
 * @param simulator - The contract simulator (after stake)
 * @param wallet - The user's wallet
 * @param stakeAmount - Amount staked (optional - will read from ledger if not provided)
 * @param sSUSDTokenType - Optional: add stake pool coin for withdrawals
 * @param additionalRewards - Optional: simulate additional rewards earned
 * @returns Private state with stake metadata for subsequent operations
 */
export function getPrivateStateAfterStake(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  stakeAmount?: bigint,
  sSUSDTokenType?: TokenType,
  additionalRewards: bigint = 0n
): StateraPrivateState {
  // Get the updated private state from simulator
  const currentState = simulator.getPrivateState()

  // Get the current ledger state to read ADA_sUSD_index and cumulative_scaling_factor
  const ledgerState = simulator.getLedger()

  // Try to read the staker from ledger to get accurate metadata
  const publicKeyBytes = encodeCoinPublicKey(wallet.coinPublicKey)
  const ledgerAccessor = ledger(ledgerState as any)

  let effectiveBalance = stakeAmount || 0n
  let entry_ADA_SUSD_index = ledgerState.ADA_sUSD_index || 0n
  let entry_scale_factor = ledgerState.cumulative_scaling_factor || 1n

  // Try to read from on-chain stakers map
  try {
    if (ledgerAccessor.stakers && ledgerAccessor.stakers.member) {
      const hasStaker = ledgerAccessor.stakers.member(publicKeyBytes)
      if (hasStaker) {
        const stakerRecord = ledgerAccessor.stakers.lookup(publicKeyBytes)
        // The staker exists, use the amount we passed in or fall back to what we know
        effectiveBalance = stakeAmount || effectiveBalance
      }
    }
  } catch (e) {
    // If we can't read from ledger, use the provided amount
  }

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    admin_secret: currentState.admin_secret, // Preserve admin_secret from initialization
    admin_metadata: currentState.admin_metadata, // CRITICAL: Preserve admin_metadata including super_admin
    stake_metadata: {
      effectiveBalance: effectiveBalance,
      stakeReward: additionalRewards,
      entry_ADA_SUSD_index,
      entry_scale_factor
    },
    stake_pool_coin: sSUSDTokenType
      ? createMockStakePoolCoin(sSUSDTokenType)
      : currentState.stake_pool_coin
  }
}
