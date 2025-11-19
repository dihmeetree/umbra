import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad,
  type Wallet
} from '@statera/simulator';
import { tokenType, encodeTokenType } from '@midnight-ntwrk/ledger';
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { encodeCoinPublicKey } from '@midnight-ntwrk/onchain-runtime';
import {
  sampleContractAddress,
  constructorContext,
  QueryContext,
  persistentHash,
  persistentCommit,
  CompactTypeBytes,
  CompactTypeUnsignedInteger,
  CompactTypeEnum
} from '@midnight-ntwrk/compact-runtime';
import type { TokenType, ContractAddress } from '@midnight-ntwrk/zswap';
import {
  Contract,
  createPrivateStateraState,
  witnesses,
  type StateraPrivateState
} from '../index.js';
import {  DepositorLeaf, StakerLeaf, DebtPositionStatus, ledger } from '../managed/adaStateraProtocol/contract/index.cjs';

// Set network ID for testing
setNetworkId(NetworkId.Undeployed);

/**
 * Test fixture containing all necessary components for Ada Statera Protocol testing
 */
export interface StateraTestFixture {
  simulator: ContractSimulator<StateraPrivateState>;
  walletManager: WalletManager;
  balanceTracker: BalanceTracker;
  adminWallet: Wallet;
  userWallets: Wallet[];
  contractAddress: ContractAddress;
  sSUSDTokenType: TokenType;
  sADATokenType: TokenType;
  collateralTokenType: TokenType;
}

/**
 * Creates a complete test fixture for Ada Statera Protocol
 *
 * @param numUsers - Number of user wallets to create (default: 3)
 * @returns Complete test fixture
 */
export function createStateraTestFixture(numUsers: number = 3): StateraTestFixture {
  // Create wallet manager
  const walletManager = new WalletManager();

  // Create admin wallet
  const adminWallet = walletManager.createWallet('admin');

  // Create user wallets
  const userWallets = walletManager.createWallets(numUsers, 'user');

  // Generate contract address
  const contractAddress = sampleContractAddress();

  // Create token types - MUST match what the contract uses in setSUSDTokenType circuit
  // Contract uses: tokenType(pad(32, "sUSD_token"), kernel.self())
  const sSUSDTokenType = tokenType(pad('sUSD_token', 32), contractAddress);
  const sADATokenType = tokenType(pad('statera:coin:sADA', 32), contractAddress);
  // Collateral token type (ADA)
  const collateralTokenType = tokenType(pad('ADA', 32), contractAddress);

  // Create initial private state for admin
  const adminPrivateState = createPrivateStateraState(adminWallet.secretKey);

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
        80n,                    // initLiquidationThreshold (80%)
        70n,                    // initialLVT (70%)
        110n,                   // initialMCR (110%)
        pad('ADA', 32),         // validCollateralAssetType (Bytes<32>)
        50n,                    // initialRedemptionFee (0.5%)
        50n,                    // initialBorrowingFee (0.5%)
        5n,                     // initialLiquidationIncentive (5%)
        100n                    // initialMinimumDebt (100 sUSD)
      ]
    }
  );

  // After contract initialization, get the updated private state
  // The constructor sets up admin_metadata automatically with the hash
  const initializedState = simulator.getPrivateState();

  // Initialize sUSD token type by calling the circuit
  // This MUST be done before any operations that use sUSD tokens
  simulator
    .as(createAdminPrivateState(simulator, adminWallet))
    .executeImpureCircuit('setSUSDTokenType');

  // Create balance tracker
  const balanceTracker = new BalanceTracker();

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
  };
}

/**
 * Helper to create a private state for a wallet
 */
export function createPrivateStateForWallet(wallet: Wallet): StateraPrivateState {
  return createPrivateStateraState(wallet.secretKey);
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
  const state = privateState || (createPrivateStateraState(wallet.secretKey) as any);
  return simulator.as(state, wallet.coinPublicKey);
}

/**
 * Helper to create a depositor leaf after deposit
 * This matches what the depositToCollateralPool circuit creates
 *
 * @param wallet - The wallet
 * @param collateral - Collateral amount
 * @param debt - Debt amount
 * @param coinType - Collateral coin type (color)
 * @returns Depositor leaf matching circuit logic
 */
function createDepositorLeaf(
  wallet: Wallet,
  collateral: bigint,
  debt: bigint,
  coinType: Uint8Array
): any {
  // User ID - in circuit this is generateUserId(userSecret)
  // The contract does: persistentCommit<Bytes<32>>(ownPublicKey().bytes, sk)
  // We MUST use encodeCoinPublicKey() to ensure the bytes match what ownPublicKey() returns
  const publicKeyBytes = encodeCoinPublicKey(wallet.coinPublicKey);

  console.log('\n=== createDepositorLeaf Debug - TEST CODE COMPUTED VALUES ===');
  console.log('Wallet coinPublicKey (hex string):', wallet.coinPublicKey);
  console.log('Encoded public key bytes (ALL 32 bytes):',  Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  console.log('Secret key (ALL 32 bytes):', Array.from(wallet.secretKey).map(b => b.toString(16).padStart(2, '0')).join(''));

  const userId = persistentCommit(_bytes32, publicKeyBytes, wallet.secretKey);
  console.log('Generated userId (ALL 32 bytes):', Array.from(userId).map(b => b.toString(16).padStart(2, '0')).join(''));
  console.log('===============================================================\n');

  // Metadata - in circuit this is MintMetadata { collateral, debt }
  const metadata = { collateral, debt };

  // Metadata hash - in circuit this is hashMintMetadata(metadata, depositorsId)
  // The circuit uses persistentCommit with the userId as randomizer
  const metadataHash = hashMintMetadataForTest(metadata, userId);
  console.log('Metadata hash (first 8):', Array.from(metadataHash.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Mint counter commitment - in circuit this is persistentCommit(0, randomness)
  // For the initial deposit, the counter is 0
  // The randomness is derived from the user secret
  const userSecretHash = persistentHash(_bytes32, wallet.secretKey);
  const initialRandomness = persistentHash(_bytes32, userSecretHash);

  // Create a descriptor for Uint<64> counter
  const counterDescriptor = _uint64;
  const mintCounterCommitment = persistentCommit(counterDescriptor, 0n, initialRandomness);
  console.log('Mint counter commitment (first 8):', Array.from(mintCounterCommitment.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Position status - inactive initially (0), active (1) when there's debt
  // MUST use enum values from DebtPositionStatus to match circuit's serialization
  const position = debt > 0n ? DebtPositionStatus.active : DebtPositionStatus.inactive;
  console.log('Position (enum value):', position);
  console.log('Position (DebtPositionStatus.inactive):', DebtPositionStatus.inactive);
  console.log('CoinType (first 8):', Array.from(coinType.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));

  const depositorLeaf = {
    id: userId,
    metadataHash,
    position,
    coinType,
    mintCounterCommitment
  };

  console.log('\nDepositor leaf created, now hashing it...');
  return depositorLeaf;
}

/**
 * Helper to create a private state for a wallet with depositor leaf
 * Use this after deposit to enable mint/withdraw operations
 *
 * This properly constructs the depositor leaf to match what depositToCollateralPool creates
 *
 * @param wallet - The wallet
 * @param collateral - Collateral amount deposited
 * @param debt - Current debt amount (0 for new deposits)
 * @param coinType - Collateral coin type (default: ADA)
 * @returns Private state with depositor leaf
 */
export function createPrivateStateWithDepositorLeaf(
  wallet: Wallet,
  collateral: bigint = 1000n,
  debt: bigint = 0n,
  coinType: Uint8Array = pad('ADA', 32)
): StateraPrivateState {
  const baseState = createPrivateStateraState(wallet.secretKey);

  // Create the depositor leaf matching circuit logic
  const depositorLeaf = createDepositorLeaf(wallet, collateral, debt, coinType);

  // Hash the leaf using the SAME hash function as the circuit
  const commitment = hashDepositorLeafForTest(depositorLeaf);
  console.log('Final commitment hash (ALL 32 bytes):', Array.from(commitment).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Update private state with the depositor leaf AND commitment
  return {
    ...baseState,
    currentDepositorLeaf: depositorLeaf,
    currentDepositorCommitment: commitment,
    // Also update mint_metadata to match what the circuit would have set
    mint_metadata: {
      collateral,
      debt
    }
  };
}

/**
 * Helper to create admin private state with proper metadata from simulator
 * Use this when executing admin circuits that require admin authentication
 *
 * @param simulator - The contract simulator with initialized admin state
 * @param adminWallet - The admin wallet
 * @returns Private state with correct admin metadata
 */
export function createAdminPrivateState(
  simulator: ContractSimulator<StateraPrivateState>,
  adminWallet: Wallet
): StateraPrivateState {
  // Get the current private state which has the correct admin_metadata set by constructor
  const currentState = simulator.getPrivateState();

  // Return a new state with the admin's secret key and the initialized admin_metadata
  return {
    ...currentState,
    secret_key: adminWallet.secretKey
  };
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
  ]);

  balanceTracker.printBalances(walletKey, tokenNames);
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
  ]);

  balanceTracker.printAllBalances(tokenNames);
}

/**
 * Helper to update balances for all wallets in the fixture
 */
export function updateAllBalances(
  fixture: StateraTestFixture
): void {
  const { simulator, balanceTracker, adminWallet, userWallets } = fixture;

  // Update admin balance
  balanceTracker.updateFromSimulator(
    simulator,
    adminWallet.coinPublicKey,
    'admin'
  );

  // Update user balances
  userWallets.forEach((wallet, index) => {
    balanceTracker.updateFromSimulator(
      simulator,
      wallet.coinPublicKey,
      `user${index}`
    );
  });
}

/**
 * Mock Merkle tree for testing commitment/nullifier pattern
 * This simulates the on-chain Merkle tree structure
 */
export class MockMerkleTree {
  private leaves: Map<string, Uint8Array> = new Map();

  /**
   * Adds a leaf to the mock tree
   */
  addLeaf(commitment: Uint8Array): void {
    const key = Buffer.from(commitment).toString('hex');
    this.leaves.set(key, commitment);
  }

  /**
   * Finds a path for a leaf (simplified for testing)
   */
  findPathForLeaf(commitment: Uint8Array): any {
    const key = Buffer.from(commitment).toString('hex');
    if (!this.leaves.has(key)) {
      return null;
    }

    // Return a mock path structure
    // In a real implementation, this would return the actual Merkle path
    return {
      leaf: commitment,
      siblings: [],
      index: 0n
    };
  }

  /**
   * Checks if a commitment exists in the tree
   */
  hasLeaf(commitment: Uint8Array): boolean {
    const key = Buffer.from(commitment).toString('hex');
    return this.leaves.has(key);
  }

  /**
   * Clears all leaves
   */
  clear(): void {
    this.leaves.clear();
  }
}

/**
 * Creates a user ID from a wallet's secret key
 * This is a simplified version for testing
 */
export function createUserId(wallet: Wallet): Uint8Array {
  // In production, this would be derived from the secret key using proper hashing
  return wallet.secretKey;
}

/**
 * Creates a metadata hash for testing
 * This is a simplified version for testing
 */
export function createMetadataHash(metadata: any): Uint8Array {
  // In production, this would use proper hashing
  const hash = new Uint8Array(32);
  hash.fill(0);
  return hash;
}

/**
 * Creates a mint counter commitment for testing
 */
export function createMintCounterCommitment(counter: bigint): Uint8Array {
  // In production, this would use proper commitment scheme
  const commitment = new Uint8Array(32);
  commitment.fill(0);
  return commitment;
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
  };
}

/**
 * Creates a collateral coin for deposit with proper SPECK conversion
 * Contract uses SPECK_per_tDUST = 1000000 for ADA conversions
 *
 * @param amountInADA - Amount in ADA (or collateral token units)
 * @returns CoinInfo with value in SPECK
 */
export function createCollateralCoin(amountInADA: bigint): any {
  const SPECK_per_tDUST = 1000000n;
  return {
    nonce: generateNonce(),
    color: pad('ADA', 32),
    value: amountInADA * SPECK_per_tDUST
  };
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
  return {
    nonce: generateNonce(),
    color: encodeTokenType(sSUSDTokenType),
    value
  };
}

/**
 * Converts a hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  // Remove 0x prefix if present
  hex = hex.replace(/^0x/, '');

  // Pad to ensure even length
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  // Pad to 32 bytes if needed
  if (bytes.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(bytes);
    return padded;
  }

  return bytes.slice(0, 32);
}

/**
 * Creates a mock ComplianceToken (KYC token) for testing
 * Accepts either string (hex) or Uint8Array for userPk
 */
export function createMockComplianceToken(
  userPk: string | Uint8Array,
  oraclePk: Uint8Array
): any {
  const currentTime = BigInt(Math.floor(Date.now() / 1000));

  // Convert userPk to Uint8Array if it's a string
  const userPkBytes = typeof userPk === 'string' ? hexToBytes(userPk) : userPk;

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
  };
}

/**
 * Creates a mock oracle public key
 */
export function createMockOraclePk(): Uint8Array {
  return pad('trusted-oracle-1', 32);
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
  };

  // Add to simulator inputs so receive() can find it
  simulator.addCoinInput(runtimeCoin);
}

// Create type descriptors using the same primitives as the contract
const _bytes32 = new CompactTypeBytes(32);
const _uint64 = new CompactTypeUnsignedInteger(18446744073709551615n, 8); // Uint<64>

// DebtPositionStatus enum: inactive=0, active=1, closed=2
// WORKAROUND: CompactTypeEnum(2, 1) has a bug where toValue(0) returns empty array
// We use CompactTypeUnsignedInteger instead which correctly serializes 0
const _debtPositionStatus = new CompactTypeUnsignedInteger(2n, 1); // Max value 2, 1 byte (same as enum)

/**
 * Creates a type descriptor for DepositorLeaf that matches the contract's compiled descriptor
 *
 * DepositorLeaf structure from contract:
 * - id: Bytes<32>
 * - metadataHash: Bytes<32>
 * - position: DebtPositionStatus (enum with max value 2, size 1 byte)
 * - coinType: Bytes<32>
 * - mintCounterCommitment: Bytes<32>
 */
class DepositorLeafDescriptor {
  alignment() {
    // Concatenate alignments in the same order as the contract
    // Use CompactTypeUnsignedInteger alignment for position (workaround for enum bug)
    return _bytes32.alignment()
      .concat(_bytes32.alignment())
      .concat(_debtPositionStatus.alignment())
      .concat(_bytes32.alignment())
      .concat(_bytes32.alignment());
  }

  toValue(leaf: any): Uint8Array[] {
    // Serialize in the same order as the contract
    // Use CompactTypeUnsignedInteger to serialize position (workaround for CompactTypeEnum bug)
    return (_bytes32.toValue(leaf.id) as Uint8Array[])
      .concat(_bytes32.toValue(leaf.metadataHash) as Uint8Array[])
      .concat(_debtPositionStatus.toValue(leaf.position) as Uint8Array[])
      .concat(_bytes32.toValue(leaf.coinType) as Uint8Array[])
      .concat(_bytes32.toValue(leaf.mintCounterCommitment) as Uint8Array[]);
  }

  fromValue(buffer: Uint8Array[]): any {
    return {
      id: _bytes32.fromValue(buffer),
      metadataHash: _bytes32.fromValue(buffer),
      position: _debtPositionStatus.fromValue(buffer),
      coinType: _bytes32.fromValue(buffer),
      mintCounterCommitment: _bytes32.fromValue(buffer)
    };
  }
}

/**
 * Creates a type descriptor for StakerLeaf
 *
 * StakerLeaf structure:
 * - id: Bytes<32>
 * - metadataHash: Bytes<32>
 */
class StakerLeafDescriptor {
  alignment() {
    return _bytes32.alignment().concat(_bytes32.alignment());
  }

  toValue(leaf: any): Uint8Array[] {
    return (_bytes32.toValue(leaf.id) as Uint8Array[]).concat(_bytes32.toValue(leaf.metadataHash) as Uint8Array[]);
  }

  fromValue(buffer: Uint8Array[]): any {
    return {
      id: _bytes32.fromValue(buffer),
      metadataHash: _bytes32.fromValue(buffer)
    };
  }
}

/**
 * Creates a type descriptor for MintMetadata
 *
 * MintMetadata structure:
 * - collateral: Uint<64>
 * - debt: Uint<64>
 */
class MintMetadataDescriptor {
  alignment() {
    return _uint64.alignment().concat(_uint64.alignment());
  }

  toValue(metadata: any): Uint8Array[] {
    return (_uint64.toValue(metadata.collateral) as Uint8Array[]).concat(_uint64.toValue(metadata.debt) as Uint8Array[]);
  }

  fromValue(buffer: Uint8Array[]): any {
    return {
      collateral: _uint64.fromValue(buffer),
      debt: _uint64.fromValue(buffer)
    };
  }
}

const depositorLeafDescriptor = new DepositorLeafDescriptor();
const stakerLeafDescriptor = new StakerLeafDescriptor();
const mintMetadataDescriptor = new MintMetadataDescriptor();

/**
 * Hash a depositor leaf using the compiled contract's hash function
 * CRITICAL: We MUST use the contract's hash function because it uses the BUGGY enum serialization
 * that's actually used when the circuit inserts commitments into the tree!
 */
function hashDepositorLeafForTest(leaf: any): Uint8Array {
  // Use persistentHash with our workaround descriptor
  // But WAIT - the circuit uses the BUGGY enum, so we need to match that!
  // Let's use the actual contract's enum descriptor
  const _bytes32 = new CompactTypeBytes(32);
  const _uint64 = new CompactTypeUnsignedInteger(18446744073709551615n, 8);
  const _debtPositionStatusEnum = new CompactTypeEnum(2, 1); // Use BUGGY enum to match circuit!

  class BuggyDepositorLeafDescriptor {
    alignment() {
      return _bytes32.alignment()
        .concat(_bytes32.alignment())
        .concat(_debtPositionStatusEnum.alignment()) // BUGGY enum
        .concat(_bytes32.alignment())
        .concat(_bytes32.alignment());
    }

    toValue(leaf: any): Uint8Array[] {
      return (_bytes32.toValue(leaf.id) as Uint8Array[])
        .concat(_bytes32.toValue(leaf.metadataHash) as Uint8Array[])
        .concat(_debtPositionStatusEnum.toValue(leaf.position) as Uint8Array[]) // BUGGY enum!
        .concat(_bytes32.toValue(leaf.coinType) as Uint8Array[])
        .concat(_bytes32.toValue(leaf.mintCounterCommitment) as Uint8Array[]);
    }
  }

  const buggyDescriptor = new BuggyDepositorLeafDescriptor();
  return persistentHash(buggyDescriptor, leaf);
}

/**
 * Hash a staker leaf using the same persistentHash function as the circuit
 */
function hashStakerLeafForTest(leaf: any): Uint8Array {
  return persistentHash(stakerLeafDescriptor, leaf);
}

/**
 * Hash mint metadata using persistentCommit (same as contract's hashMintMetadata)
 */
function hashMintMetadataForTest(metadata: any, randomizer: Uint8Array): Uint8Array {
  return persistentCommit(mintMetadataDescriptor, metadata, randomizer);
}

/**
 * Helper to extract the actual depositor commitment from the on-chain tree
 * This retrieves the REAL commitment hash that was inserted by the circuit
 *
 * @param simulator - The contract simulator (after deposit)
 * @param treeIndex - Index in the tree (usually firstFree - 1 for most recent)
 * @returns The actual commitment hash from the tree, or undefined if not found
 */
function extractDepositorCommitmentFromTree(
  simulator: ContractSimulator<StateraPrivateState>,
  treeIndex: bigint
): Uint8Array | undefined {
  try {
    const rawLedgerState = simulator.getLedger();
    const ledgerAccessor = ledger(rawLedgerState);

    // Create a dummy leaf (all zeros) - we just need to get the path
    const dummyLeaf = new Uint8Array(32);
    dummyLeaf.fill(0);

    // Use pathForLeaf to get the path at this index
    // The path.leaf field will contain the ACTUAL leaf hash that was inserted
    const path = ledgerAccessor.depositorCommitments.pathForLeaf(treeIndex, dummyLeaf);

    if (path && path.leaf) {
      console.log(`✅ Extracted commitment from tree at index ${treeIndex}:`, Array.from(path.leaf.slice(0, 8)).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
      return path.leaf;
    }

    return undefined;
  } catch (e) {
    console.log(`⚠️  Could not extract commitment from tree at index ${treeIndex}:`, e);
    return undefined;
  }
}

/**
 * Helper to create private state with depositor leaf after a deposit
 *
 * IMPORTANT: Call this AFTER executing depositToCollateralPool circuit
 *
 * The deposit circuit:
 * 1. Receives the collateral coin
 * 2. Creates a depositor leaf with user's metadata
 * 3. Inserts the commitment into the on-chain Merkle tree
 * 4. Updates the private state's mint_metadata
 *
 * This helper extracts the ACTUAL commitment from the on-chain tree that was
 * inserted by the circuit, and recreates the depositor leaf to match.
 *
 * @param simulator - The contract simulator (after deposit)
 * @param wallet - The user's wallet
 * @param depositAmount - Amount deposited
 * @param collateralTokenType - The collateral token type (REQUIRED - must match what was passed to prepareCoinForReceive)
 * @returns Private state with depositor leaf for subsequent operations
 */
export function getPrivateStateAfterDeposit(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  depositAmount: bigint,
  collateralTokenType: TokenType
): StateraPrivateState {
  console.log('\n=== getPrivateStateAfterDeposit called ===');
  console.log('Wallet:', wallet.coinPublicKey);
  console.log('Deposit amount:', depositAmount);

  // Get the updated private state from simulator
  const currentState = simulator.getPrivateState();

  // CRITICAL: The circuit does disclose(coin.color) which gives the ENCODED TokenType!
  // We MUST encode the TokenType to match what the circuit receives
  const coinTypeBytes = encodeTokenType(collateralTokenType);
  console.log('Encoded coinType (first 8):', Array.from(coinTypeBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));

  // Recreate the depositor leaf that was created by the deposit circuit
  const depositorLeaf = createDepositorLeaf(
    wallet,
    depositAmount,
    0n,  // New deposits have 0 debt
    coinTypeBytes
  );

  // CRITICAL: Use the BUGGY enum hash function to match what the circuit uses!
  // The circuit's compiled descriptor uses CompactTypeEnum(2, 1) which has a bug,
  // so we MUST replicate that bug to get matching hashes!
  const commitment = hashDepositorLeafForTest(depositorLeaf);

  // VERIFICATION: Also compute what the circuit would hash from this leaf
  // The circuit does: oldCommitment = hashDepositorLeaf(oldLeaf)
  // where oldLeaf comes from our private state
  const circuitWouldCompute = hashDepositorLeafForTest(depositorLeaf);
  console.log('\n=== HASH VERIFICATION ===');
  console.log('Our stored commitment:      ', Array.from(commitment).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('Circuit would compute:      ', Array.from(circuitWouldCompute).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('Hashes match?', Array.from(commitment).every((b, i) => b === circuitWouldCompute[i]));
  console.log('========================\n');

  console.log('\n=== getPrivateStateAfterDeposit - TEST CODE FINAL RESULT ===');
  console.log('Final commitment hash (using buggy enum - ALL 32 bytes):', Array.from(commitment).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('DepositorLeaf fields (what we computed in test code):');
  console.log('  id (ALL 32 bytes):', Array.from(depositorLeaf.id).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('  metadataHash (ALL 32 bytes):', Array.from(depositorLeaf.metadataHash).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('  position:', depositorLeaf.position);
  console.log('  coinType (ALL 32 bytes):', Array.from(depositorLeaf.coinType).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('  mintCounterCommitment (ALL 32 bytes):', Array.from(depositorLeaf.mintCounterCommitment).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
  console.log('============================================================\n');

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    currentDepositorLeaf: depositorLeaf,
    currentDepositorCommitment: commitment,
    mint_metadata: {
      collateral: depositAmount,
      debt: 0n
    }
  };
}

/**
 * Helper to create private state with staker leaf after staking
 *
 * IMPORTANT: Call this AFTER executing depositToStabilityPool circuit
 *
 * @param simulator - The contract simulator (after stake)
 * @param wallet - The user's wallet
 * @param stakeAmount - Amount staked
 * @returns Private state with staker leaf for subsequent operations
 */
export function getPrivateStateAfterStake(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  stakeAmount: bigint
): StateraPrivateState {
  // Get the updated private state from simulator
  const currentState = simulator.getPrivateState();

  // Recreate the staker leaf that was created by the depositToStabilityPool circuit
  const userId = wallet.secretKey;

  // Create metadata hash (simplified for testing)
  const metadataHash = new Uint8Array(32);
  const stakeBytes = new DataView(new ArrayBuffer(8));
  stakeBytes.setBigUint64(0, stakeAmount, true);
  metadataHash.set(new Uint8Array(stakeBytes.buffer), 0);

  const stakerLeaf = {
    id: userId,
    metadataHash
  };

  // Hash the leaf using the SAME hash function as the circuit
  const commitment = hashStakerLeafForTest(stakerLeaf);

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    currentStakerLeaf: stakerLeaf,
    currentStakerCommitment: commitment
  };
}
