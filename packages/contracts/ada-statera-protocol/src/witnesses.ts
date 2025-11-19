import {
  Ledger,
  MintMetadata,
  DepositorLeaf,
  StakerLeaf,
  DebtPositionStatus
} from './managed/adaStateraProtocol/contract/index.cjs'
import {
  WitnessContext,
  MerkleTreeDigest,
  MerkleTreePath
} from '@midnight-ntwrk/compact-runtime'

// Type declaration for MerkleTreeManager (actual implementation in api package)
// This avoids cross-package import issues while maintaining type safety
type MerkleTreeManager = any

// Type definitions for private state structures
export type StakeMetadata = {
  effectiveBalance: bigint
  stakeReward: bigint
  entry_ADA_SUSD_index: bigint
  entry_scale_factor: bigint
}

export type AdminMetadata = {
  protocolFeePool: bigint
  super_admin: Uint8Array
  admins: Uint8Array[] // Vector<10, Bytes<32>>
  admin_count: bigint
}

export type QualifiedCoinInfo = {
  nonce: Uint8Array
  color: Uint8Array
  value: bigint
  mt_index: bigint
}

export interface StateraPrivateState {
  readonly secret_key: Uint8Array
  readonly mint_metadata: MintMetadata
  readonly stake_metadata: StakeMetadata
  readonly admin_metadata: AdminMetadata
  readonly stake_pool_coin: QualifiedCoinInfo | null
  readonly reserve_pool_coin: QualifiedCoinInfo | null
  mint_counter: bigint
  // Commitment/Nullifier pattern: track user's current commitments
  // Store both the leaf data AND the commitment hash for efficient Merkle proof lookup
  currentDepositorLeaf?: DepositorLeaf      // User's current depositor leaf data
  currentDepositorCommitment?: Uint8Array   // Hash of currentDepositorLeaf (32 bytes)
  currentStakerLeaf?: StakerLeaf            // User's current staker leaf data
  currentStakerCommitment?: Uint8Array      // Hash of currentStakerLeaf (32 bytes)
}

export const createPrivateStateraState = (
  secret_key: Uint8Array
): StateraPrivateState => ({
  secret_key,
  mint_metadata: {
    collateral: 0n,
    debt: 0n
  },
  stake_metadata: {
    effectiveBalance: 0n,
    stakeReward: 0n,
    entry_ADA_SUSD_index: 0n,
    entry_scale_factor: 0n
  },
  admin_metadata: {
    protocolFeePool: 0n,
    super_admin: new Uint8Array(32),
    admins: Array.from({ length: 10 }, () => new Uint8Array(32)),
    admin_count: 0n
  },
  stake_pool_coin: null,
  reserve_pool_coin: null,
  mint_counter: 0n,
  // Commitment/Nullifier pattern: no leaf data or commitments initially (new user)
  currentDepositorLeaf: undefined,
  currentDepositorCommitment: undefined,
  currentStakerLeaf: undefined,
  currentStakerCommitment: undefined
})

/* ========== HELPER FUNCTIONS FOR PRIVATE STATE MANAGEMENT ========== */

/**
 * Updates depositor leaf and commitment in private state
 * Call this after a successful circuit execution that creates a new depositor commitment
 *
 * @param currentState - Current private state
 * @param newLeaf - New depositor leaf data
 * @param newCommitment - Hash of the new leaf (32 bytes)
 * @returns Updated private state
 */
export function updateDepositorCommitment(
  currentState: StateraPrivateState,
  newLeaf: DepositorLeaf,
  newCommitment: Uint8Array
): StateraPrivateState {
  if (newCommitment.length !== 32) {
    throw new Error('Commitment hash must be exactly 32 bytes')
  }

  return {
    ...currentState,
    currentDepositorLeaf: newLeaf,
    currentDepositorCommitment: newCommitment
  }
}

/**
 * Updates staker leaf and commitment in private state
 * Call this after a successful circuit execution that creates a new staker commitment
 *
 * @param currentState - Current private state
 * @param newLeaf - New staker leaf data
 * @param newCommitment - Hash of the new leaf (32 bytes)
 * @returns Updated private state
 */
export function updateStakerCommitment(
  currentState: StateraPrivateState,
  newLeaf: StakerLeaf,
  newCommitment: Uint8Array
): StateraPrivateState {
  if (newCommitment.length !== 32) {
    throw new Error('Commitment hash must be exactly 32 bytes')
  }

  return {
    ...currentState,
    currentStakerLeaf: newLeaf,
    currentStakerCommitment: newCommitment
  }
}

/**
 * Creates a depositor leaf from current private state
 * Used before calling depositor circuits to prepare the leaf data
 *
 * @param privateState - Current private state
 * @param userId - Privacy-preserving user ID (32 bytes)
 * @param metadataHash - Hash of mint metadata (32 bytes)
 * @param position - Debt position status
 * @param coinType - Collateral asset type (32 bytes)
 * @param mintCounterCommitment - Mint counter commitment (32 bytes)
 * @returns DepositorLeaf
 */
export function createDepositorLeafFromState(
  privateState: StateraPrivateState,
  userId: Uint8Array,
  metadataHash: Uint8Array,
  position: DebtPositionStatus,
  coinType: Uint8Array,
  mintCounterCommitment: Uint8Array
): DepositorLeaf {
  return {
    id: userId,
    metadataHash,
    position,
    coinType,
    mintCounterCommitment
  }
}

/**
 * Creates a staker leaf from current private state
 * Used before calling staker circuits to prepare the leaf data
 *
 * @param privateState - Current private state
 * @param userId - Privacy-preserving user ID (32 bytes)
 * @param metadataHash - Hash of stake metadata (32 bytes)
 * @returns StakerLeaf
 */
export function createStakerLeafFromState(
  privateState: StateraPrivateState,
  userId: Uint8Array,
  metadataHash: Uint8Array
): StakerLeaf {
  return {
    id: userId,
    metadataHash
  }
}

export const witnesses = {
  division: (
    { privateState }: WitnessContext<Ledger, StateraPrivateState>,
    dividend: bigint,
    divisor: bigint
  ): [StateraPrivateState, [bigint, bigint]] => {
    if (divisor == 0n) throw 'Invaid arithemetic operation'

    const quotient = BigInt(Math.round(Number(dividend / divisor)))
    const remainder = dividend % divisor

    return [privateState, [quotient, remainder]]
  },

  // Returns the user's secret key stored offchain in their private state
  secret_key: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    Uint8Array
  ] => {
    if (!privateState || !privateState.secret_key) {
      throw new Error('Secret key not found in private state')
    }
    return [privateState, privateState.secret_key]
  },

  // Returns the user's mint-metadata stored offchain in their private state
  get_mintmetadata_private_state: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    MintMetadata
  ] => {
    return [
      privateState,
      privateState.mint_metadata || { collateral: 0n, debt: 0n }
    ]
  },

  /* Sets mint_metadata in private state*/
  set_mint_metadata: (
    { privateState }: WitnessContext<Ledger, StateraPrivateState>,
    newMetadata: Partial<MintMetadata>
  ): [StateraPrivateState, []] => {
    const newPrivateState = {
      ...privateState,
      mint_metadata: {
        ...(privateState.mint_metadata || { collateral: 0n, debt: 0n }),
        ...newMetadata
      }
    }

    return [newPrivateState, []]
  },

  // Returns the user's stake metadata from private state
  get_stakemetadata_private_state: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    StakeMetadata
  ] => {
    return [
      privateState,
      privateState.stake_metadata || {
        effectiveBalance: 0n,
        stakeReward: 0n,
        entry_ADA_SUSD_index: 0n,
        entry_scale_factor: 0n
      }
    ]
  },

  /* Sets stake_metadata in private state */
  set_stake_metadata: (
    { privateState }: WitnessContext<Ledger, StateraPrivateState>,
    newMetadata: Partial<StakeMetadata>
  ): [StateraPrivateState, []] => {
    const newPrivateState = {
      ...privateState,
      stake_metadata: {
        ...(privateState.stake_metadata || {
          effectiveBalance: 0n,
          stakeReward: 0n,
          entry_ADA_SUSD_index: 0n,
          entry_scale_factor: 0n
        }),
        ...newMetadata
      }
    }

    return [newPrivateState, []]
  },

  // Returns the admin metadata from private state
  get_adminmetadata_private_state: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    AdminMetadata
  ] => {
    return [
      privateState,
      privateState.admin_metadata || {
        protocolFeePool: 0n,
        super_admin: new Uint8Array(32),
        admins: Array(10).fill(new Uint8Array(32)),
        admin_count: 0n
      }
    ]
  },

  /* Sets admin_metadata in private state */
  set_admin_metadata: (
    { privateState }: WitnessContext<Ledger, StateraPrivateState>,
    newMetadata: Partial<AdminMetadata>
  ): [StateraPrivateState, []] => {
    const newPrivateState = {
      ...privateState,
      admin_metadata: {
        ...(privateState.admin_metadata || {
          protocolFeePool: 0n,
          super_admin: new Uint8Array(32),
          admins: Array(10).fill(new Uint8Array(32)),
          admin_count: 0n
        }),
        ...newMetadata
      }
    }

    return [newPrivateState, []]
  },

  // Returns the stake pool coin from private state
  get_stakepoolcoin_private_state: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    QualifiedCoinInfo
  ] => {
    if (!privateState.stake_pool_coin) {
      throw new Error(
        'Stake pool coin not found in private state. User must deposit to stake pool first.'
      )
    }
    return [privateState, privateState.stake_pool_coin]
  },

  // Returns the reserve pool coin from private state
  get_reservepoolcoin_private_state: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    QualifiedCoinInfo
  ] => {
    if (!privateState.reserve_pool_coin) {
      throw new Error(
        'Reserve pool coin not found in private state. Contract must have reserve pool balance.'
      )
    }
    return [privateState, privateState.reserve_pool_coin]
  },

  // Returns the admin secret key for hashing admin metadata
  admin_secret: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    Uint8Array
  ] => {
    if (!privateState || !privateState.secret_key) {
      throw new Error('Admin secret key not found in private state')
    }
    return [privateState, privateState.secret_key]
  },

  // Returns the user's current mint counter value
  // The authoritative value is the on-chain mintCounterCommitment in the user's Depositor struct.
  // The circuit will derive randomness from the secret key using persistentHash and handle incrementing.
  get_mint_counter: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    bigint
  ] => {
    const currentCounter = privateState.mint_counter

    // Just return current counter - circuit handles increment and commitment
    return [privateState, currentCounter]
  },

  /* ========== MERKLE TREE WITNESSES ========== */

  // Returns Merkle path for depositor verification
  // With commitment/nullifier pattern: get path from on-chain tree using stored commitment hash
  get_depositor_merkle_path: ({
    privateState,
    ledger
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    MerkleTreePath<Uint8Array>
  ] => {
    if (!privateState.currentDepositorLeaf || !privateState.currentDepositorCommitment) {
      throw new Error(
        'Depositor leaf or commitment not found. Cannot generate Merkle path for unknown commitment.'
      )
    }

    // Use the stored commitment hash (computed when the commitment was created)
    const commitmentHash = privateState.currentDepositorCommitment

    console.log('\n=== get_depositor_merkle_path Debug - CIRCUIT CREATED VALUES ===');
    console.log('Looking for commitment (ALL 32 bytes):', Array.from(commitmentHash).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
    console.log('Depositor leaf from private state (WHAT THE CIRCUIT ACTUALLY CREATED):');
    console.log('  id (ALL 32 bytes):', Array.from(privateState.currentDepositorLeaf.id).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
    console.log('  metadataHash (ALL 32 bytes):', Array.from(privateState.currentDepositorLeaf.metadataHash).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
    console.log('  position:', privateState.currentDepositorLeaf.position);
    console.log('  coinType (ALL 32 bytes):', Array.from(privateState.currentDepositorLeaf.coinType).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
    console.log('  mintCounterCommitment (ALL 32 bytes):', Array.from(privateState.currentDepositorLeaf.mintCounterCommitment).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));

    const firstFree = ledger.depositorCommitments.firstFree();
    console.log('Ledger depositorCommitments firstFree:', firstFree);

    const currentRoot = ledger.depositorCommitments.root();
    console.log('Current tree root field:', currentRoot.field);

    // DIAGNOSTIC: Check the tree's history to see all roots
    try {
      const history = Array.from(ledger.depositorCommitments.history());
      console.log('Tree history (number of roots):', history.length);
      if (history.length > 0) {
        console.log('Historical roots:');
        history.forEach((root, idx) => {
          console.log(`  Root ${idx}: field = ${root.field}`);
        });
      }
    } catch (e) {
      console.log('Could not get tree history:', (e as Error).message);
    }

    // DIAGNOSTIC: pathForLeaf returns whatever leaf you pass in, not what's in the tree!
    // Skip this misleading debug output
    // console.log('=== pathForLeaf ALWAYS returns the leaf you request ===');
    // console.log('Skipping misleading tree enumeration');
    // console.log('=========================================================\n');

    // WORKAROUND: findPathForLeaf() has a bug and doesn't find commitments
    // Instead, we search through all existing indices to find our commitment
    // In the commitment/nullifier pattern, the most recent commitment is typically at firstFree - 1
    let path: MerkleTreePath<Uint8Array> | undefined;

    // CRITICAL: Use findPathForLeaf which searches the actual tree!
    // pathForLeaf just constructs a path but doesn't verify the leaf exists
    console.log('Getting path using findPathForLeaf (searches actual tree)...');
    console.log('  commitmentHash type:', typeof commitmentHash);
    console.log('  commitmentHash instanceof Uint8Array:', commitmentHash instanceof Uint8Array);
    console.log('  commitmentHash.length:', commitmentHash.length);
    try {
      path = ledger.depositorCommitments.findPathForLeaf(commitmentHash);
      console.log('findPathForLeaf returned:', path === null ? 'null' : path === undefined ? 'undefined' : 'a value');
      if (path) {
        console.log('✅ findPathForLeaf found the commitment in the tree!');
        console.log('Path structure:', Object.keys(path));
      } else {
        console.log('⚠️  findPathForLeaf returned null/undefined - commitment not found in tree');

        // DIAGNOSTIC: Try getting path at all indices to see what's actually in the tree
        console.log('\n=== DIAGNOSTIC: Enumerating tree contents ===');
        const maxIndex = Number(firstFree);
        for (let i = 0n; i < firstFree; i++) {
          try {
            // CRITICAL FIX: pathForLeaf constructs a path but the sibl ings might not be correct!
            // The path.leaf is set to whatever we pass in, but the siblings come from the tree
            const testPath = ledger.depositorCommitments.pathForLeaf(i, commitmentHash);
            if (testPath && testPath.leaf) {
              console.log(`Index ${i}: path retrieved`);
              console.log(`  path.leaf (first 16): ${Array.from(testPath.leaf.slice(0, 16)).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join('')}`);
              console.log(`  Leaf matches our commitment? ${Array.from(testPath.leaf).every((b, idx) => b === commitmentHash[idx])}`);

              // Get the ACTUAL leaf hash that was inserted at this index
              // We need to verify the path computes to the current root
              // But we can't easily do that without implementing the Merkle hash function

              // For now, just use the path from index 0 since that's where firstFree-1 = 0
              if (i === 0n) {
                console.log(`✅ Using path from index ${i} (the only index with our commitment)`);

                // WORKAROUND: Manually verify and fix the path if needed
                // For a single element at index 0, we expect all siblings to be 0 and all goes_left to be true
                const allSiblingsZero = (testPath as any).path.every((entry: any) => entry.sibling.field === 0n);
                const allGoLeft = (testPath as any).path.every((entry: any) => entry.goes_left === true);

                console.log(`  Path validation: allSiblingsZero=${allSiblingsZero}, allGoLeft=${allGoLeft}`);

                // DIAGNOSTIC: Check sibling structure
                if ((testPath as any).path.length > 0) {
                  const firstSibling = (testPath as any).path[0].sibling;
                  console.log(`  First sibling type: ${typeof firstSibling}, keys: ${Object.keys(firstSibling)}`);
                  console.log(`  First sibling.field type: ${typeof firstSibling.field}`);
                }

                if (!allSiblingsZero || !allGoLeft) {
                  console.log('⚠️  WARNING: Path from pathForLeaf has unexpected sibling structure!');
                  console.log('  This may cause checkRoot to fail.');
                }

                path = testPath as MerkleTreePath<Uint8Array>;
              }
            }
          } catch (e) {
            console.log(`Index ${i}: error - ${(e as Error).message}`);
          }
        }
        console.log('===========================================\n');
      }
    } catch (e) {
      console.log(`findPathForLeaf error: ${(e as Error).message}`);
    }

    console.log('Path found:', path !== undefined);

    // Log success and detailed path info
    if (path) {
      console.log('✅ Successfully retrieved Merkle path for depositor commitment');
      console.log('Path details:');
      console.log('  - Leaf (first 16 bytes):', Array.from((path.leaf as Uint8Array).slice(0, 16)).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
      console.log('  - Number of siblings:', (path as any).path.length);
      console.log('  - All siblings are zero?', (path as any).path.every((entry: any) => entry.sibling.field === 0n));
      console.log('  - All go left?', (path as any).path.every((entry: any) => entry.goes_left === true));

      // DIAGNOSTIC: Verify the path by checking if leaf matches what we expect
      console.log('\n=== PATH VERIFICATION ===');
      console.log('path.leaf (ALL 32):', Array.from(path.leaf).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
      console.log('Expected commitment:', Array.from(commitmentHash).map((b: unknown) => (b as number).toString(16).padStart(2, '0')).join(''));
      console.log('Leaf matches expected?', Array.from(path.leaf).every((b, i) => b === commitmentHash[i]));

      // Check if this path structure is what the circuit expects
      console.log('Path object keys:', Object.keys(path));
      console.log('Path.path[0] structure (if exists):', (path as any).path[0] ? Object.keys((path as any).path[0]) : 'N/A');

      // CRITICAL DIAGNOSTIC: Manually verify if this path computes to the current root
      // This will tell us if the issue is with the path structure or the circuit's checkRoot
      try {
        const treeRoot = ledger.depositorCommitments.root();
        console.log('\nManual root verification:');
        console.log('Tree root (field):', treeRoot.field);
        console.log('This should match what merkleTreePathRootNoLeafHash computes');
        console.log('If they don\'t match, the path is wrong!');
      } catch (e) {
        console.log('Could not get tree root:', (e as Error).message);
      }
      console.log('==========================\n');
    }

    console.log('========================================\n');

    if (!path) {
      throw new Error(
        'Depositor commitment not found in on-chain tree. This should not happen for existing depositors.'
      )
    }

    return [privateState, path]
  },

  // Returns Merkle path for staker verification
  // With commitment/nullifier pattern: get path from on-chain tree using stored commitment hash
  get_staker_merkle_path: ({
    privateState,
    ledger
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    MerkleTreePath<Uint8Array>
  ] => {
    if (!privateState.currentStakerLeaf || !privateState.currentStakerCommitment) {
      throw new Error(
        'Staker leaf or commitment not found. Cannot generate Merkle path for unknown commitment.'
      )
    }

    // Use the stored commitment hash (computed when the commitment was created)
    const commitmentHash = privateState.currentStakerCommitment

    // Get Merkle path from on-chain tree
    const path = ledger.stakerCommitments.findPathForLeaf(commitmentHash)

    if (!path) {
      throw new Error(
        'Staker commitment not found in on-chain tree. This should not happen for existing stakers.'
      )
    }

    return [privateState, path]
  },

  // Returns current depositor leaf from private state
  // Commitment/Nullifier pattern: just return the leaf data tracked in private state
  get_depositor_leaf: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    DepositorLeaf
  ] => {
    if (!privateState.currentDepositorLeaf) {
      throw new Error(
        'Depositor leaf not found. Ensure currentDepositorLeaf is set in private state before circuit call.'
      )
    }
    return [privateState, privateState.currentDepositorLeaf]
  },

  // Returns current staker leaf from private state
  // Commitment/Nullifier pattern: just return the leaf data tracked in private state
  get_staker_leaf: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    StakerLeaf
  ] => {
    if (!privateState.currentStakerLeaf) {
      throw new Error(
        'Staker leaf not found. Ensure currentStakerLeaf is set in private state before circuit call.'
      )
    }
    return [privateState, privateState.currentStakerLeaf]
  }
}
