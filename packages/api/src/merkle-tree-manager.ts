import { createHash } from 'crypto'

/**
 * Merkle Tree Manager for Statera Privacy-Preserving Registries
 *
 * Manages Sparse Merkle Trees for depositors and stakers off-chain.
 * Provides zero-knowledge proofs for on-chain verification.
 */

export interface DepositorLeaf {
  id: Uint8Array // 32 bytes - privacy-preserving user ID
  metadataHash: Uint8Array // 32 bytes - hash of private balances
  position: 'inactive' | 'active' | 'closed'
  coinType: Uint8Array // 32 bytes - collateral asset type
  mintCounterCommitment: Uint8Array // 32 bytes - mint counter commitment
}

export interface StakerLeaf {
  id: Uint8Array // 32 bytes
  metadataHash: Uint8Array // 32 bytes
}

export interface MerkleTreePathEntry {
  sibling: Uint8Array // 32 bytes - sibling hash
  goesLeft: boolean // true if path goes left, false if right
}

export interface MerkleTreePath {
  leaf: Uint8Array // 32 bytes - leaf hash
  path: MerkleTreePathEntry[] // 20 entries for depth 20
}

export interface MerkleProofResult {
  path: MerkleTreePath
  currentLeaf?: DepositorLeaf | StakerLeaf
  updatedLeaf?: DepositorLeaf | StakerLeaf
  newRoot: Uint8Array
}

/**
 * Sparse Merkle Tree implementation
 * Depth 20 supports up to 2^20 = 1,048,576 leaves
 */
export class SparseMerkleTree {
  private nodes: Map<string, Uint8Array> = new Map()
  private leaves: Map<number, Uint8Array> = new Map()
  private readonly emptyHash: Uint8Array

  constructor(private depth: number = 20) {
    this.emptyHash = this.hash(new Uint8Array(32))
    this.initializeEmptyTree()
  }

  /**
   * SHA-256 hash function (matches Compact's persistentHash)
   */
  private hash(data: Uint8Array): Uint8Array {
    return createHash('sha256').update(data).digest()
  }

  /**
   * Compute node key for caching
   */
  private nodeKey(level: number, index: number): string {
    return `${level}:${index}`
  }

  /**
   * Initialize empty tree with default hashes
   */
  private initializeEmptyTree(): void {
    // Pre-compute empty hashes for each level
    let currentHash = this.emptyHash

    for (let level = 0; level < this.depth; level++) {
      // Store empty hash for this level
      const combined = new Uint8Array(64)
      combined.set(currentHash, 0) // left = empty
      combined.set(currentHash, 32) // right = empty
      currentHash = this.hash(combined)
    }
  }

  /**
   * Get leaf at index
   */
  getLeaf(index: number): Uint8Array {
    return this.leaves.get(index) || this.emptyHash
  }

  /**
   * Set leaf at index
   */
  setLeaf(index: number, leafHash: Uint8Array): void {
    this.leaves.set(index, leafHash)
    this.updatePath(index)
  }

  /**
   * Update all nodes on the path from leaf to root
   */
  private updatePath(index: number): void {
    let currentIndex = index
    let currentHash = this.getLeaf(index)

    for (let level = 0; level < this.depth; level++) {
      const isLeft = currentIndex % 2 === 0
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1
      const siblingHash = this.getNodeHash(level, siblingIndex)

      // Compute parent hash
      const combined = new Uint8Array(64)
      if (isLeft) {
        combined.set(currentHash, 0)
        combined.set(siblingHash, 32)
      } else {
        combined.set(siblingHash, 0)
        combined.set(currentHash, 32)
      }

      currentHash = this.hash(combined)
      currentIndex = Math.floor(currentIndex / 2)

      // Store computed hash
      this.nodes.set(this.nodeKey(level + 1, currentIndex), currentHash)
    }
  }

  /**
   * Get hash of a node at specific level and index
   */
  private getNodeHash(level: number, index: number): Uint8Array {
    if (level === 0) {
      return this.getLeaf(index)
    }

    const key = this.nodeKey(level, index)
    if (this.nodes.has(key)) {
      return this.nodes.get(key)!
    }

    // Return empty hash for uninitialized nodes
    return this.emptyHash
  }

  /**
   * Get Merkle path from leaf to root
   */
  getPath(index: number): MerkleTreePath {
    const path: MerkleTreePathEntry[] = []
    let currentIndex = index

    for (let level = 0; level < this.depth; level++) {
      const isLeft = currentIndex % 2 === 0
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1
      const siblingHash = this.getNodeHash(level, siblingIndex)

      path.push({
        sibling: siblingHash,
        goesLeft: !isLeft // Sibling position: if current is left, sibling is right
      })

      currentIndex = Math.floor(currentIndex / 2)
    }

    return {
      leaf: this.getLeaf(index),
      path
    }
  }

  /**
   * Get current root hash
   */
  getRoot(): Uint8Array {
    return this.getNodeHash(this.depth, 0)
  }

  /**
   * Verify a Merkle proof
   */
  verifyProof(
    leafIndex: number,
    leafHash: Uint8Array,
    path: MerkleTreePath
  ): boolean {
    let currentHash = leafHash
    let currentIndex = leafIndex

    for (const entry of path.path) {
      const combined = new Uint8Array(64)
      if (entry.goesLeft) {
        // Sibling is on the left
        combined.set(entry.sibling, 0)
        combined.set(currentHash, 32)
      } else {
        // Sibling is on the right
        combined.set(currentHash, 0)
        combined.set(entry.sibling, 32)
      }

      currentHash = this.hash(combined)
      currentIndex = Math.floor(currentIndex / 2)
    }

    const root = this.getRoot()
    return Buffer.from(currentHash).equals(Buffer.from(root))
  }
}

/**
 * Main Merkle Tree Manager
 */
export class MerkleTreeManager {
  private depositorTree: SparseMerkleTree
  private stakerTree: SparseMerkleTree
  private depositorIndex: Map<string, number> = new Map() // userId -> tree index
  private stakerIndex: Map<string, number> = new Map()
  private depositorLeaves: Map<number, DepositorLeaf> = new Map() // index -> leaf data
  private stakerLeaves: Map<number, StakerLeaf> = new Map()
  private nextDepositorIndex: number = 0
  private nextStakerIndex: number = 0

  constructor(depth: number = 20) {
    this.depositorTree = new SparseMerkleTree(depth)
    this.stakerTree = new SparseMerkleTree(depth)
  }

  /**
   * SHA-256 hash (matches Compact's persistentHash)
   */
  private hash(data: Uint8Array): Uint8Array {
    return createHash('sha256').update(data).digest()
  }

  /**
   * Serialize DepositorLeaf to bytes (must match Compact serialization)
   */
  private serializeDepositorLeaf(leaf: DepositorLeaf): Uint8Array {
    const buffer = new Uint8Array(32 * 4 + 1)
    const positionMap = { inactive: 0, active: 1, closed: 2 }

    buffer.set(leaf.id, 0)
    buffer.set(leaf.metadataHash, 32)
    buffer[64] = positionMap[leaf.position]
    buffer.set(leaf.coinType, 65)
    buffer.set(leaf.mintCounterCommitment, 97)

    return buffer
  }

  /**
   * Serialize StakerLeaf to bytes
   */
  private serializeStakerLeaf(leaf: StakerLeaf): Uint8Array {
    const buffer = new Uint8Array(64)
    buffer.set(leaf.id, 0)
    buffer.set(leaf.metadataHash, 32)
    return buffer
  }

  /**
   * Hash a depositor leaf (matches hashDepositorLeaf in Compact)
   */
  hashDepositorLeaf(leaf: DepositorLeaf): Uint8Array {
    const serialized = this.serializeDepositorLeaf(leaf)
    return this.hash(serialized)
  }

  /**
   * Hash a staker leaf (matches hashStakerLeaf in Compact)
   */
  hashStakerLeaf(leaf: StakerLeaf): Uint8Array {
    const serialized = this.serializeStakerLeaf(leaf)
    return this.hash(serialized)
  }

  // ==================== DEPOSITOR OPERATIONS ====================

  /**
   * Insert a new depositor
   */
  async insertDepositor(leaf: DepositorLeaf): Promise<MerkleProofResult> {
    const userId = Buffer.from(leaf.id).toString('hex')

    if (this.depositorIndex.has(userId)) {
      throw new Error(`Depositor ${userId} already exists`)
    }

    const index = this.nextDepositorIndex++

    // Get path before insertion
    const pathBefore = this.depositorTree.getPath(index)

    // Hash and insert leaf
    const leafHash = this.hashDepositorLeaf(leaf)
    this.depositorTree.setLeaf(index, leafHash)

    // Store leaf data
    this.depositorLeaves.set(index, leaf)
    this.depositorIndex.set(userId, index)

    // Get new root
    const newRoot = this.depositorTree.getRoot()

    return {
      path: pathBefore,
      updatedLeaf: leaf,
      newRoot
    }
  }

  /**
   * Update an existing depositor
   */
  async updateDepositor(
    userId: Uint8Array,
    updater: (current: DepositorLeaf) => DepositorLeaf
  ): Promise<MerkleProofResult> {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.depositorIndex.get(userIdHex)

    if (index === undefined) {
      throw new Error(`Depositor ${userIdHex} not found`)
    }

    const currentLeaf = this.depositorLeaves.get(index)!
    const pathBefore = this.depositorTree.getPath(index)

    // Apply update
    const updatedLeaf = updater(currentLeaf)

    // Hash and update leaf
    const updatedLeafHash = this.hashDepositorLeaf(updatedLeaf)
    this.depositorTree.setLeaf(index, updatedLeafHash)
    this.depositorLeaves.set(index, updatedLeaf)

    // Get new root
    const newRoot = this.depositorTree.getRoot()

    return {
      path: pathBefore,
      currentLeaf,
      updatedLeaf,
      newRoot
    }
  }

  /**
   * Get depositor leaf
   */
  getDepositorLeaf(userId: Uint8Array): DepositorLeaf | undefined {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.depositorIndex.get(userIdHex)
    return index !== undefined ? this.depositorLeaves.get(index) : undefined
  }

  /**
   * Get depositor Merkle path
   */
  getDepositorPath(userId: Uint8Array): MerkleTreePath {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.depositorIndex.get(userIdHex)

    if (index === undefined) {
      throw new Error(`Depositor ${userIdHex} not found`)
    }

    return this.depositorTree.getPath(index)
  }

  /**
   * Check if depositor exists
   */
  hasDepositor(userId: Uint8Array): boolean {
    const userIdHex = Buffer.from(userId).toString('hex')
    return this.depositorIndex.has(userIdHex)
  }

  /**
   * Get depositors root
   */
  getDepositorsRoot(): Uint8Array {
    return this.depositorTree.getRoot()
  }

  // ==================== STAKER OPERATIONS ====================

  /**
   * Insert a new staker
   */
  async insertStaker(leaf: StakerLeaf): Promise<MerkleProofResult> {
    const userId = Buffer.from(leaf.id).toString('hex')

    if (this.stakerIndex.has(userId)) {
      throw new Error(`Staker ${userId} already exists`)
    }

    const index = this.nextStakerIndex++
    const pathBefore = this.stakerTree.getPath(index)

    const leafHash = this.hashStakerLeaf(leaf)
    this.stakerTree.setLeaf(index, leafHash)

    this.stakerLeaves.set(index, leaf)
    this.stakerIndex.set(userId, index)

    const newRoot = this.stakerTree.getRoot()

    return {
      path: pathBefore,
      updatedLeaf: leaf,
      newRoot
    }
  }

  /**
   * Update an existing staker
   */
  async updateStaker(
    userId: Uint8Array,
    updater: (current: StakerLeaf) => StakerLeaf
  ): Promise<MerkleProofResult> {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.stakerIndex.get(userIdHex)

    if (index === undefined) {
      throw new Error(`Staker ${userIdHex} not found`)
    }

    const currentLeaf = this.stakerLeaves.get(index)!
    const pathBefore = this.stakerTree.getPath(index)

    const updatedLeaf = updater(currentLeaf)
    const updatedLeafHash = this.hashStakerLeaf(updatedLeaf)
    this.stakerTree.setLeaf(index, updatedLeafHash)
    this.stakerLeaves.set(index, updatedLeaf)

    const newRoot = this.stakerTree.getRoot()

    return {
      path: pathBefore,
      currentLeaf,
      updatedLeaf,
      newRoot
    }
  }

  /**
   * Get staker leaf
   */
  getStakerLeaf(userId: Uint8Array): StakerLeaf | undefined {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.stakerIndex.get(userIdHex)
    return index !== undefined ? this.stakerLeaves.get(index) : undefined
  }

  /**
   * Get staker Merkle path
   */
  getStakerPath(userId: Uint8Array): MerkleTreePath {
    const userIdHex = Buffer.from(userId).toString('hex')
    const index = this.stakerIndex.get(userIdHex)

    if (index === undefined) {
      throw new Error(`Staker ${userIdHex} not found`)
    }

    return this.stakerTree.getPath(index)
  }

  /**
   * Check if staker exists
   */
  hasStaker(userId: Uint8Array): boolean {
    const userIdHex = Buffer.from(userId).toString('hex')
    return this.stakerIndex.has(userIdHex)
  }

  /**
   * Get stakers root
   */
  getStakersRoot(): Uint8Array {
    return this.stakerTree.getRoot()
  }

  // ==================== PERSISTENCE ====================

  /**
   * Export tree state for persistence
   */
  export(): any {
    return {
      depositorIndex: Array.from(this.depositorIndex.entries()),
      stakerIndex: Array.from(this.stakerIndex.entries()),
      depositorLeaves: Array.from(this.depositorLeaves.entries()).map(
        ([idx, leaf]) => ({
          index: idx,
          leaf: {
            id: Buffer.from(leaf.id).toString('hex'),
            metadataHash: Buffer.from(leaf.metadataHash).toString('hex'),
            position: leaf.position,
            coinType: Buffer.from(leaf.coinType).toString('hex'),
            mintCounterCommitment: Buffer.from(
              leaf.mintCounterCommitment
            ).toString('hex')
          }
        })
      ),
      stakerLeaves: Array.from(this.stakerLeaves.entries()).map(
        ([idx, leaf]) => ({
          index: idx,
          leaf: {
            id: Buffer.from(leaf.id).toString('hex'),
            metadataHash: Buffer.from(leaf.metadataHash).toString('hex')
          }
        })
      ),
      nextDepositorIndex: this.nextDepositorIndex,
      nextStakerIndex: this.nextStakerIndex
    }
  }

  /**
   * Import tree state from persistence
   */
  import(data: any): void {
    this.depositorIndex = new Map(data.depositorIndex)
    this.stakerIndex = new Map(data.stakerIndex)

    // Rebuild depositor leaves and tree
    for (const { index, leaf } of data.depositorLeaves) {
      const depositorLeaf: DepositorLeaf = {
        id: Buffer.from(leaf.id, 'hex'),
        metadataHash: Buffer.from(leaf.metadataHash, 'hex'),
        position: leaf.position,
        coinType: Buffer.from(leaf.coinType, 'hex'),
        mintCounterCommitment: Buffer.from(leaf.mintCounterCommitment, 'hex')
      }
      this.depositorLeaves.set(index, depositorLeaf)
      const leafHash = this.hashDepositorLeaf(depositorLeaf)
      this.depositorTree.setLeaf(index, leafHash)
    }

    // Rebuild staker leaves and tree
    for (const { index, leaf } of data.stakerLeaves) {
      const stakerLeaf: StakerLeaf = {
        id: Buffer.from(leaf.id, 'hex'),
        metadataHash: Buffer.from(leaf.metadataHash, 'hex')
      }
      this.stakerLeaves.set(index, stakerLeaf)
      const leafHash = this.hashStakerLeaf(stakerLeaf)
      this.stakerTree.setLeaf(index, leafHash)
    }

    this.nextDepositorIndex = data.nextDepositorIndex
    this.nextStakerIndex = data.nextStakerIndex
  }
}
