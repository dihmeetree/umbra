import type {
  CircuitContext,
  ContractAddress,
  ZswapLocalState,
  EncodedQualifiedCoinInfo
} from '@midnight-ntwrk/compact-runtime'
import {
  constructorContext,
  decodeZswapLocalState,
  QueryContext,
  sampleContractAddress
} from '@midnight-ntwrk/compact-runtime'
import type * as ocrt from '@midnight-ntwrk/onchain-runtime'
import { encodeCoinPublicKey } from '@midnight-ntwrk/onchain-runtime'
import { TokenType } from '@midnight-ntwrk/zswap'
import { encodeTokenType } from '@midnight-ntwrk/ledger'
import type {
  ContractWithCircuits,
  ContractConfig,
  OutputInfo
} from './types.js'
import { logger } from './logger.js'
import { SnapshotManager } from './snapshot.js'
import {
  CircuitNotFoundError,
  MultipleOutputsError,
  CircuitExecutionError
} from './errors.js'

/**
 * Generic contract simulator for Midnight Compact contracts
 *
 * This class provides a flexible simulation environment for deploying and interacting
 * with Compact contracts. It manages circuit contexts, private state, and provides
 * utilities for balance management and output tracking.
 *
 * @template TPrivateState - The type of the contract's private state
 */
export class ContractSimulator<TPrivateState> {
  readonly contract: ContractWithCircuits<TPrivateState>
  readonly contractAddress: ContractAddress
  protected circuitContext: CircuitContext<TPrivateState>
  private snapshots: SnapshotManager<TPrivateState>

  /**
   * Creates a new contract simulator instance
   *
   * @param contract - The compiled contract instance with circuits
   * @param config - Configuration for initializing the contract
   */
  constructor(
    contract: ContractWithCircuits<TPrivateState>,
    config: ContractConfig<TPrivateState>
  ) {
    this.contract = contract
    this.contractAddress = config.contractAddress
    this.snapshots = new SnapshotManager<TPrivateState>()

    logger.debug('Initializing contract simulator', {
      contractAddress: config.contractAddress,
      hasCoinPublicKey: !!config.coinPublicKey
    })

    const constructorCtx = constructorContext(
      config.initialPrivateState,
      config.coinPublicKey
    )

    // Some contracts expect nonce as a separate parameter, others don't
    // If constructorArgs is provided, we assume the contract doesn't take nonce separately
    const {
      currentPrivateState,
      currentContractState,
      currentZswapLocalState
    } =
      config.constructorArgs && config.constructorArgs.length > 0
        ? (this.contract.initialState as any)(
            constructorCtx,
            ...config.constructorArgs
          )
        : this.contract.initialState(
            constructorCtx,
            config.nonce,
            ...(config.constructorArgs || [])
          )

    this.circuitContext = {
      currentPrivateState,
      currentZswapLocalState,
      originalState: currentContractState,
      transactionContext: new QueryContext(
        currentContractState.data,
        config.contractAddress
      )
    }

    logger.debug('Contract simulator initialized successfully')
  }

  /**
   * Creates a new simulator instance with a different contract address
   * Useful for deploying multiple instances of the same contract
   */
  static deploy<TPrivateState>(
    contract: ContractWithCircuits<TPrivateState>,
    config: Omit<ContractConfig<TPrivateState>, 'contractAddress'>
  ): ContractSimulator<TPrivateState> {
    return new ContractSimulator(contract, {
      ...config,
      contractAddress: sampleContractAddress()
    })
  }

  /**
   * Switches the private state context for the simulator
   * This allows simulating transactions from different users
   *
   * @param privateState - The new private state to use
   * @param coinPublicKey - Optional: also update the public key context for this execution
   * @returns This simulator instance for method chaining
   */
  as(privateState: TPrivateState, coinPublicKey?: string): this {
    logger.trace('Switching context', {
      hasCoinPublicKey: !!coinPublicKey,
      coinPublicKeyProvided: coinPublicKey !== undefined
    })

    this.circuitContext = {
      ...this.circuitContext,
      currentPrivateState: privateState
    }

    // If a new public key is provided, update the ZSwap local state
    // ownPublicKey() reads from circuitContext.currentZswapLocalState.coinPublicKey
    if (coinPublicKey !== undefined) {
      const encodedPublicKey = { bytes: encodeCoinPublicKey(coinPublicKey) }
      logger.trace('Setting coinPublicKey in ZSwap local state')

      this.circuitContext = {
        ...this.circuitContext,
        currentZswapLocalState: {
          ...this.circuitContext.currentZswapLocalState,
          coinPublicKey: encodedPublicKey as any
        }
      }
    }

    return this
  }

  /**
   * Gets the current ledger state
   */
  getLedger(): any {
    return this.circuitContext.transactionContext.state
  }

  /**
   * Gets the current private state
   */
  getPrivateState(): TPrivateState {
    return this.circuitContext.currentPrivateState
  }

  /**
   * Gets the current ZSwap local state containing outputs
   */
  getZswapLocalState(): ZswapLocalState {
    return decodeZswapLocalState(this.circuitContext.currentZswapLocalState)
  }

  /**
   * Gets all outputs from the last circuit execution
   */
  getOutputs(): OutputInfo[] {
    const zswapState = this.getZswapLocalState()
    return zswapState.outputs.map((output) => ({
      recipient: output.recipient.is_left
        ? output.recipient.left
        : output.recipient.right,
      coinInfo: output.coinInfo
    }))
  }

  /**
   * Gets a single output for a specific recipient
   * Throws an error if multiple outputs are found
   *
   * @param recipient - The recipient's coin public key
   * @returns The coin info for the recipient, or undefined if not found
   */
  getOutputByRecipient(
    recipient: ocrt.CoinPublicKey
  ): ocrt.CoinInfo | undefined {
    const zswapState = this.getZswapLocalState()
    const outputs = zswapState.outputs.filter(
      (output) => output.recipient.left === recipient
    )

    if (outputs.length === 0) {
      return undefined
    } else if (outputs.length > 1) {
      throw new MultipleOutputsError(recipient, outputs.length)
    }

    return outputs[0].coinInfo
  }

  /**
   * Gets all outputs for a specific recipient
   *
   * @param recipient - The recipient's coin public key
   * @returns Array of coin infos for the recipient
   */
  getOutputsByRecipient(recipient: ocrt.CoinPublicKey): ocrt.CoinInfo[] {
    const zswapState = this.getZswapLocalState()
    return zswapState.outputs
      .filter((output) => output.recipient.left === recipient)
      .map((output) => output.coinInfo)
  }

  /**
   * Gets the balance of a specific token type for a recipient
   *
   * @param recipient - The recipient's coin public key
   * @param tokenType - The token type to check
   * @returns The total balance of the token type
   */
  getBalance(recipient: ocrt.CoinPublicKey, tokenType: TokenType): bigint {
    const outputs = this.getOutputsByRecipient(recipient)
    return outputs
      .filter((output) => output.type === tokenType)
      .reduce((sum, output) => sum + output.value, 0n)
  }

  /**
   * Gets all token balances for a recipient
   *
   * @param recipient - The recipient's coin public key
   * @returns A record mapping token types to their balances
   */
  getAllBalances(recipient: ocrt.CoinPublicKey): Record<string, bigint> {
    const outputs = this.getOutputsByRecipient(recipient)
    const balances: Record<string, bigint> = {}

    for (const output of outputs) {
      const tokenKey = output.type.toString()
      balances[tokenKey] = (balances[tokenKey] || 0n) + output.value
    }

    return balances
  }

  /**
   * Converts a nonce to Uint8Array (handles both hex string and Uint8Array inputs)
   */
  private nonceToBytes(nonce: string | Uint8Array): Uint8Array {
    // If already Uint8Array, return as-is
    if (nonce instanceof Uint8Array) {
      return nonce
    }

    // Convert hex string to bytes
    const cleanHex = nonce.replace(/^0x/, '')
    const bytes = new Uint8Array(cleanHex.length / 2)
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16)
    }
    return bytes
  }

  /**
   * Adds a coin to the ZSwap inputs for the next circuit execution
   * This allows circuits that call receive() to find and consume the coin
   *
   * IMPORTANT: Call this BEFORE executing a circuit that expects to receive coins
   *
   * @param coinInfo - The coin to make available as input
   */
  addCoinInput(coinInfo: ocrt.CoinInfo): void {
    logger.trace('Adding coin input', {
      value: coinInfo.value
    })

    // Work directly with the encoded state to avoid type issues
    const currentEncoded = this.circuitContext.currentZswapLocalState

    // Create an EncodedQualifiedCoinInfo for the ZSwap local state
    // This is what the circuit runtime expects in the inputs array
    const encodedCoin: EncodedQualifiedCoinInfo = {
      nonce: this.nonceToBytes(coinInfo.nonce),
      color: encodeTokenType(coinInfo.type),
      value: coinInfo.value,
      mt_index: 0n // Default to 0 for testing
    }

    // Add the encoded coin to inputs so receive() can find it
    this.circuitContext = {
      ...this.circuitContext,
      currentZswapLocalState: {
        ...currentEncoded,
        inputs: [...currentEncoded.inputs, encodedCoin]
      }
    }
  }

  /**
   * Clears all coin inputs
   * Useful for resetting state between test operations
   */
  clearCoinInputs(): void {
    logger.trace('Clearing coin inputs')
    this.circuitContext = {
      ...this.circuitContext,
      currentZswapLocalState: {
        ...this.circuitContext.currentZswapLocalState,
        inputs: []
      }
    }
  }

  /**
   * Executes a pure circuit (read-only operation)
   *
   * @param circuitName - The name of the circuit to execute
   * @param args - Arguments to pass to the circuit
   * @returns The result of the circuit execution
   */
  executeCircuit(circuitName: string, ...args: any[]): any {
    const circuit = this.contract.circuits[circuitName]
    if (!circuit) {
      throw new CircuitNotFoundError(circuitName, true)
    }

    logger.debug(`Executing circuit: ${circuitName}`)

    try {
      const result = circuit(this.circuitContext, ...args)
      this.circuitContext = result.context
      logger.debug(`Circuit ${circuitName} completed successfully`)
      return result
    } catch (error) {
      logger.error(`Circuit ${circuitName} failed:`, (error as Error).message)
      throw new CircuitExecutionError(circuitName, error as Error)
    }
  }

  /**
   * Executes an impure circuit (state-modifying operation)
   *
   * @param circuitName - The name of the impure circuit to execute
   * @param args - Arguments to pass to the circuit
   * @returns The result of the circuit execution
   */
  executeImpureCircuit(circuitName: string, ...args: any[]): any {
    const circuit = this.contract.impureCircuits[circuitName]
    if (!circuit) {
      throw new CircuitNotFoundError(circuitName, false)
    }

    logger.debug(`Executing impure circuit: ${circuitName}`)

    try {
      const result = circuit(this.circuitContext, ...args)
      this.circuitContext = result.context
      logger.debug(`Impure circuit ${circuitName} completed successfully`)
      return result
    } catch (error) {
      logger.error(
        `Impure circuit ${circuitName} failed:`,
        (error as Error).message
      )
      throw new CircuitExecutionError(circuitName, error as Error)
    }
  }

  /**
   * Gets the current circuit context
   * Useful for advanced operations and debugging
   */
  getContext(): CircuitContext<TPrivateState> {
    return this.circuitContext
  }

  /**
   * Sets the circuit context directly
   * Use with caution - this is for advanced operations
   */
  setContext(context: CircuitContext<TPrivateState>): void {
    this.circuitContext = context
  }

  // ==================== SNAPSHOT MANAGEMENT ====================

  /**
   * Creates a snapshot of the current state
   *
   * @param id - Optional ID for the snapshot
   * @returns The ID of the created snapshot
   */
  createSnapshot(id?: string): string {
    const snapshotId = this.snapshots.create(this.circuitContext, id)
    logger.debug(`Created snapshot: ${snapshotId}`)
    return snapshotId
  }

  /**
   * Restores a previously saved snapshot
   *
   * @param id - The ID of the snapshot to restore
   */
  restoreSnapshot(id: string): void {
    logger.debug(`Restoring snapshot: ${id}`)
    this.circuitContext = this.snapshots.restore(id)
  }

  /**
   * Deletes a snapshot
   *
   * @param id - The ID of the snapshot to delete
   * @returns True if the snapshot was deleted
   */
  deleteSnapshot(id: string): boolean {
    const deleted = this.snapshots.delete(id)
    if (deleted) {
      logger.debug(`Deleted snapshot: ${id}`)
    }
    return deleted
  }

  /**
   * Gets all snapshot IDs
   */
  getSnapshotIds(): string[] {
    return this.snapshots.getSnapshotIds()
  }

  /**
   * Clears all snapshots
   */
  clearSnapshots(): void {
    this.snapshots.clear()
    logger.debug('Cleared all snapshots')
  }

  // ==================== INSPECTION UTILITIES ====================

  /**
   * Creates a ledger inspector for examining ledger state
   *
   * @returns A LedgerInspector instance
   */
  inspect(): any {
    // Import dynamically to avoid circular dependency
    const { LedgerInspector } = require('./LedgerInspector.js')
    return new LedgerInspector(this)
  }

  /**
   * Prints a summary of the current ledger state
   * Convenience method that creates an inspector and prints
   */
  printLedgerSummary(): void {
    const inspector = this.inspect()
    inspector.printSummary()
  }
}
