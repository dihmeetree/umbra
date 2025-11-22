import type { CircuitContext } from '@midnight-ntwrk/compact-runtime'
import { SimulatorError, SimulatorErrorCode } from './errors.js'

/**
 * Represents a snapshot of the simulator state
 */
export interface Snapshot<TPrivateState> {
  id: string
  context: CircuitContext<TPrivateState>
  timestamp: number
}

/**
 * Manages snapshots of simulator state for testing
 *
 * This allows you to save and restore contract state at different points,
 * useful for testing different scenarios from the same starting point
 */
export class SnapshotManager<TPrivateState> {
  private snapshots: Map<string, Snapshot<TPrivateState>> = new Map()
  private autoIncrementId: number = 0

  /**
   * Creates a snapshot of the current state
   *
   * @param context - The circuit context to snapshot
   * @param id - Optional ID for the snapshot (auto-generated if not provided)
   * @returns The ID of the created snapshot
   */
  create(context: CircuitContext<TPrivateState>, id?: string): string {
    const snapshotId = id || `snapshot_${this.autoIncrementId++}`

    // Deep clone the context to avoid mutations
    const snapshot: Snapshot<TPrivateState> = {
      id: snapshotId,
      context: this.cloneContext(context),
      timestamp: Date.now()
    }

    this.snapshots.set(snapshotId, snapshot)
    return snapshotId
  }

  /**
   * Restores a previously saved snapshot
   *
   * @param id - The ID of the snapshot to restore
   * @returns The restored circuit context
   * @throws If the snapshot ID doesn't exist
   */
  restore(id: string): CircuitContext<TPrivateState> {
    const snapshot = this.snapshots.get(id)

    if (!snapshot) {
      throw new SimulatorError(
        SimulatorErrorCode.INVALID_SNAPSHOT,
        `Snapshot '${id}' not found`,
        { availableSnapshots: Array.from(this.snapshots.keys()) }
      )
    }

    // Return a deep clone to avoid mutations
    return this.cloneContext(snapshot.context)
  }

  /**
   * Checks if a snapshot exists
   *
   * @param id - The ID of the snapshot
   * @returns True if the snapshot exists
   */
  has(id: string): boolean {
    return this.snapshots.has(id)
  }

  /**
   * Deletes a snapshot
   *
   * @param id - The ID of the snapshot to delete
   * @returns True if the snapshot was deleted, false if it didn't exist
   */
  delete(id: string): boolean {
    return this.snapshots.delete(id)
  }

  /**
   * Gets all snapshot IDs
   */
  getSnapshotIds(): string[] {
    return Array.from(this.snapshots.keys())
  }

  /**
   * Gets information about all snapshots
   */
  listSnapshots(): Array<{ id: string; timestamp: number; age: number }> {
    const now = Date.now()
    return Array.from(this.snapshots.values()).map((snapshot) => ({
      id: snapshot.id,
      timestamp: snapshot.timestamp,
      age: now - snapshot.timestamp
    }))
  }

  /**
   * Clears all snapshots
   */
  clear(): void {
    this.snapshots.clear()
    this.autoIncrementId = 0
  }

  /**
   * Gets the number of stored snapshots
   */
  get count(): number {
    return this.snapshots.size
  }

  /**
   * Deep clones a circuit context
   * Note: This uses JSON serialization which works for most cases
   * but may not work if the context contains non-serializable objects
   */
  private cloneContext(
    context: CircuitContext<TPrivateState>
  ): CircuitContext<TPrivateState> {
    // For now, we'll use structured cloning approach
    // This works for most Midnight types which are serializable
    try {
      return JSON.parse(JSON.stringify(context))
    } catch (error) {
      // Fallback to shallow clone if JSON serialization fails
      console.warn('Failed to deep clone context, using shallow clone')
      return { ...context }
    }
  }
}
