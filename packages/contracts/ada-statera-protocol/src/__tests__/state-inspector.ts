/**
 * Contract State Inspector
 *
 * Tools for inspecting, comparing, and visualizing contract state in tests
 */

import type { ContractSimulator } from '@statera/simulator'
import type { StateraPrivateState } from '../index.js'
import { TestData } from './test-data.js'

/**
 * State snapshot for comparison
 */
export interface StateSnapshot {
  timestamp: number
  label: string
  privateState: StateraPrivateState
  ledgerState: any
}

/**
 * State difference
 */
export interface StateDiff {
  field: string
  before: any
  after: any
  changed: boolean
}

/**
 * Contract State Inspector
 */
export class StateInspector {
  private snapshots: StateSnapshot[] = []

  constructor(private simulator: ContractSimulator<StateraPrivateState>) {}

  /**
   * Take a snapshot of current state
   */
  snapshot(label: string): StateSnapshot {
    const snapshot: StateSnapshot = {
      timestamp: Date.now(),
      label,
      privateState: this.simulator.getPrivateState(),
      ledgerState: this.simulator.getLedger()
    }

    this.snapshots.push(snapshot)
    return snapshot
  }

  /**
   * Get all snapshots
   */
  getSnapshots(): readonly StateSnapshot[] {
    return this.snapshots
  }

  /**
   * Compare two snapshots
   */
  compare(label1: string, label2: string): StateDiff[] {
    const snap1 = this.snapshots.find((s) => s.label === label1)
    const snap2 = this.snapshots.find((s) => s.label === label2)

    if (!snap1 || !snap2) {
      throw new Error(`Snapshot not found: ${label1} or ${label2}`)
    }

    return this.diffStates(snap1.privateState, snap2.privateState)
  }

  /**
   * Diff two private states
   */
  private diffStates(
    before: StateraPrivateState,
    after: StateraPrivateState
  ): StateDiff[] {
    const diffs: StateDiff[] = []

    // Compare mint metadata
    if (before.mint_metadata.collateral !== after.mint_metadata.collateral) {
      diffs.push({
        field: 'mint_metadata.collateral',
        before: before.mint_metadata.collateral,
        after: after.mint_metadata.collateral,
        changed: true
      })
    }

    if (before.mint_metadata.debt !== after.mint_metadata.debt) {
      diffs.push({
        field: 'mint_metadata.debt',
        before: before.mint_metadata.debt,
        after: after.mint_metadata.debt,
        changed: true
      })
    }

    // Compare stake metadata
    if (
      before.stake_metadata.effectiveBalance !==
      after.stake_metadata.effectiveBalance
    ) {
      diffs.push({
        field: 'stake_metadata.effectiveBalance',
        before: before.stake_metadata.effectiveBalance,
        after: after.stake_metadata.effectiveBalance,
        changed: true
      })
    }

    if (
      before.stake_metadata.stakeReward !== after.stake_metadata.stakeReward
    ) {
      diffs.push({
        field: 'stake_metadata.stakeReward',
        before: before.stake_metadata.stakeReward,
        after: after.stake_metadata.stakeReward,
        changed: true
      })
    }

    // Compare admin metadata
    if (
      before.admin_metadata.protocolFeePool !==
      after.admin_metadata.protocolFeePool
    ) {
      diffs.push({
        field: 'admin_metadata.protocolFeePool',
        before: before.admin_metadata.protocolFeePool,
        after: after.admin_metadata.protocolFeePool,
        changed: true
      })
    }

    // Compare mint counter
    if (before.mint_counter !== after.mint_counter) {
      diffs.push({
        field: 'mint_counter',
        before: before.mint_counter,
        after: after.mint_counter,
        changed: true
      })
    }

    return diffs
  }

  /**
   * Pretty print state
   */
  printState(state: StateraPrivateState): string {
    return `
Private State:
==============
Mint Metadata:
  Collateral: ${state.mint_metadata.collateral}
  Debt: ${state.mint_metadata.debt}
  Health Factor: ${this.calculateHealthFactor(state.mint_metadata.collateral, state.mint_metadata.debt)}

Stake Metadata:
  Effective Balance: ${state.stake_metadata.effectiveBalance}
  Stake Reward: ${state.stake_metadata.stakeReward}
  Entry ADA/sUSD Index: ${state.stake_metadata.entry_ADA_SUSD_index}
  Entry Scale Factor: ${state.stake_metadata.entry_scale_factor}

Admin Metadata:
  Protocol Fee Pool: ${state.admin_metadata.protocolFeePool}
  Super Admin: ${Buffer.from(state.admin_metadata.super_admin).toString('hex').slice(0, 16)}...
  Admin Count: ${state.admin_metadata.admin_count}

Mint Counter: ${state.mint_counter}
Has Stake Pool Coin: ${state.stake_pool_coin !== null}
Has Reserve Pool Coin: ${state.reserve_pool_coin !== null}
    `.trim()
  }

  /**
   * Print diff between snapshots
   */
  printDiff(label1: string, label2: string): string {
    const diffs = this.compare(label1, label2)

    if (diffs.length === 0) {
      return `No changes between "${label1}" and "${label2}"`
    }

    return `
State Changes: ${label1} → ${label2}
${'='.repeat(50)}
${diffs.map((d) => `${d.field}: ${d.before} → ${d.after}`).join('\n')}
    `.trim()
  }

  /**
   * Calculate health factor
   */
  private calculateHealthFactor(collateral: bigint, debt: bigint): string {
    if (debt === 0n) return '∞ (no debt)'

    const hf = TestData.thresholds.calculateHealthFactor(
      collateral,
      debt,
      TestData.thresholds.DEFAULT_LIQUIDATION
    )

    return `${hf} (${hf >= 1n ? 'healthy' : 'liquidatable'})`
  }

  /**
   * Export state as JSON
   */
  exportState(state: StateraPrivateState): string {
    return JSON.stringify(
      {
        mintMetadata: {
          collateral: state.mint_metadata.collateral.toString(),
          debt: state.mint_metadata.debt.toString()
        },
        stakeMetadata: {
          effectiveBalance: state.stake_metadata.effectiveBalance.toString(),
          stakeReward: state.stake_metadata.stakeReward.toString(),
          entryADASUSDIndex:
            state.stake_metadata.entry_ADA_SUSD_index.toString(),
          entryScaleFactor: state.stake_metadata.entry_scale_factor.toString()
        },
        adminMetadata: {
          protocolFeePool: state.admin_metadata.protocolFeePool.toString(),
          adminCount: state.admin_metadata.admin_count.toString()
        },
        mintCounter: state.mint_counter.toString()
      },
      null,
      2
    )
  }

  /**
   * Clear all snapshots
   */
  clear(): void {
    this.snapshots = []
  }
}

/**
 * Create a state inspector for a simulator
 */
export function inspectState(
  simulator: ContractSimulator<StateraPrivateState>
): StateInspector {
  return new StateInspector(simulator)
}

/**
 * Quick state inspection utility
 */
export function logState(
  simulator: ContractSimulator<StateraPrivateState>,
  label?: string
): void {
  const inspector = new StateInspector(simulator)
  const state = simulator.getPrivateState()

  console.log(`\n${label ? `[${label}] ` : ''}State Inspection:`)
  console.log(inspector.printState(state))
  console.log('')
}
