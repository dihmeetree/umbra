/**
 * Simulator Extensions
 *
 * Additional functionality for ContractSimulator including history tracking,
 * event collection, and execution metrics
 */

import type { ContractSimulator } from './ContractSimulator.js'

/**
 * Transaction history entry
 */
export interface HistoryEntry<TPrivateState> {
  timestamp: number
  circuitName: string
  circuitType: 'pure' | 'impure'
  args: any[]
  result?: any
  error?: Error
  stateBefore: TPrivateState
  stateAfter?: TPrivateState
  duration: number
}

/**
 * Execution metrics
 */
export interface ExecutionMetrics {
  totalCircuits: number
  pureCircuits: number
  impureCircuits: number
  errors: number
  totalDuration: number
  averageDuration: number
  circuitCounts: Record<string, number>
}

/**
 * Event log entry
 */
export interface EventLogEntry {
  timestamp: number
  type: string
  data: any
  circuitName?: string
}

/**
 * Simulator History Tracker
 *
 * Wraps a ContractSimulator to track execution history, events, and metrics
 */
export class SimulatorHistoryTracker<TPrivateState> {
  private history: HistoryEntry<TPrivateState>[] = []
  private events: EventLogEntry[] = []
  private startTime: number

  constructor(private simulator: ContractSimulator<TPrivateState>) {
    this.startTime = Date.now()
  }

  /**
   * Execute a circuit and track it
   */
  async executeWithTracking(
    circuitName: string,
    circuitType: 'pure' | 'impure',
    args: any[]
  ): Promise<any> {
    const startTime = performance.now()
    const stateBefore = this.simulator.getPrivateState()

    const entry: HistoryEntry<TPrivateState> = {
      timestamp: Date.now(),
      circuitName,
      circuitType,
      args,
      stateBefore,
      duration: 0
    }

    try {
      const result =
        circuitType === 'pure'
          ? this.simulator.executeCircuit(circuitName, ...args)
          : this.simulator.executeImpureCircuit(circuitName, ...args)

      entry.result = result
      entry.stateAfter = this.simulator.getPrivateState()
      entry.duration = performance.now() - startTime

      this.history.push(entry)
      this.logEvent('circuit_success', {
        circuitName,
        duration: entry.duration
      })

      return result
    } catch (error) {
      entry.error = error as Error
      entry.duration = performance.now() - startTime

      this.history.push(entry)
      this.logEvent('circuit_error', {
        circuitName,
        error: (error as Error).message
      })

      throw error
    }
  }

  /**
   * Log a custom event
   */
  logEvent(type: string, data: any, circuitName?: string): void {
    this.events.push({
      timestamp: Date.now(),
      type,
      data,
      circuitName
    })
  }

  /**
   * Get execution history
   */
  getHistory(): readonly HistoryEntry<TPrivateState>[] {
    return this.history
  }

  /**
   * Get event log
   */
  getEvents(): readonly EventLogEntry[] {
    return this.events
  }

  /**
   * Get execution metrics
   */
  getMetrics(): ExecutionMetrics {
    const circuitCounts: Record<string, number> = {}

    for (const entry of this.history) {
      circuitCounts[entry.circuitName] =
        (circuitCounts[entry.circuitName] || 0) + 1
    }

    const totalDuration = this.history.reduce(
      (sum, entry) => sum + entry.duration,
      0
    )

    return {
      totalCircuits: this.history.length,
      pureCircuits: this.history.filter((e) => e.circuitType === 'pure').length,
      impureCircuits: this.history.filter((e) => e.circuitType === 'impure')
        .length,
      errors: this.history.filter((e) => e.error).length,
      totalDuration,
      averageDuration:
        this.history.length > 0 ? totalDuration / this.history.length : 0,
      circuitCounts
    }
  }

  /**
   * Get history for a specific circuit
   */
  getCircuitHistory(circuitName: string): HistoryEntry<TPrivateState>[] {
    return this.history.filter((e) => e.circuitName === circuitName)
  }

  /**
   * Get errors from history
   */
  getErrors(): HistoryEntry<TPrivateState>[] {
    return this.history.filter((e) => e.error)
  }

  /**
   * Clear history and events
   */
  clear(): void {
    this.history = []
    this.events = []
    this.startTime = Date.now()
  }

  /**
   * Get summary report
   */
  getSummary(): string {
    const metrics = this.getMetrics()
    const errors = this.getErrors()

    return `
Simulator Execution Summary
===========================
Total Circuits: ${metrics.totalCircuits}
Pure Circuits: ${metrics.pureCircuits}
Impure Circuits: ${metrics.impureCircuits}
Errors: ${metrics.errors}
Total Duration: ${metrics.totalDuration.toFixed(2)}ms
Average Duration: ${metrics.averageDuration.toFixed(2)}ms

Circuit Breakdown:
${Object.entries(metrics.circuitCounts)
  .map(([name, count]) => `  ${name}: ${count}`)
  .join('\n')}

${errors.length > 0 ? `\nErrors:\n${errors.map((e) => `  ${e.circuitName}: ${e.error?.message}`).join('\n')}` : ''}
    `.trim()
  }
}

/**
 * Create a history tracker for a simulator
 */
export function withHistory<TPrivateState>(
  simulator: ContractSimulator<TPrivateState>
): SimulatorHistoryTracker<TPrivateState> {
  return new SimulatorHistoryTracker(simulator)
}
