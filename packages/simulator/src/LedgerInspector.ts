import type { ContractSimulator } from './ContractSimulator.js';
import { logger } from './logger.js';

/**
 * Information about a Merkle tree in the ledger
 */
export interface MerkleTreeInfo {
  firstFree: bigint;
  root: {
    field: bigint;
  };
  isFull: boolean;
  history: Array<{ field: bigint }>;
  depth: number;
}

/**
 * Inspector for examining ledger state in detail
 *
 * Provides convenient methods for inspecting Merkle trees, maps, and global state
 * without needing to manually create ledger accessors
 *
 * @example
 * ```typescript
 * const inspector = new LedgerInspector(simulator);
 *
 * // Inspect Merkle trees
 * const treeInfo = inspector.getMerkleTreeInfo('depositorCommitments');
 * console.log(`Tree has ${treeInfo.firstFree} elements`);
 *
 * // Check global state
 * const isPaused = inspector.getGlobalState('isPaused');
 *
 * // Print summary
 * inspector.printSummary();
 * ```
 */
export class LedgerInspector<TPrivateState> {
  private simulator: ContractSimulator<TPrivateState>;
  private ledgerAccessor: any;

  constructor(simulator: ContractSimulator<TPrivateState>) {
    this.simulator = simulator;
    this.ledgerAccessor = this.createLedgerAccessor();
  }

  /**
   * Creates a ledger accessor from the current simulator state
   * This uses the contract's ledger accessor if available
   */
  private createLedgerAccessor(): any {
    const rawLedger = this.simulator.getLedger();

    // Try to get the ledger accessor from the contract
    // Most contracts export a `ledger` function that takes raw ledger state
    try {
      // Check if the contract has a ledger accessor
      const contract = (this.simulator as any).contract;
      if (contract.ledger) {
        return contract.ledger(rawLedger);
      }
    } catch (e) {
      logger.warn('Could not create ledger accessor from contract, using raw ledger');
    }

    // Fallback to raw ledger
    return rawLedger;
  }

  /**
   * Refreshes the ledger accessor to reflect current state
   */
  refresh(): void {
    this.ledgerAccessor = this.createLedgerAccessor();
  }

  /**
   * Gets detailed information about a Merkle tree in the ledger
   *
   * @param treeName - Name of the Merkle tree (e.g., 'depositorCommitments')
   * @returns Information about the tree
   */
  getMerkleTreeInfo(treeName: string): MerkleTreeInfo | null {
    try {
      const tree = this.ledgerAccessor[treeName];
      if (!tree) {
        logger.warn(`Merkle tree '${treeName}' not found in ledger`);
        return null;
      }

      // Try to get tree info
      const info: MerkleTreeInfo = {
        firstFree: tree.firstFree ? tree.firstFree() : 0n,
        root: tree.root ? tree.root() : { field: 0n },
        isFull: tree.isFull ? tree.isFull() : false,
        history: [],
        depth: 20, // Default depth for Midnight trees
      };

      // Try to get history
      if (tree.history) {
        try {
          info.history = Array.from(tree.history());
        } catch (e) {
          logger.debug('Could not retrieve tree history');
        }
      }

      return info;
    } catch (error) {
      logger.error(`Error inspecting Merkle tree '${treeName}':`, (error as Error).message);
      return null;
    }
  }

  /**
   * Checks if a specific commitment exists in a Merkle tree's history
   *
   * @param treeName - Name of the Merkle tree
   * @param commitment - The commitment to search for (as bytes)
   * @returns True if found in the tree
   */
  hasCommitmentInHistory(treeName: string, commitment: Uint8Array): boolean {
    try {
      const tree = this.ledgerAccessor[treeName];
      if (!tree || !tree.findPathForLeaf) {
        return false;
      }

      const path = tree.findPathForLeaf(commitment);
      return path !== null && path !== undefined;
    } catch (error) {
      logger.debug(`Error checking commitment in ${treeName}:`, (error as Error).message);
      return false;
    }
  }

  /**
   * Gets the contents of a map in the ledger
   *
   * @param mapName - Name of the map (e.g., 'depositorNullifiers')
   * @returns Object with map information
   */
  getMapInfo(mapName: string): { isEmpty: boolean; size?: number } | null {
    try {
      const map = this.ledgerAccessor[mapName];
      if (!map) {
        logger.warn(`Map '${mapName}' not found in ledger`);
        return null;
      }

      const info: { isEmpty: boolean; size?: number } = {
        isEmpty: map.isEmpty ? map.isEmpty() : true,
      };

      // Try to get size if available
      if (map.size) {
        try {
          info.size = Number(map.size());
        } catch (e) {
          logger.debug('Could not get map size');
        }
      }

      return info;
    } catch (error) {
      logger.error(`Error inspecting map '${mapName}':`, (error as Error).message);
      return null;
    }
  }

  /**
   * Checks if a value exists in a set
   *
   * @param setName - Name of the set
   * @param value - The value to check (as bytes)
   * @returns True if the value is in the set
   */
  isInSet(setName: string, value: Uint8Array): boolean {
    try {
      const set = this.ledgerAccessor[setName];
      if (!set || !set.member) {
        return false;
      }

      return set.member(value);
    } catch (error) {
      logger.debug(`Error checking set membership in ${setName}:`, (error as Error).message);
      return false;
    }
  }

  /**
   * Gets a global state value from the ledger
   *
   * @param fieldName - Name of the global state field
   * @returns The value, or undefined if not found
   */
  getGlobalState(fieldName: string): any {
    try {
      // Global state is usually accessed directly on the ledger accessor
      if (this.ledgerAccessor[fieldName] !== undefined) {
        return this.ledgerAccessor[fieldName];
      }

      // Or might be a function call
      if (typeof this.ledgerAccessor[fieldName] === 'function') {
        return this.ledgerAccessor[fieldName]();
      }

      logger.warn(`Global state field '${fieldName}' not found`);
      return undefined;
    } catch (error) {
      logger.error(`Error reading global state '${fieldName}':`, (error as Error).message);
      return undefined;
    }
  }

  /**
   * Prints a formatted summary of the ledger state
   */
  printSummary(): void {
    console.log('\n╔══════════════════════════════════════╗');
    console.log('║       LEDGER STATE SUMMARY           ║');
    console.log('╚══════════════════════════════════════╝\n');

    // List all available properties
    const properties = Object.keys(this.ledgerAccessor);

    // Separate by type
    const trees: string[] = [];
    const maps: string[] = [];
    const globals: string[] = [];

    for (const prop of properties) {
      const value = this.ledgerAccessor[prop];

      // Check if it's a Merkle tree (has firstFree, root methods)
      if (value && typeof value === 'object' && value.firstFree && value.root) {
        trees.push(prop);
      }
      // Check if it's a map (has isEmpty method)
      else if (value && typeof value === 'object' && value.isEmpty) {
        maps.push(prop);
      }
      // Otherwise it's global state
      else {
        globals.push(prop);
      }
    }

    // Print Merkle trees
    if (trees.length > 0) {
      console.log('📊 MERKLE TREES:');
      for (const treeName of trees) {
        const info = this.getMerkleTreeInfo(treeName);
        if (info) {
          console.log(`  • ${treeName}:`);
          console.log(`      Elements: ${info.firstFree}`);
          console.log(`      Root: ${info.root.field.toString().slice(0, 16)}...`);
          console.log(`      Full: ${info.isFull}`);
          console.log(`      History: ${info.history.length} roots`);
        }
      }
      console.log('');
    }

    // Print maps
    if (maps.length > 0) {
      console.log('🗺️  MAPS/SETS:');
      for (const mapName of maps) {
        const info = this.getMapInfo(mapName);
        if (info) {
          console.log(`  • ${mapName}:`);
          console.log(`      Empty: ${info.isEmpty}`);
          if (info.size !== undefined) {
            console.log(`      Size: ${info.size}`);
          }
        }
      }
      console.log('');
    }

    // Print global state
    if (globals.length > 0) {
      console.log('🌍 GLOBAL STATE:');
      for (const fieldName of globals) {
        const value = this.getGlobalState(fieldName);
        console.log(`  • ${fieldName}: ${this.formatValue(value)}`);
      }
      console.log('');
    }
  }

  /**
   * Formats a value for display
   */
  private formatValue(value: any): string {
    if (value === null || value === undefined) {
      return 'null';
    }
    if (typeof value === 'bigint') {
      return value.toString();
    }
    if (typeof value === 'object') {
      return JSON.stringify(value).slice(0, 50) + '...';
    }
    return String(value);
  }

  /**
   * Gets the raw ledger accessor for advanced operations
   */
  getRawLedger(): any {
    return this.ledgerAccessor;
  }

  /**
   * Checks if a specific ledger field exists
   */
  hasField(fieldName: string): boolean {
    return fieldName in this.ledgerAccessor;
  }

  /**
   * Lists all available fields in the ledger
   */
  listFields(): string[] {
    return Object.keys(this.ledgerAccessor);
  }
}
