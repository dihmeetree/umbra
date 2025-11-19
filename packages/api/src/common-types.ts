import {
  Contract,
  Witnesses,
  StateraPrivateState,
  Depositor,
  Staker
} from '@statera/ada-statera-protocol'
import { MidnightProviders } from '@midnight-ntwrk/midnight-js-types'
import { type FoundContract } from '@midnight-ntwrk/midnight-js-contracts'

export const stateraPrivateStateId = 'stateraPrivateState'
export type StateraPrivateStateId = typeof stateraPrivateStateId
export type StateraContract = Contract<
  StateraPrivateState,
  Witnesses<StateraPrivateState>
>
export type TokenCircuitKeys = Exclude<
  keyof StateraContract['impureCircuits'],
  number | symbol
>
export type StateraContractProviders = MidnightProviders<
  TokenCircuitKeys,
  StateraPrivateStateId,
  StateraPrivateState
>
export type DeployedStateraOnchainContract = FoundContract<StateraContract>
export type DerivedStateraContractState = {
  readonly sUSDTokenType: Uint8Array
  readonly liquidationThreshold: bigint
  // Commitment/Nullifier pattern: depositor and staker data is now in on-chain trees
  readonly depositorCommitmentsCount: bigint  // Number of commitments in tree
  readonly stakerCommitmentsCount: bigint      // Number of staker commitments
  readonly depositorNullifiersCount: bigint    // Number of spent commitments
  readonly stakerNullifiersCount: bigint       // Number of spent staker commitments
  readonly LVT: bigint
  readonly MCR: bigint
  readonly liquidationCount: bigint
  readonly validCollateralType: Uint8Array
  readonly trustedOracles: DerivedTrustedOracle[]
  // Merkle tree roots for reference
  readonly depositorCommitmentsRoot: { field: bigint }
  readonly stakerCommitmentsRoot: { field: bigint }
}

export type DerivedDepositor = {
  id: Uint8Array
  depositor: Depositor
}

export type DerivedStaker = {
  id: Uint8Array
  staker: Staker
}

export type DerivedTrustedOracle = {
  id: bigint
  oraclePk: string
}

export type DerivedReservedPoolTotal = {
  id: string
  pool_balance: {
    nonce: Uint8Array
    color: Uint8Array
    value: bigint
    mt_index: bigint
  }
}
