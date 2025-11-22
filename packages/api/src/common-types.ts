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
  // Direct Map storage: count depositors and stakers
  readonly depositorsCount: bigint // Number of depositors in Map
  readonly stakersCount: bigint // Number of stakers in Map
  readonly LVT: bigint
  readonly MCR: bigint
  readonly liquidationCount: bigint
  readonly validCollateralType: Uint8Array
  readonly trustedOracles: DerivedTrustedOracle[]
  readonly mintMetadata?: any // Added from private state
  readonly secret_key?: Uint8Array // Added from private state
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
