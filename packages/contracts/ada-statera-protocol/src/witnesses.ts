import {
  Ledger,
  MintMetadata
} from './managed/adaStateraProtocol/contract/index.cjs'
import { WitnessContext } from '@midnight-ntwrk/compact-runtime'
import {
  MissingCoinError,
  MissingMetadataError,
  WitnessValidators
} from './witness-errors.js'

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
  readonly admin_secret: Uint8Array // Fixed admin secret for admin metadata hashing
  readonly mint_metadata: MintMetadata
  readonly stake_metadata: StakeMetadata
  readonly admin_metadata: AdminMetadata
  readonly stake_pool_coin: QualifiedCoinInfo | null
  readonly reserve_pool_coin: QualifiedCoinInfo | null
  mint_counter: bigint
}

export const createPrivateStateraState = (
  secret_key: Uint8Array,
  admin_secret?: Uint8Array
): StateraPrivateState => ({
  secret_key,
  admin_secret: admin_secret || secret_key, // Use provided admin secret or default to secret_key
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
  mint_counter: 0n
})

export const witnesses = {
  division: (
    { privateState }: WitnessContext<Ledger, StateraPrivateState>,
    dividend: bigint,
    divisor: bigint
  ): [StateraPrivateState, [bigint, bigint]] => {
    // Use safe division validator
    const quotient = BigInt(
      Math.round(
        Number(
          WitnessValidators.safeDivision(dividend, divisor, 'division witness')
        )
      )
    )
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
        admins: Array.from({ length: 10 }, () => new Uint8Array(32)),
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
          admins: Array.from({ length: 10 }, () => new Uint8Array(32)),
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
      throw new MissingCoinError(
        'stake_pool',
        'User must deposit to stake pool first.'
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
      throw new MissingCoinError(
        'reserve_pool',
        'Contract must have reserve pool balance.'
      )
    }
    return [privateState, privateState.reserve_pool_coin]
  },

  // Returns the admin secret key for hashing admin metadata
  // IMPORTANT: This returns the FIXED admin_secret, not the current user's secret_key
  // This ensures admin metadata hashes are consistent regardless of who executes the circuit
  admin_secret: ({
    privateState
  }: WitnessContext<Ledger, StateraPrivateState>): [
    StateraPrivateState,
    Uint8Array
  ] => {
    WitnessValidators.requireDefined(privateState, 'privateState')
    WitnessValidators.requireDefined(privateState.admin_secret, 'admin_secret')
    return [privateState, privateState.admin_secret]
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
  }
}
