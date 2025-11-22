/**
 * Private State Management Helpers
 *
 * Functions for creating and managing private states in tests
 */

import type { ContractSimulator, Wallet } from '@statera/simulator'
import type { TokenType } from '@midnight-ntwrk/zswap'
import {
  createPrivateStateraState,
  type StateraPrivateState,
  type MintMetadata
} from '../../index.js'
import { createMockStakePoolCoin } from './coin-helpers.js'

/**
 * Creates a basic private state for a wallet
 * Automatically preserves admin_secret and admin_metadata from simulator
 */
export function createPrivateStateForWallet(
  wallet: Wallet,
  simulator?: ContractSimulator<StateraPrivateState>
): StateraPrivateState {
  if (!simulator) {
    return createPrivateStateraState(wallet.secretKey, wallet.secretKey)
  }

  const currentState = simulator.getPrivateState()
  const baseState = createPrivateStateraState(
    wallet.secretKey,
    currentState.admin_secret
  )

  return {
    ...baseState,
    admin_metadata: currentState.admin_metadata,
    admin_secret: currentState.admin_secret
  }
}

/**
 * Creates admin private state
 */
export function createAdminPrivateState(
  simulator: ContractSimulator<StateraPrivateState>,
  adminWallet: Wallet
): StateraPrivateState {
  const currentState = simulator.getPrivateState()

  return {
    ...currentState,
    secret_key: adminWallet.secretKey,
    admin_secret: currentState.admin_secret
  }
}

/**
 * Helper to execute a circuit as admin with proper authentication
 */
export function asAdmin(
  simulator: ContractSimulator<StateraPrivateState>,
  adminWallet: Wallet
): ContractSimulator<StateraPrivateState> {
  return simulator.as(
    createAdminPrivateState(simulator, adminWallet),
    adminWallet.coinPublicKey
  )
}

/**
 * Creates private state with mint metadata after deposit
 */
export function getPrivateStateAfterDeposit(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  depositAmount: bigint,
  collateralTokenType?: TokenType
): StateraPrivateState {
  const currentState = simulator.getPrivateState()

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    admin_secret: currentState.admin_secret,
    admin_metadata: currentState.admin_metadata,
    mint_metadata: {
      collateral: depositAmount,
      debt: 0n
    },
    reserve_pool_coin: collateralTokenType
      ? {
          nonce: new Uint8Array(32),
          color: new Uint8Array(32),
          value: 100000000000n,
          mt_index: 0n
        }
      : currentState.reserve_pool_coin
  }
}

/**
 * Creates private state with mint metadata (for repayment tests)
 */
export function createPrivateStateWithMintMetadata(
  wallet: Wallet,
  collateral: bigint,
  debt: bigint
): StateraPrivateState {
  const baseState = createPrivateStateraState(wallet.secretKey)

  return {
    ...baseState,
    mint_metadata: {
      collateral,
      debt
    }
  }
}

/**
 * Creates private state after staking
 */
export function getPrivateStateAfterStake(
  simulator: ContractSimulator<StateraPrivateState>,
  wallet: Wallet,
  stakeAmount: bigint,
  sSUSDTokenType?: TokenType,
  additionalRewards: bigint = 0n
): StateraPrivateState {
  const currentState = simulator.getPrivateState()
  let entry_ADA_SUSD_index = 0n
  let entry_scale_factor = 1n

  try {
    const ledger = simulator.getLedger()
    entry_ADA_SUSD_index = ledger.ADA_sUSD_index || 0n
    entry_scale_factor = ledger.cumulative_scaling_factor || 1n
  } catch (e) {
    // If we can't read from ledger, use the provided amount
  }

  return {
    ...currentState,
    secret_key: wallet.secretKey,
    admin_secret: currentState.admin_secret,
    admin_metadata: currentState.admin_metadata,
    stake_metadata: {
      effectiveBalance: stakeAmount,
      stakeReward: additionalRewards,
      entry_ADA_SUSD_index,
      entry_scale_factor
    },
    stake_pool_coin: sSUSDTokenType
      ? createMockStakePoolCoin(sSUSDTokenType)
      : currentState.stake_pool_coin
  }
}
