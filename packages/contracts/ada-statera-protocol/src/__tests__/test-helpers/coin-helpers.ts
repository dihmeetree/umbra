/**
 * Coin Creation and Management Helpers
 *
 * Functions for creating and preparing coins for contract operations
 */

import type { ContractSimulator } from '@statera/simulator';
import { LegacyCoinBuilder } from '@statera/simulator';
import type { TokenType } from '@midnight-ntwrk/zswap';
import type { StateraPrivateState } from '../../index.js';
import { TestData } from '../test-data.js';

/**
 * Creates a generic mock coin
 */
export function createMockCoin(value: bigint, tokenType: TokenType) {
  return new LegacyCoinBuilder()
    .withValue(value)
    .withTokenType(tokenType)
    .build();
}

/**
 * Creates a collateral coin (ADA) with SPECK conversion
 */
export function createCollateralCoin(tdust: bigint) {
  const speck = TestData.units.toSpeck(tdust);
  return {
    nonce: new Uint8Array(32),
    color: new Uint8Array(32),
    value: speck,
  };
}

/**
 * Creates an sUSD coin
 */
export function createSUSDCoin(amount: bigint, sSUSDTokenType: TokenType) {
  return new LegacyCoinBuilder()
    .withValue(amount)
    .withTokenType(sSUSDTokenType)
    .build();
}

/**
 * Creates a mock qualified coin info for stake pool
 */
export function createMockStakePoolCoin(sSUSDTokenType?: TokenType) {
  return {
    nonce: new Uint8Array(32),
    color: new Uint8Array(32),
    value: 100000000000n,
    mt_index: 0n,
  };
}

/**
 * Creates a mock qualified coin info for reserve pool
 */
export function createMockReservePoolCoin(collateralTokenType: TokenType) {
  return {
    nonce: new Uint8Array(32),
    color: new Uint8Array(32),
    value: 100000000000n,
    mt_index: 0n,
  };
}

/**
 * Prepares a coin to be received by adding it to simulator's ZSwap local state
 */
export function prepareCoinForReceive<T>(
  simulator: ContractSimulator<T>,
  coin: any,
  tokenType: TokenType
): void {
  const zswapState = simulator.getZswapLocalState();
  const existingInputs = zswapState.coins_received.inputs || [];

  simulator['circuitContext'].currentZswapLocalState = {
    ...zswapState,
    coins_received: {
      ...zswapState.coins_received,
      inputs: [
        ...existingInputs,
        {
          ...coin,
          token_type: tokenType,
        },
      ],
    },
  };
}
