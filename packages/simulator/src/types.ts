import type { CircuitContext, ContractAddress } from '@midnight-ntwrk/compact-runtime';
import type * as ocrt from '@midnight-ntwrk/onchain-runtime';
import type { TokenType } from '@midnight-ntwrk/zswap';

/**
 * Represents a generic contract with circuits
 */
export interface ContractWithCircuits<TPrivateState> {
  initialState: (
    context: any,
    nonce: Uint8Array,
    ...args: any[]
  ) => {
    currentPrivateState: TPrivateState;
    currentContractState: any;
    currentZswapLocalState: any;
  };
  circuits: Record<string, (context: CircuitContext<TPrivateState>, ...args: any[]) => any>;
  impureCircuits: Record<string, (context: CircuitContext<TPrivateState>, ...args: any[]) => any>;
}

/**
 * Configuration for initializing a contract simulator
 */
export interface ContractConfig<TPrivateState> {
  contractAddress: ContractAddress;
  initialPrivateState: TPrivateState;
  nonce: Uint8Array;
  coinPublicKey: ocrt.CoinPublicKey;
  constructorArgs?: any[];
}

/**
 * Represents a wallet with a private key and coin public key
 */
export interface Wallet {
  secretKey: Uint8Array;
  coinPublicKey: ocrt.CoinPublicKey;
  publicKey?: Uint8Array;
}

/**
 * Token balance information
 */
export interface TokenBalance {
  type: TokenType;
  value: bigint;
}

/**
 * Output information from a circuit execution
 */
export interface OutputInfo {
  recipient: ocrt.CoinPublicKey | ContractAddress;
  coinInfo: ocrt.CoinInfo;
}

/**
 * Result of a circuit execution
 */
export interface CircuitResult<TPrivateState> {
  context: CircuitContext<TPrivateState>;
  outputs: OutputInfo[];
  ledger: any;
}
