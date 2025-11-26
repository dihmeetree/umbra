/**
 * @statera/prover-client
 *
 * TypeScript client for interacting with the Statera TLSNotary prover service.
 * Provides cryptographically attested data from external APIs for use in
 * Midnight smart contracts.
 */

export {
  ProverClient,
  ProverClientConfig,
  AttestedPrice,
  ProverError,
  hexToBigInt,
  padToBytes512,
  createSignedBytes
} from './client.js'

export type {
  ProveRequest,
  ProveResponse,
  RawProveResponse,
  NotarySignature,
  JubJubSignature,
  RawSignatureResponse,
  CurvePoint,
  SignedBytes,
  PriceData
} from './types.js'
