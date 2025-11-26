/**
 * Types for TLSNotary prover client
 */

/**
 * Request to prove a URL's content
 */
export interface ProveRequest {
  /** The URL to fetch and prove */
  url: string
  /** Optional custom headers to include in the request */
  headers?: Array<[string, string]>
  /** Whether to reveal the full response body */
  reveal_body?: boolean
  /** Specific JSON keys to reveal (alternative to reveal_body) */
  reveal_body_keys?: string[]
}

/**
 * JubJub curve point coordinates
 */
export interface CurvePoint {
  x: bigint
  y: bigint
}

/**
 * Schnorr signature on JubJub curve
 */
export interface JubJubSignature {
  /** R point of the signature */
  r: CurvePoint
  /** S scalar of the signature */
  s: bigint
  /** Public key that created the signature */
  pk: CurvePoint
}

/**
 * Raw signature response from the prover API (hex-encoded)
 */
export interface RawSignatureResponse {
  r_x: string
  r_y: string
  s: string
  pk_x: string
  pk_y: string
}

/**
 * Notary signature with the signed data
 */
export interface NotarySignature {
  /** The parsed JubJub signature */
  signature: JubJubSignature
  /** The raw data that was signed */
  data: Uint8Array
}

/**
 * Full response from the prover API
 */
export interface ProveResponse {
  /** The TLSNotary presentation (bincode-encoded) */
  presentation: number[]
  /** The server name that was connected to */
  server_name: string
  /** The sent data (with redactions) */
  sent: string
  /** The received data (with redactions) */
  recv: string
  /** The notary signature over the revealed data */
  notary_signature: NotarySignature
}

/**
 * Raw response from the prover API (before parsing)
 */
export interface RawProveResponse {
  presentation: number[]
  server_name: string
  sent: string
  recv: string
  notary_signature: {
    signature: RawSignatureResponse
    data: number[]
  }
}

/**
 * SignedBytes structure compatible with Compact contracts
 */
export interface SignedBytes {
  /** Data padded to 512 bytes */
  data: Uint8Array
  /** Actual length of the original data */
  dataLen: bigint
  /** The signature */
  signature: {
    r: CurvePoint
    s: bigint
  }
  /** The notary's public key */
  pk: CurvePoint
}

/**
 * Parsed price data from DIA Data API
 */
export interface PriceData {
  /** Asset symbol (e.g., "BTC") */
  symbol: string
  /** Price in USD */
  price: number
  /** Timestamp of the price */
  timestamp: Date
  /** Raw JSON data */
  raw: Record<string, unknown>
}
