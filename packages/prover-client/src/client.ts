/**
 * TLSNotary Prover Client
 *
 * Provides a TypeScript interface for interacting with the Statera prover service
 * to obtain cryptographically attested data from external APIs.
 */

import type {
  ProveRequest,
  ProveResponse,
  RawProveResponse,
  NotarySignature,
  JubJubSignature,
  SignedBytes,
  PriceData
} from './types.js'

/**
 * Configuration for the ProverClient
 */
export interface ProverClientConfig {
  /** Base URL of the prover service */
  baseUrl: string
  /** Request timeout in milliseconds */
  timeout?: number
}

/**
 * Client for interacting with the TLSNotary prover service
 */
export class ProverClient {
  private readonly baseUrl: string
  private readonly timeout: number

  constructor(config: ProverClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '') // Remove trailing slash
    this.timeout = config.timeout ?? 30000
  }

  /**
   * Prove a URL's content and get an attested response
   *
   * @param request - The prove request parameters
   * @returns The prove response with signature and data
   */
  async prove(request: ProveRequest): Promise<ProveResponse> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.timeout)

    try {
      const response = await fetch(`${this.baseUrl}/prove`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new ProverError(
          `Prover request failed: ${response.status} ${response.statusText}`,
          response.status,
          errorText
        )
      }

      const rawResponse: RawProveResponse = await response.json()
      return this.parseResponse(rawResponse)
    } finally {
      clearTimeout(timeoutId)
    }
  }

  /**
   * Fetch and attest a Bitcoin price from DIA Data API
   *
   * @returns Attested Bitcoin price data
   */
  async getBitcoinPrice(): Promise<AttestedPrice> {
    const response = await this.prove({
      url: 'https://api.diadata.org/v1/assetQuotation/Bitcoin/0x0000000000000000000000000000000000000000',
      reveal_body: true
    })

    return new AttestedPrice(response)
  }

  /**
   * Fetch and attest a price for any asset from DIA Data API
   *
   * @param asset - Asset name (e.g., "Bitcoin", "Ethereum")
   * @param address - Token address (use zeros for native assets)
   * @returns Attested price data
   */
  async getAssetPrice(
    asset: string,
    address: string = '0x0000000000000000000000000000000000000000'
  ): Promise<AttestedPrice> {
    const response = await this.prove({
      url: `https://api.diadata.org/v1/assetQuotation/${asset}/${address}`,
      reveal_body: true
    })

    return new AttestedPrice(response)
  }

  /**
   * Check if the prover service is healthy
   */
  async isHealthy(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      })
      return response.ok
    } catch {
      return false
    }
  }

  /**
   * Parse the raw prover response into typed structures
   */
  private parseResponse(raw: RawProveResponse): ProveResponse {
    const sig = raw.notary_signature.signature

    const signature: JubJubSignature = {
      r: {
        x: hexToBigInt(sig.r_x),
        y: hexToBigInt(sig.r_y)
      },
      s: hexToBigInt(sig.s),
      pk: {
        x: hexToBigInt(sig.pk_x),
        y: hexToBigInt(sig.pk_y)
      }
    }

    const notarySignature: NotarySignature = {
      signature,
      data: new Uint8Array(raw.notary_signature.data)
    }

    return {
      presentation: raw.presentation,
      server_name: raw.server_name,
      sent: raw.sent,
      recv: raw.recv,
      notary_signature: notarySignature
    }
  }
}

/**
 * Attested price data with helper methods
 */
export class AttestedPrice {
  readonly response: ProveResponse
  readonly priceData: PriceData

  constructor(response: ProveResponse) {
    this.response = response
    this.priceData = this.parseData()
  }

  /**
   * Get the notary's public key X coordinate (used as identifier)
   */
  get notaryPkX(): bigint {
    return this.response.notary_signature.signature.pk.x
  }

  /**
   * Get the notary's public key
   */
  get notaryPk(): { x: bigint; y: bigint } {
    return this.response.notary_signature.signature.pk
  }

  /**
   * Get the signature
   */
  get signature(): JubJubSignature {
    return this.response.notary_signature.signature
  }

  /**
   * Get the raw signed data
   */
  get rawData(): Uint8Array {
    return this.response.notary_signature.data
  }

  /**
   * Get the price in USD
   */
  get price(): number {
    return this.priceData.price
  }

  /**
   * Get the asset symbol
   */
  get symbol(): string {
    return this.priceData.symbol
  }

  /**
   * Get the timestamp
   */
  get timestamp(): Date {
    return this.priceData.timestamp
  }

  /**
   * Create a SignedBytes structure for use with Compact contracts
   */
  toSignedBytes(): SignedBytes {
    return createSignedBytes(
      this.rawData,
      this.signature,
      this.notaryPk
    )
  }

  /**
   * Parse the raw data into price data
   */
  private parseData(): PriceData {
    const json = JSON.parse(new TextDecoder().decode(this.rawData))
    return {
      symbol: json.Symbol,
      price: json.Price,
      timestamp: new Date(json.Time),
      raw: json
    }
  }
}

/**
 * Error thrown by the prover client
 */
export class ProverError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly responseBody?: string
  ) {
    super(message)
    this.name = 'ProverError'
  }
}

/**
 * Convert hex string to bigint
 */
export function hexToBigInt(hex: string): bigint {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex
  return BigInt('0x' + cleanHex)
}

/**
 * Pad data to 512 bytes for Bytes<512> type
 */
export function padToBytes512(data: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(512)
  bytes.set(data.slice(0, 512))
  return bytes
}

/**
 * Create a SignedBytes structure from signature components
 */
export function createSignedBytes(
  data: Uint8Array,
  signature: JubJubSignature,
  pk?: { x: bigint; y: bigint }
): SignedBytes {
  return {
    data: padToBytes512(data),
    dataLen: BigInt(data.length),
    signature: {
      r: signature.r,
      s: signature.s
    },
    pk: pk ?? signature.pk
  }
}
