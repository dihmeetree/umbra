/**
 * Oracle API client - calls the backend oracle-server
 */

const API_BASE = 'http://localhost:3002'

export interface VerifiedPrice {
  symbol: string
  price: number
  timestamp: string
  rawData: string
  signature: {
    r: { x: string; y: string }
    s: string
    pk: { x: string; y: string }
  }
  contractVerified: boolean
}

export interface OracleStatus {
  initialized: boolean
  adminPublicKey: {
    x: string
    y: string
  }
}

export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
}

/**
 * Initialize the oracle contract on the backend
 */
export async function initializeOracle(): Promise<ApiResponse<{
  adminPublicKey: { x: string; y: string }
  contractAddress: string
}>> {
  const response = await fetch(`${API_BASE}/api/oracle/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
  return response.json()
}

/**
 * Get oracle status
 */
export async function getOracleStatus(): Promise<ApiResponse<OracleStatus>> {
  const response = await fetch(`${API_BASE}/api/oracle/status`)
  return response.json()
}

/**
 * Fetch verified Bitcoin price through the oracle
 */
export async function fetchVerifiedBitcoinPrice(
  proverUrl: string = 'http://localhost:8080'
): Promise<ApiResponse<VerifiedPrice>> {
  const response = await fetch(`${API_BASE}/api/oracle/price`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proverUrl })
  })
  return response.json()
}

/**
 * Format a bigint string as a truncated hex string
 */
export function formatBigInt(value: string | undefined | null, maxLen: number = 16): string {
  if (!value || value === '0' || value === '') {
    return '0x0'
  }
  try {
    const bigVal = BigInt(value)
    if (bigVal === 0n) {
      return '0x0'
    }
    const hex = bigVal.toString(16)
    if (hex.length <= maxLen) {
      return '0x' + hex
    }
    return '0x' + hex.slice(0, maxLen / 2) + '...' + hex.slice(-maxLen / 2)
  } catch {
    return '0x0'
  }
}

// ============ Game API ============

export interface GameStats {
  totalBets: string
  totalWins: string
  totalLosses: string
}

export interface GameConstraints {
  minTimeDelta: string
  maxTimeDelta: string
}

export interface GameResult {
  result: 'Won' | 'Lost' | 'Push' | 'Open'
  startPrice: string
  endPrice: string
  priceDiff: string
}

/**
 * Initialize the prediction game contract
 */
export async function initializeGame(): Promise<ApiResponse<{
  adminPublicKey: { x: string; y: string }
  contractAddress: string
  minTimeDelta: string
  maxTimeDelta: string
}>> {
  const response = await fetch(`${API_BASE}/api/game/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
  return response.json()
}

/**
 * Get game statistics
 */
export async function getGameStats(): Promise<ApiResponse<GameStats>> {
  const response = await fetch(`${API_BASE}/api/game/stats`)
  return response.json()
}

/**
 * Get game time constraints
 */
export async function getGameConstraints(): Promise<ApiResponse<GameConstraints>> {
  const response = await fetch(`${API_BASE}/api/game/constraints`)
  return response.json()
}

/**
 * Resolve a bet using the contract
 */
export async function resolveBet(
  prediction: 'up' | 'down',
  startAttestation: VerifiedPrice,
  endAttestation: VerifiedPrice
): Promise<ApiResponse<GameResult>> {
  const response = await fetch(`${API_BASE}/api/game/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      prediction,
      startAttestation: {
        ...startAttestation,
        dataLen: startAttestation.rawData.length
      },
      endAttestation: {
        ...endAttestation,
        dataLen: endAttestation.rawData.length
      }
    })
  })
  return response.json()
}
