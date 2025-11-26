/**
 * Oracle service - handles the contract simulator and price verification
 */
import { ProverClient, padToBytes512 } from '@statera/prover-client'
import { ContractSimulator, WalletManager, generateNonce, disableLogging } from '@statera/simulator'
import { Contract } from '@statera/ada-statera-protocol/bitcoin-oracle'
import { sampleContractAddress, ecMulGenerator } from '@midnight-ntwrk/compact-runtime'
import { setNetworkId, NetworkId } from '@midnight-ntwrk/midnight-js-network-id'

export interface VerifiedPrice {
  symbol: string
  price: number
  timestamp: string
  rawData: string // base64 encoded
  signature: {
    r: { x: string; y: string }
    s: string
    pk: { x: string; y: string }
  }
  contractVerified: boolean
}

export interface OracleState {
  adminSecretKey: bigint
  adminPublicKey: { x: bigint; y: bigint }
  simulator: ContractSimulator<Record<string, never>>
}

// Singleton oracle state
let oracleState: OracleState | null = null

/**
 * Initialize the oracle contract simulator
 */
export async function initializeOracle(): Promise<{
  adminPublicKey: { x: string; y: string }
  contractAddress: string
}> {
  // Disable debug logging and set network
  disableLogging()
  setNetworkId(NetworkId.Undeployed)

  const walletManager = new WalletManager()
  const adminWallet = walletManager.createWallet('admin')

  // Generate admin secret key
  const adminSecretKey = 12345678901234567890n
  const adminPublicKey = ecMulGenerator(adminSecretKey)

  const contractAddress = sampleContractAddress()

  const simulator = new ContractSimulator<Record<string, never>>(
    new Contract({}) as any,
    {
      contractAddress,
      initialPrivateState: {},
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey,
      constructorArgs: [adminSecretKey]
    }
  )

  oracleState = {
    adminSecretKey,
    adminPublicKey,
    simulator
  }

  return {
    adminPublicKey: {
      x: adminPublicKey.x.toString(),
      y: adminPublicKey.y.toString()
    },
    contractAddress: contractAddress.toString()
  }
}

/**
 * Get the current oracle state, initializing if needed
 */
export async function getOracleState(): Promise<OracleState> {
  if (!oracleState) {
    await initializeOracle()
  }
  return oracleState!
}

/**
 * Fetch and verify a Bitcoin price through the oracle
 */
export async function fetchVerifiedBitcoinPrice(proverUrl: string): Promise<VerifiedPrice> {
  const state = await getOracleState()
  const proverClient = new ProverClient({ baseUrl: proverUrl, timeout: 60000 })

  // Fetch attested price from prover
  const attestedPrice = await proverClient.getBitcoinPrice()

  // Add notary to trusted set
  state.simulator.executeImpureCircuit(
    'addTrustedNotary',
    attestedPrice.notaryPkX,
    state.adminSecretKey
  )

  // Create SignedBytes structure
  const signedBytes = {
    data: padToBytes512(attestedPrice.rawData),
    dataLen: BigInt(attestedPrice.rawData.length),
    signature: {
      r: attestedPrice.signature.r,
      s: attestedPrice.signature.s
    },
    pk: attestedPrice.notaryPk
  }

  // Verify through contract
  const result = state.simulator.executeImpureCircuit(
    'verifyAttestedData',
    signedBytes
  )

  // Extract verified data
  const verifiedData = result.result as Uint8Array
  const extractedData = verifiedData.slice(0, Number(signedBytes.dataLen))
  const dataJson = JSON.parse(new TextDecoder().decode(extractedData))

  return {
    symbol: dataJson.Symbol,
    price: dataJson.Price,
    timestamp: new Date(dataJson.Time).toISOString(),
    rawData: Buffer.from(attestedPrice.rawData).toString('base64'),
    signature: {
      r: {
        x: attestedPrice.signature.r.x.toString(),
        y: attestedPrice.signature.r.y.toString()
      },
      s: attestedPrice.signature.s.toString(),
      pk: {
        x: attestedPrice.notaryPk.x.toString(),
        y: attestedPrice.notaryPk.y.toString()
      }
    },
    contractVerified: true
  }
}

/**
 * Format a bigint as a truncated hex string
 */
export function formatBigInt(value: bigint, maxLen: number = 16): string {
  const hex = value.toString(16)
  if (hex.length <= maxLen) {
    return '0x' + hex
  }
  return '0x' + hex.slice(0, maxLen / 2) + '...' + hex.slice(-maxLen / 2)
}
