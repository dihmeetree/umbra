/**
 * Prediction Game service - handles the game contract simulator
 */
import { ProverClient, padToBytes512 } from '@statera/prover-client'
import { ContractSimulator, WalletManager, generateNonce, disableLogging } from '@statera/simulator'
import { Contract } from '@statera/ada-statera-protocol/prediction-game'
import { sampleContractAddress, ecMulGenerator } from '@midnight-ntwrk/compact-runtime'
import { setNetworkId, NetworkId } from '@midnight-ntwrk/midnight-js-network-id'

// Direction enum matching contract
export enum Direction {
  Up = 0,
  Down = 1
}

// BetState enum matching contract
export enum BetState {
  Open = 0,
  Won = 1,
  Lost = 2,
  Push = 3
}

export interface PriceAttestation {
  signedData: {
    data: Uint8Array
    dataLen: bigint
    signature: {
      r: { x: bigint; y: bigint }
      s: bigint
    }
    pk: { x: bigint; y: bigint }
  }
  priceCents: bigint
  timestamp: bigint
}

export interface GameState {
  adminSecretKey: bigint
  adminPublicKey: { x: bigint; y: bigint }
  simulator: ContractSimulator<Record<string, never>>
  minTimeDelta: bigint
  maxTimeDelta: bigint
}

export interface GameStats {
  totalBets: bigint
  totalWins: bigint
  totalLosses: bigint
}

// Singleton game state
let gameState: GameState | null = null

/**
 * Initialize the prediction game contract simulator
 */
export async function initializeGame(
  minTimeDelta: bigint = 50n, // 50 seconds minimum (allows some flexibility for 60s UI timer)
  maxTimeDelta: bigint = 120n // 120 seconds maximum (60s timer + ~30s buffer for two price fetches)
): Promise<{
  adminPublicKey: { x: string; y: string }
  contractAddress: string
  minTimeDelta: string
  maxTimeDelta: string
}> {
  // Disable debug logging and set network
  disableLogging()
  setNetworkId(NetworkId.Undeployed)

  const walletManager = new WalletManager()
  const adminWallet = walletManager.createWallet('game-admin')

  // Generate admin secret key
  const adminSecretKey = 98765432109876543210n
  const adminPublicKey = ecMulGenerator(adminSecretKey)

  const contractAddress = sampleContractAddress()

  const simulator = new ContractSimulator<Record<string, never>>(
    new Contract({}) as any,
    {
      contractAddress,
      initialPrivateState: {},
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey,
      constructorArgs: [adminSecretKey, minTimeDelta, maxTimeDelta]
    }
  )

  gameState = {
    adminSecretKey,
    adminPublicKey,
    simulator,
    minTimeDelta,
    maxTimeDelta
  }

  return {
    adminPublicKey: {
      x: adminPublicKey.x.toString(),
      y: adminPublicKey.y.toString()
    },
    contractAddress: contractAddress.toString(),
    minTimeDelta: minTimeDelta.toString(),
    maxTimeDelta: maxTimeDelta.toString()
  }
}

/**
 * Get the current game state, initializing if needed
 */
export async function getGameState(): Promise<GameState> {
  if (!gameState) {
    await initializeGame()
  }
  return gameState!
}

/**
 * Add a trusted notary to the game contract
 */
export async function addTrustedNotary(notaryPkX: bigint): Promise<void> {
  const state = await getGameState()
  state.simulator.executeImpureCircuit(
    'addTrustedNotary',
    notaryPkX,
    state.adminSecretKey
  )
}

/**
 * Create a PriceAttestation from prover response
 */
export function createPriceAttestation(
  attestedPrice: {
    rawData: Uint8Array
    signature: { r: { x: bigint; y: bigint }; s: bigint }
    notaryPk: { x: bigint; y: bigint }
    price: number
    timestamp: string
  }
): PriceAttestation {
  return {
    signedData: {
      data: padToBytes512(attestedPrice.rawData),
      dataLen: BigInt(attestedPrice.rawData.length),
      signature: {
        r: attestedPrice.signature.r,
        s: attestedPrice.signature.s
      },
      pk: attestedPrice.notaryPk
    },
    priceCents: BigInt(Math.round(attestedPrice.price * 100)),
    timestamp: BigInt(Math.floor(new Date(attestedPrice.timestamp).getTime() / 1000))
  }
}

/**
 * Resolve a bet using the contract
 */
export async function resolveBet(
  prediction: Direction,
  startAttestation: PriceAttestation,
  endAttestation: PriceAttestation
): Promise<{
  result: BetState
  startPrice: string
  endPrice: string
  priceDiff: string
}> {
  const state = await getGameState()

  // Ensure notary is trusted
  await addTrustedNotary(startAttestation.signedData.pk.x)
  if (startAttestation.signedData.pk.x !== endAttestation.signedData.pk.x) {
    await addTrustedNotary(endAttestation.signedData.pk.x)
  }

  // Call the contract to resolve the bet
  const result = state.simulator.executeImpureCircuit(
    'resolveBet',
    prediction,
    startAttestation,
    endAttestation
  )

  const betResult = result.result as number

  return {
    result: betResult as BetState,
    startPrice: (Number(startAttestation.priceCents) / 100).toFixed(2),
    endPrice: (Number(endAttestation.priceCents) / 100).toFixed(2),
    priceDiff: ((Number(endAttestation.priceCents) - Number(startAttestation.priceCents)) / 100).toFixed(2)
  }
}

/**
 * Get game statistics from the contract
 */
export async function getGameStats(): Promise<GameStats> {
  const state = await getGameState()

  const totalBets = state.simulator.executeImpureCircuit('getTotalBets')
  const totalWins = state.simulator.executeImpureCircuit('getTotalWins')
  const totalLosses = state.simulator.executeImpureCircuit('getTotalLosses')

  return {
    totalBets: totalBets.result as bigint,
    totalWins: totalWins.result as bigint,
    totalLosses: totalLosses.result as bigint
  }
}

/**
 * Get game time constraints
 */
export async function getTimeConstraints(): Promise<{
  minTimeDelta: string
  maxTimeDelta: string
}> {
  const state = await getGameState()
  return {
    minTimeDelta: state.minTimeDelta.toString(),
    maxTimeDelta: state.maxTimeDelta.toString()
  }
}
