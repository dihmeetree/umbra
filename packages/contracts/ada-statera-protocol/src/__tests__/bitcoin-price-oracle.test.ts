import { describe, it, expect, beforeEach } from 'vitest'
import {
  ContractSimulator,
  WalletManager,
  disableLogging,
  generateNonce
} from '@statera/simulator'
import {
  ProverClient,
  AttestedPrice,
  createSignedBytes,
  hexToBigInt,
  padToBytes512
} from '@statera/prover-client'
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id'
import {
  sampleContractAddress,
  ecMulGenerator
} from '@midnight-ntwrk/compact-runtime'
import type { ContractAddress } from '@midnight-ntwrk/zswap'
import {
  Contract,
  ledger,
  pureCircuits
} from '../managed/bitcoinPriceOracle/contract/index.cjs'
import type { SignedBytes } from '@statera/prover-client'

// Disable debug logging for cleaner test output
disableLogging()

// Set network ID for testing
setNetworkId(NetworkId.Undeployed)

/**
 * Test fixture for BitcoinPriceOracle
 */
interface OracleTestFixture {
  simulator: ContractSimulator<Record<string, never>>
  walletManager: WalletManager
  adminSecretKey: bigint
  adminPublicKey: { x: bigint; y: bigint }
  contractAddress: ContractAddress
}

/**
 * Creates a test fixture for BitcoinPriceOracle testing
 */
function createOracleTestFixture(): OracleTestFixture {
  // Create wallet manager for coinPublicKey
  const walletManager = new WalletManager()
  const adminWallet = walletManager.createWallet('admin')

  // Generate admin secret key (just a random field element for testing)
  const adminSecretKey = 12345678901234567890n

  // Compute admin public key using ecMulGenerator (sk * G)
  const adminPublicKey = ecMulGenerator(adminSecretKey)

  // Generate contract address
  const contractAddress = sampleContractAddress()

  // Deploy the oracle contract
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

  return {
    simulator,
    walletManager,
    adminSecretKey,
    adminPublicKey,
    contractAddress
  }
}

/**
 * Creates a mock notary key pair for testing
 */
function createMockNotaryKeyPair(): {
  sk: bigint
  pk: { x: bigint; y: bigint }
} {
  const sk = 98765432109876543210n
  const pk = ecMulGenerator(sk)
  return { sk, pk }
}

/**
 * Creates a SignedBytes structure compatible with the contract
 */
function toContractSignedBytes(
  data: Uint8Array,
  signature: { r: { x: bigint; y: bigint }; s: bigint },
  pk: { x: bigint; y: bigint }
): SignedBytes {
  return {
    data: padToBytes512(data),
    dataLen: BigInt(data.length),
    signature,
    pk
  }
}

describe('BitcoinPriceOracle Contract', () => {
  let fixture: OracleTestFixture

  beforeEach(() => {
    fixture = createOracleTestFixture()
  })

  describe('Contract Deployment', () => {
    it('should deploy with correct admin public key', () => {
      const { simulator, adminPublicKey } = fixture

      const ledgerState = simulator.getLedger()
      const oracleLedger = ledger(ledgerState)

      expect(oracleLedger.adminPk.x).toBe(adminPublicKey.x)
      expect(oracleLedger.adminPk.y).toBe(adminPublicKey.y)
    })

    it('should start with empty trusted notaries set', () => {
      const { simulator } = fixture

      const ledgerState = simulator.getLedger()
      const oracleLedger = ledger(ledgerState)

      // The trustedNotaries set should be empty
      expect(oracleLedger.trustedNotaries.size()).toBe(0n)
    })
  })

  describe('Admin Operations', () => {
    it('should allow admin to add a trusted notary', () => {
      const { simulator, adminSecretKey } = fixture
      const notary = createMockNotaryKeyPair()

      // Add notary using admin's secret key
      simulator.executeImpureCircuit(
        'addTrustedNotary',
        notary.pk.x,
        adminSecretKey
      )

      const ledgerState = simulator.getLedger()
      const oracleLedger = ledger(ledgerState)

      // Verify notary was added
      expect(oracleLedger.trustedNotaries.member(notary.pk.x)).toBe(true)
    })

    it('should reject non-admin from adding notary', () => {
      const { simulator } = fixture
      const notary = createMockNotaryKeyPair()
      const wrongSecretKey = 11111111111111111111n

      // Attempt to add notary with wrong secret key
      expect(() => {
        simulator.executeImpureCircuit(
          'addTrustedNotary',
          notary.pk.x,
          wrongSecretKey
        )
      }).toThrow('Unauthorized: not admin')
    })

    it('should allow admin to remove a trusted notary', () => {
      const { simulator, adminSecretKey } = fixture
      const notary = createMockNotaryKeyPair()

      // Add notary first
      simulator.executeImpureCircuit(
        'addTrustedNotary',
        notary.pk.x,
        adminSecretKey
      )

      // Remove notary
      simulator.executeImpureCircuit(
        'removeTrustedNotary',
        notary.pk.x,
        adminSecretKey
      )

      const ledgerState = simulator.getLedger()
      const oracleLedger = ledger(ledgerState)

      // Verify notary was removed
      expect(oracleLedger.trustedNotaries.member(notary.pk.x)).toBe(false)
    })

    it('should allow adding multiple notaries', () => {
      const { simulator, adminSecretKey } = fixture
      const notary1 = createMockNotaryKeyPair()
      const notary2Sk = 11111111111111111111n
      const notary2Pk = ecMulGenerator(notary2Sk)

      // Add both notaries
      simulator.executeImpureCircuit(
        'addTrustedNotary',
        notary1.pk.x,
        adminSecretKey
      )
      simulator.executeImpureCircuit(
        'addTrustedNotary',
        notary2Pk.x,
        adminSecretKey
      )

      const ledgerState = simulator.getLedger()
      const oracleLedger = ledger(ledgerState)

      // Verify both notaries are trusted
      expect(oracleLedger.trustedNotaries.member(notary1.pk.x)).toBe(true)
      expect(oracleLedger.trustedNotaries.member(notary2Pk.x)).toBe(true)
    })
  })

  describe('SignedBytes Structure', () => {
    it('should correctly pad data to 512 bytes', () => {
      const data = new TextEncoder().encode('{"Price": 100000}')
      const signedBytes = toContractSignedBytes(
        data,
        { r: { x: 0n, y: 0n }, s: 0n },
        { x: 0n, y: 0n }
      )

      expect(signedBytes.data.length).toBe(512)
      expect(signedBytes.dataLen).toBe(BigInt(data.length))
    })

    it('should preserve original data in padded bytes', () => {
      const originalData = new TextEncoder().encode(
        '{"Symbol": "BTC", "Price": 87000.50}'
      )
      const signedBytes = toContractSignedBytes(
        originalData,
        { r: { x: 0n, y: 0n }, s: 0n },
        { x: 0n, y: 0n }
      )

      const extractedData = signedBytes.data.slice(
        0,
        Number(signedBytes.dataLen)
      )
      const extractedStr = new TextDecoder().decode(extractedData)

      expect(extractedStr).toBe('{"Symbol": "BTC", "Price": 87000.50}')
    })

    it('should parse DIA Data API response format', () => {
      const diaResponse = {
        Address: '0x0000000000000000000000000000000000000000',
        Blockchain: 'Bitcoin',
        Name: 'Bitcoin',
        Price: 87399.6,
        PriceYesterday: 93971.56,
        Symbol: 'BTC',
        Time: '2025-11-21T07:42:47Z',
        VolumeYesterdayUSD: 0
      }

      const data = new TextEncoder().encode(JSON.stringify(diaResponse))
      const signedBytes = toContractSignedBytes(
        data,
        { r: { x: 0n, y: 0n }, s: 0n },
        { x: 0n, y: 0n }
      )

      // Parse back the data
      const extractedData = signedBytes.data.slice(
        0,
        Number(signedBytes.dataLen)
      )
      const parsed = JSON.parse(new TextDecoder().decode(extractedData))

      expect(parsed.Symbol).toBe('BTC')
      expect(parsed.Price).toBe(87399.6)
      expect(parsed.Time).toBe('2025-11-21T07:42:47Z')
    })
  })

  describe('Signature Verification Edge Cases', () => {
    it('should reject untrusted notary even with valid-looking signature structure', () => {
      const { simulator } = fixture
      const untrustedNotary = createMockNotaryKeyPair()

      // Create a properly structured SignedBytes (signature is invalid but structure is correct)
      const data = new TextEncoder().encode('{"Price": 100000}')
      const signedBytes = toContractSignedBytes(
        data,
        { r: { x: 1n, y: 1n }, s: 1n },
        untrustedNotary.pk
      )

      // Should fail because notary is not trusted (before signature verification)
      expect(() => {
        simulator.executeImpureCircuit('verifyAttestedData', signedBytes)
      }).toThrow('Notary not trusted')
    })

    it('should reject malformed signature from trusted notary', () => {
      const { simulator, adminSecretKey } = fixture
      const notary = createMockNotaryKeyPair()

      // Add notary as trusted
      simulator.executeImpureCircuit(
        'addTrustedNotary',
        notary.pk.x,
        adminSecretKey
      )

      // Create SignedBytes with invalid signature (s=0, r=identity point)
      const data = new TextEncoder().encode('{"Price": 100000}')
      const signedBytes = toContractSignedBytes(
        data,
        { r: { x: 0n, y: 1n }, s: 0n }, // Invalid signature
        notary.pk
      )

      // Should fail signature verification
      expect(() => {
        simulator.executeImpureCircuit('verifyAttestedData', signedBytes)
      }).toThrow('Invalid notary signature')
    })
  })
})

/**
 * Integration tests that require running notary/prover services
 *
 * To run integration tests:
 * 1. Start the notary: cd crates/notary && NOTARY_SIGNING_KEY=<hex> cargo run
 * 2. Start the prover: cd crates/prover && cargo run
 * 3. Run tests: yarn test bitcoin-price-oracle.test.ts
 */
describe('BitcoinPriceOracle Integration Tests', () => {
  const PROVER_URL = process.env.PROVER_URL || 'http://localhost:3000'
  const proverClient = new ProverClient({ baseUrl: PROVER_URL })

  it('should fetch, attest, and verify Bitcoin price through contract', async () => {
    // Get attested Bitcoin price using the prover client
    const attestedPrice = await proverClient.getBitcoinPrice()

    console.log('Notary signature details:')
    console.log(
      `  pk: (${attestedPrice.notaryPk.x}, ${attestedPrice.notaryPk.y})`
    )
    console.log(
      `  r: (${attestedPrice.signature.r.x}, ${attestedPrice.signature.r.y})`
    )
    console.log(`  s: ${attestedPrice.signature.s}`)
    console.log(`  data length: ${attestedPrice.rawData.length} bytes`)

    // Create contract fixture and register the notary
    const fixture = createOracleTestFixture()
    const { simulator, adminSecretKey } = fixture

    // Add the real notary as trusted
    simulator.executeImpureCircuit(
      'addTrustedNotary',
      attestedPrice.notaryPkX,
      adminSecretKey
    )

    // Create SignedBytes structure for contract
    const signedBytes = toContractSignedBytes(
      attestedPrice.rawData,
      attestedPrice.signature,
      attestedPrice.notaryPk
    )

    // Verify through the contract and get the attested data back
    const circuitResult = simulator.executeImpureCircuit(
      'verifyAttestedData',
      signedBytes
    )

    // Extract the original JSON from verified data
    const verifiedData = circuitResult.result as Uint8Array
    const extractedData = verifiedData.slice(0, Number(signedBytes.dataLen))
    const dataJson = JSON.parse(new TextDecoder().decode(extractedData))

    console.log('Contract-verified attested data:', {
      Symbol: dataJson.Symbol,
      Price: dataJson.Price,
      Time: dataJson.Time
    })

    // Verify the price matches what we got from the prover
    expect(dataJson.Price).toBe(attestedPrice.price)
    expect(dataJson.Symbol).toBe(attestedPrice.symbol)

    // Verify the price is in a reasonable range
    expect(attestedPrice.price).toBeGreaterThan(10000) // > $10k
    expect(attestedPrice.price).toBeLessThan(1000000) // < $1M

    console.log(`Verified Bitcoin price: $${attestedPrice.price.toFixed(2)}`)
  })

  it('should verify signature using pure circuit', async () => {
    // Get attested Bitcoin price using the prover client
    const attestedPrice = await proverClient.getBitcoinPrice()

    // Create SignedBytes structure for pure circuit
    const signedBytes = toContractSignedBytes(
      attestedPrice.rawData,
      attestedPrice.signature,
      attestedPrice.notaryPk
    )

    // Verify using pure circuit (no ledger access needed)
    const isValid = pureCircuits.verifyNotarySignature(signedBytes)

    console.log(`Pure circuit signature verification: ${isValid}`)
    expect(isValid).toBe(true)
  })

  it('should fetch Ethereum price', async () => {
    // Get attested Ethereum price
    const attestedPrice = await proverClient.getAssetPrice('Ethereum')

    console.log(`Ethereum price: $${attestedPrice.price.toFixed(2)}`)
    console.log(`Symbol: ${attestedPrice.symbol}`)
    console.log(`Timestamp: ${attestedPrice.timestamp.toISOString()}`)

    expect(attestedPrice.symbol).toBe('ETH')
    expect(attestedPrice.price).toBeGreaterThan(100) // > $100
    expect(attestedPrice.price).toBeLessThan(100000) // < $100k
  })
})
