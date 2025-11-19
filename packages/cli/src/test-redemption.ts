import { createLogger } from './logger-utils.js'
import { StandaloneConfig } from './config.js'
import {
  buildWalletAndWaitForFunds,
  createWalletAndMidnightProvider
} from './index.js'
import { StateraAPI } from '@statera/statera-api'
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider'
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider'
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider'
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider'
import { PrivateStateId } from '@midnight-ntwrk/midnight-js-types'

/**
 * Test script that demonstrates the sUSD redemption flow
 *
 * This test demonstrates:
 * 1. Depositing collateral
 * 2. Minting sUSD
 * 3. Redeeming sUSD for ADA (new feature!)
 *
 * Prerequisites:
 *   Deploy a contract first:
 *     bun run src/launcher/standalone.ts
 *
 *   Then run this test with the deployed contract address:
 *     CONTRACT_ADDRESS="..." bun run src/test-redemption.ts
 */

async function testRedemption() {
  const config = new StandaloneConfig()
  const logger = await createLogger(config.logDir)

  logger.info('=== Starting sUSD Redemption Test ===')

  try {
    // Step 1: Build wallet using genesis seed (for standalone network)
    logger.info('Building wallet with genesis seed...')
    const GENESIS_MINT_WALLET_SEED =
      '0000000000000000000000000000000000000000000000000000000000000001'
    const wallet = await buildWalletAndWaitForFunds(
      config,
      GENESIS_MINT_WALLET_SEED,
      '',
      logger
    )

    logger.info('Wallet funded and ready')

    // Step 2: Build providers (exactly like the CLI does)
    const walletAndMidnightProvider =
      await createWalletAndMidnightProvider(wallet)
    const providers = {
      privateStateProvider: levelPrivateStateProvider<PrivateStateId>({
        privateStateStoreName: config.privateStateStoreName as string
      }),
      publicDataProvider: indexerPublicDataProvider(
        config.indexer,
        config.indexerWS
      ),
      zkConfigProvider: new NodeZkConfigProvider<never>(config.zkConfigPath),
      proofProvider: httpClientProofProvider(config.proofServer),
      walletProvider: walletAndMidnightProvider,
      midnightProvider: walletAndMidnightProvider
    }

    // Step 3: Join the contract
    const contractAddress = process.env.CONTRACT_ADDRESS
    if (!contractAddress) {
      throw new Error(
        'CONTRACT_ADDRESS environment variable not set. Deploy a contract first using: bun run src/launcher/standalone.ts'
      )
    }

    logger.info({ contractAddress }, 'Joining contract...')
    const stateraApi = await StateraAPI.joinStateraContract(
      providers,
      contractAddress,
      logger
    )
    logger.info('Successfully joined contract')

    // Step 4: Deposit collateral (1000 ADA)
    logger.info('Step 1: Depositing 1000 ADA as collateral...')
    const depositResult = await stateraApi.depositToCollateralPool(1000)
    logger.info('Deposit successful', {
      txHash: depositResult.public.txHash,
      blockHeight: depositResult.public.blockHeight
    })

    // Step 5: Mint sUSD (500 sUSD, safe ratio)
    logger.info('Step 2: Minting 500 sUSD...')
    const mintResult = await stateraApi.mint_sUSD(500)
    logger.info('Mint successful', {
      txHash: mintResult.public.txHash,
      mintedAmount: 500,
      blockHeight: mintResult.public.blockHeight
    })

    // Step 6: Redeem sUSD for ADA
    // Oracle price: 1 ADA = $1 (scaled to 1000000 for precision)
    const oraclePrice = 1000000
    const amountToRedeem = 100

    // Use a trusted oracle PK (in production, this would come from your oracle service)
    const oraclePk =
      process.env.ORACLE_PK ||
      '0000000000000000000000000000000000000000000000000000000000000000'

    logger.info(
      `Step 3: Redeeming ${amountToRedeem} sUSD for ADA at price $${oraclePrice / 1000000}...`
    )
    const redeemResult = await stateraApi.redeemSUSD(
      amountToRedeem,
      oraclePrice,
      oraclePk
    )

    logger.info('Redemption successful!', {
      txHash: redeemResult.public.txHash,
      amountRedeemed: amountToRedeem,
      oraclePrice: oraclePrice,
      expectedADAReceived: `~${amountToRedeem * 0.995} ADA (after 0.5% fee)`,
      blockHeight: redeemResult.public.blockHeight
    })

    // Step 7: Verify redemption
    logger.info('=== Redemption Test Summary ===')
    logger.info('✅ Deposited: 1000 ADA')
    logger.info('✅ Minted: 500 sUSD')
    logger.info(`✅ Redeemed: ${amountToRedeem} sUSD for ADA`)
    logger.info(
      `✅ Redemption fee: 0.5% (${amountToRedeem * 0.005} ADA deducted)`
    )
    logger.info(`✅ Net ADA received: ~${amountToRedeem * 0.995} ADA`)
    logger.info('=== Test completed successfully ===')
  } catch (error) {
    logger.error('Test failed with error:', error)
    throw error
  }
}

// Run the test
testRedemption()
  .then(() => {
    console.log('✅ Redemption test passed')
    process.exit(0)
  })
  .catch((error) => {
    console.error('❌ Redemption test failed:', error)
    process.exit(1)
  })
