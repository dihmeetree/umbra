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
 * Test script that replicates the UI deposit flow
 *
 * To deploy a contract first:
 *   bun run src/launcher/standalone.ts
 *
 * Then run this test with the deployed contract address:
 *   CONTRACT_ADDRESS="..." bun run src/test-deposit.ts
 */

async function testDeposit() {
  const config = new StandaloneConfig()
  const logger = await createLogger(config.logDir)

  logger.info('=== Starting Deposit Collateral Test ===')

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

    logger.info('Wallet funded and ready for deposit testing')

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

    // Step 5: Attempt deposit (exactly like the CLI does)
    const amountToDeposit = 10 // 10 tDUST
    logger.info(
      { amount: amountToDeposit },
      'Attempting to deposit collateral...'
    )

    try {
      // This is the exact same call the UI makes
      const txData = await stateraApi.depositToCollateralPool(amountToDeposit)

      logger.info(
        {
          txHash: txData.public.txHash,
          blockHeight: txData.public.blockHeight,
          blockHash: txData.public.blockHash
        },
        '✅ Deposit successful!'
      )

      console.log('\n✅ DEPOSIT SUCCEEDED!')
      console.log(`Transaction Hash: ${txData.public.txHash}`)
      console.log(`Block Height: ${txData.public.blockHeight}`)
    } catch (error) {
      logger.error({ error }, '❌ Deposit failed')

      // Detailed error logging
      if (error instanceof Error) {
        logger.error(
          {
            name: error.name,
            message: error.message
          },
          'Error details'
        )

        console.error('\n❌ DEPOSIT FAILED!')
        console.error(`Error: ${error.message}`)

        // Check error type
        if (
          error.message.includes('prove-tx') ||
          error.message.includes('Proof Server') ||
          error.message.includes('400')
        ) {
          console.error('\n🔍 This is a PROOF SERVER ERROR')
          console.error('The proof generation failed on the server side.')
          console.error('\nTo see detailed logs:')
          console.error('  docker logs manual-statera-proof-server --tail 100')
        } else if (
          error.message.includes('assert') ||
          error.message.includes('Unauthorized')
        ) {
          console.error('\n🔍 This is a CIRCUIT ASSERTION ERROR')
          console.error('The circuit validation failed.')
          console.error('\nPossible causes:')
          console.error('  - Trusted oracle not in the list')
          console.error('  - Invalid token type')
          console.error('  - Insufficient balance')
        }

        // Print stack trace
        if (error.stack) {
          console.error('\nStack trace:')
          console.error(error.stack)
        }
      }

      throw error
    }
  } catch (error) {
    logger.error(
      {
        error,
        errorType: typeof error,
        errorConstructor: error?.constructor?.name
      },
      'Test execution failed'
    )
    console.error('\n❌ TEST EXECUTION FAILED')
    console.error('Error:', error)
    if (error instanceof Error) {
      console.error('Message:', error.message)
      console.error('Stack:', error.stack)
    }
    throw error
  }
}

// Run the test
testDeposit()
  .then(() => {
    console.log('\n✅ Test completed successfully')
    process.exit(0)
  })
  .catch((error) => {
    console.error('\n❌ Test failed')
    process.exit(1)
  })
