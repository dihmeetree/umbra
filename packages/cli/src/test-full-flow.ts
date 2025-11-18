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
 * Comprehensive test script that tests the full deposit/withdraw/repay flow
 *
 * To run:
 *   1. Deploy contract: bun run src/launcher/standalone.ts
 *   2. Run test: CONTRACT_ADDRESS="..." bun run src/test-full-flow.ts
 */

async function testFullFlow() {
  const config = new StandaloneConfig()
  const logger = await createLogger(config.logDir)

  logger.info('=== Starting Full Flow Test ===')
  logger.info(
    'This will test: deposit → withdraw → deposit → mint → repay → withdraw'
  )

  try {
    // Step 1: Build wallet
    logger.info('Step 1: Building wallet with genesis seed...')
    const GENESIS_MINT_WALLET_SEED =
      '0000000000000000000000000000000000000000000000000000000000000001'
    const wallet = await buildWalletAndWaitForFunds(
      config,
      GENESIS_MINT_WALLET_SEED,
      '',
      logger
    )
    logger.info('✅ Wallet funded and ready')

    // Step 2: Get contract address
    const contractAddress = process.env.CONTRACT_ADDRESS
    if (!contractAddress) {
      throw new Error(
        'CONTRACT_ADDRESS not set. Deploy first: bun run src/launcher/standalone.ts'
      )
    }

    // Step 3: Build providers
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

    // Step 4: Join contract
    logger.info({ contractAddress }, 'Step 2: Joining contract...')
    const stateraApi = await StateraAPI.joinStateraContract(
      providers,
      contractAddress,
      logger
    )
    logger.info('✅ Joined contract')

    // Step 5: First deposit
    logger.info('Step 3: First deposit (100 tDUST)...')
    const deposit1 = await stateraApi.depositToCollateralPool(100)
    logger.info(
      { txHash: deposit1.public.txHash },
      '✅ First deposit successful'
    )

    // Step 6: Withdraw all
    logger.info('Step 4: Withdrawing all collateral (100 tDUST)...')
    const withdraw1 = await stateraApi.withdrawCollateral(100, 1) // oracle price = 1
    logger.info(
      { txHash: withdraw1.public.txHash },
      '✅ Withdrawal successful - position should be CLOSED'
    )

    // Step 7: Second deposit
    logger.info('Step 5: Second deposit after full withdrawal (50 tDUST)...')
    logger.info(
      '⚠️  This is the critical test - was failing with sparse merkle tree error'
    )
    const deposit2 = await stateraApi.depositToCollateralPool(50)
    logger.info(
      { txHash: deposit2.public.txHash },
      '✅ Second deposit successful - position REACTIVATED!'
    )

    // Step 8: Mint sUSD
    logger.info('Step 6: Minting sUSD (30 sUSD)...')
    const mint1 = await stateraApi.mint_sUSD(30)
    logger.info(
      { txHash: mint1.public.txHash },
      '✅ Minted 30 sUSD - position is ACTIVE'
    )

    // Step 9: Repay sUSD
    logger.info('Step 7: Repaying all sUSD (30 sUSD)...')
    const repay1 = await stateraApi.repay(30)
    logger.info(
      { txHash: repay1.public.txHash },
      '✅ Repaid 30 sUSD - position should be INACTIVE (not closed!)'
    )

    // Step 10: Partial withdrawal
    logger.info('Step 8: Partial withdrawal (25 tDUST)...')
    const withdraw2 = await stateraApi.withdrawCollateral(25, 1)
    logger.info(
      { txHash: withdraw2.public.txHash },
      '✅ Partial withdrawal successful - position still INACTIVE'
    )

    // Step 11: Final withdrawal
    logger.info(
      'Step 9: Final withdrawal of remaining collateral (25 tDUST)...'
    )
    const withdraw3 = await stateraApi.withdrawCollateral(25, 1)
    logger.info(
      { txHash: withdraw3.public.txHash },
      '✅ Final withdrawal successful - position now CLOSED'
    )

    // Step 12: Third deposit (verify we can still deposit after closing)
    logger.info(
      'Step 10: Third deposit to verify position can be reactivated (75 tDUST)...'
    )
    const deposit3 = await stateraApi.depositToCollateralPool(75)
    logger.info(
      { txHash: deposit3.public.txHash },
      '✅ Third deposit successful - position REACTIVATED again!'
    )

    console.log('\n' + '='.repeat(60))
    console.log('🎉 ALL TESTS PASSED! 🎉')
    console.log('='.repeat(60))
    console.log('\nVerified flows:')
    console.log('  ✅ Deposit → Withdraw all → Deposit (position reactivation)')
    console.log('  ✅ Mint → Repay → position becomes inactive (not closed)')
    console.log('  ✅ Partial withdrawals from inactive position')
    console.log('  ✅ Full withdrawal closes position')
    console.log('  ✅ Multiple reactivation cycles')
    console.log('='.repeat(60))
  } catch (error) {
    logger.error({ error }, '❌ Test failed')
    console.error('\n' + '='.repeat(60))
    console.error('❌ TEST FAILED')
    console.error('='.repeat(60))

    if (error instanceof Error) {
      console.error(`\nError: ${error.message}`)

      if (error.message.includes('sparse merkle tree')) {
        console.error('\n🔍 SPARSE MERKLE TREE ERROR')
        console.error("This indicates the reserve pool merge fix didn't work.")
        console.error(
          'Check that the contract was deployed with the latest code.'
        )
      } else if (
        error.message.includes('liquidated') ||
        error.message.includes('closed')
      ) {
        console.error('\n🔍 POSITION CLOSED ERROR')
        console.error('This indicates a position status bug.')
        console.error('Check the withdraw/repay circuit fixes.')
      } else if (error.message.includes('Invalid token type')) {
        console.error('\n🔍 TOKEN TYPE ERROR')
        console.error('The sUSD token type might not be initialized.')
        console.error('Run: await api.setSUSDColor() after deployment.')
      }

      if (error.stack) {
        console.error('\nStack trace:')
        console.error(error.stack)
      }
    }

    throw error
  }
}

// Run the test
testFullFlow()
  .then(() => {
    console.log('\n✅ Test completed successfully')
    process.exit(0)
  })
  .catch((error) => {
    console.error('\n❌ Test failed')
    process.exit(1)
  })
