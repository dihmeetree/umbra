/**
 * Example: Using State Inspector
 *
 * This example demonstrates how to use the StateInspector to track
 * and visualize state changes during test execution.
 */

import { describe, it } from 'vitest'
import { createStateraTestFixture } from '../test-utils.js'
import { DepositBuilder, MintBuilder, AdminBuilder } from '../test-builders.js'
import { TestData } from '../test-data.js'
import { inspectState } from '../state-inspector.js'
import { createMockOraclePk } from '../test-helpers/index.js'

describe('State Inspector Example', () => {
  it('should track and visualize state changes through deposit and mint', () => {
    const fixture = createStateraTestFixture(3)
    const { simulator, adminWallet, userWallets } = fixture
    const user = userWallets[0]
    const oraclePk = createMockOraclePk()

    // Create state inspector
    const inspector = inspectState(simulator)

    // Take snapshot of initial state
    inspector.snapshot('initial')

    console.log('\n' + '='.repeat(60))
    console.log('STATE INSPECTION EXAMPLE')
    console.log('='.repeat(60))

    // Setup oracle
    new AdminBuilder(simulator, adminWallet).addOracle(oraclePk)
    inspector.snapshot('after-oracle-setup')

    // Deposit collateral
    new DepositBuilder(simulator, fixture)
      .forUser(user)
      .amount(TestData.deposits.STANDARD)
      .withCompliance(oraclePk)
      .execute()

    inspector.snapshot('after-deposit')

    // Print state after deposit
    console.log('\n📸 State After Deposit:')
    console.log(inspector.printState(simulator.getPrivateState()))

    // Mint sUSD
    new MintBuilder(simulator, fixture)
      .forUser(user)
      .withCollateral(TestData.deposits.STANDARD)
      .amount(TestData.mints.STANDARD)
      .execute()

    inspector.snapshot('after-mint')

    // Print state after mint
    console.log('\n📸 State After Mint:')
    console.log(inspector.printState(simulator.getPrivateState()))

    // Print differences
    console.log('\n🔍 Changes from Initial to After Deposit:')
    console.log(inspector.printDiff('initial', 'after-deposit'))

    console.log('\n🔍 Changes from After Deposit to After Mint:')
    console.log(inspector.printDiff('after-deposit', 'after-mint'))

    // Export state as JSON
    console.log('\n📄 Exported State (JSON):')
    console.log(inspector.exportState(simulator.getPrivateState()))

    console.log('\n' + '='.repeat(60) + '\n')
  })

  it('should demonstrate health factor calculation in state', () => {
    const fixture = createStateraTestFixture(3)
    const { simulator, adminWallet, userWallets } = fixture
    const user = userWallets[0]
    const oraclePk = createMockOraclePk()

    // Use TestData scenarios
    const scenario = TestData.scenarios.HEALTHY_POSITION

    console.log('\n' + '='.repeat(60))
    console.log('HEALTH FACTOR TRACKING')
    console.log('='.repeat(60))
    console.log(`\nScenario: ${scenario.description}`)

    // Setup
    new AdminBuilder(simulator, adminWallet).addOracle(oraclePk)

    // Create position
    new DepositBuilder(simulator, fixture)
      .forUser(user)
      .amount(scenario.collateral)
      .withCompliance(oraclePk)
      .execute()

    new MintBuilder(simulator, fixture)
      .forUser(user)
      .withCollateral(scenario.collateral)
      .amount(scenario.mint)
      .execute()

    // Check if position is healthy
    const state = simulator.getPrivateState()
    const isHealthy = TestData.thresholds.isHealthy(
      state.mint_metadata.collateral,
      state.mint_metadata.debt,
      TestData.thresholds.DEFAULT_LIQUIDATION
    )

    console.log(`\nCollateral: ${state.mint_metadata.collateral}`)
    console.log(`Debt: ${state.mint_metadata.debt}`)
    console.log(`Is Healthy: ${isHealthy ? '✅ Yes' : '❌ No'}`)

    const hf = TestData.thresholds.calculateHealthFactor(
      state.mint_metadata.collateral,
      state.mint_metadata.debt,
      TestData.thresholds.DEFAULT_LIQUIDATION
    )
    console.log(`Health Factor: ${hf}`)
    console.log('\n' + '='.repeat(60) + '\n')
  })
})
