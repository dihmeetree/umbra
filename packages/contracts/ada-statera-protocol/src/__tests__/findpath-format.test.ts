import { describe, it, expect } from 'vitest';
import {
  createStateraTestFixture,
  createCollateralCoin,
  prepareCoinForReceive,
  createMockOraclePk,
  createMockComplianceToken,
  asWallet,
  getPrivateStateAfterDeposit
} from './test-utils.js';
import { ledger } from '../managed/adaStateraProtocol/contract/index.cjs';

describe('findPathForLeaf Format Test', () => {
  it('should test different formats for findPathForLeaf', () => {
    const fixture = createStateraTestFixture(1);
    const { simulator, userWallets, collateralTokenType } = fixture;
    const user = userWallets[0];

    // Setup
    const oraclePk = createMockOraclePk();
    simulator.as(simulator.getPrivateState()).executeImpureCircuit('addTrustedOracle', oraclePk);

    // Deposit
    const depositAmount = 1000n;
    const collateralCoin = createCollateralCoin(depositAmount);
    const complianceToken = createMockComplianceToken(user.coinPublicKey, oraclePk);
    prepareCoinForReceive(simulator, collateralCoin, collateralTokenType);

    asWallet(simulator, user).executeImpureCircuit(
      'depositToCollateralPool',
      collateralCoin,
      depositAmount,
      complianceToken,
      true
    );

    const privateState = getPrivateStateAfterDeposit(simulator, user, depositAmount, collateralTokenType);
    const commitment = privateState.currentDepositorCommitment!;
    const ledgerAfter = ledger(simulator.getLedger());

    console.log('\n=== Testing different formats ===');
    console.log('Commitment:', Array.from(commitment).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('Type:', commitment.constructor.name);
    console.log('Is Uint8Array?', commitment instanceof Uint8Array);

    // Test 1: Direct Uint8Array (what we've been doing)
    console.log('\n--- Test 1: Direct Uint8Array ---');
    try {
      const path1 = ledgerAfter.depositorCommitments.findPathForLeaf(commitment);
      console.log('Result:', path1 ? 'FOUND' : 'null/undefined');
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    // Test 2: Create a new Uint8Array copy
    console.log('\n--- Test 2: New Uint8Array copy ---');
    try {
      const commitmentCopy = new Uint8Array(commitment);
      const path2 = ledgerAfter.depositorCommitments.findPathForLeaf(commitmentCopy);
      console.log('Result:', path2 ? 'FOUND' : 'null/undefined');
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    // Test 3: Convert to Buffer and back
    console.log('\n--- Test 3: Buffer conversion ---');
    try {
      const buffer = Buffer.from(commitment);
      const commitmentFromBuffer = new Uint8Array(buffer);
      const path3 = ledgerAfter.depositorCommitments.findPathForLeaf(commitmentFromBuffer);
      console.log('Result:', path3 ? 'FOUND' : 'null/undefined');
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    // Test 4: Try with path from pathForLeaf to see if it has the right format
    console.log('\n--- Test 4: Get leaf from pathForLeaf and search for that ---');
    try {
      const pathFromIndex = ledgerAfter.depositorCommitments.pathForLeaf(0n, commitment);
      console.log('pathForLeaf returned leaf:', Array.from(pathFromIndex.leaf.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
      console.log('Leaf type:', pathFromIndex.leaf.constructor.name);

      // Now search for THIS leaf
      const path4 = ledgerAfter.depositorCommitments.findPathForLeaf(pathFromIndex.leaf);
      console.log('findPathForLeaf with pathForLeaf.leaf:', path4 ? 'FOUND' : 'null/undefined');
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    // Test 5: Check if maybe we need to use the internal representation
    console.log('\n--- Test 5: Check internal tree representation ---');
    try {
      const rawLedger = simulator.getLedger();
      console.log('Raw ledger type:', typeof rawLedger);
      console.log('Raw ledger keys:', Object.keys(rawLedger).slice(0, 10));
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    expect(commitment).toBeDefined();
  });
});
