import { describe, it, expect } from 'vitest';
import {
  ContractSimulator,
  generateNonce,
  pad
} from '@statera/simulator';
import { tokenType } from '@midnight-ntwrk/ledger';
import { sampleContractAddress } from '@midnight-ntwrk/compact-runtime';
import {
  Contract,
  createPrivateStateraState,
  witnesses
} from '../index.js';
import { ledger } from '../managed/adaStateraProtocol/contract/index.cjs';
import {
  createStateraTestFixture,
  createCollateralCoin,
  prepareCoinForReceive,
  createMockOraclePk,
  createMockComplianceToken,
  asWallet
} from './test-utils.js';

describe('Merkle Tree Debug Tests', () => {
  it('should debug findPathForLeaf and pathForLeaf after insertion', () => {
    const fixture = createStateraTestFixture(1);
    const { simulator, userWallets, contractAddress, collateralTokenType } = fixture;
    const user = userWallets[0];

    // Step 1: Add oracle
    const oraclePk = createMockOraclePk();
    simulator
      .as(simulator.getPrivateState())
      .executeImpureCircuit('addTrustedOracle', oraclePk);

    // Step 2: Deposit to create a commitment in the tree
    const depositAmount = 1000n;
    const collateralCoin = createCollateralCoin(depositAmount);
    const complianceToken = createMockComplianceToken(user.coinPublicKey, oraclePk);

    prepareCoinForReceive(simulator, collateralCoin, collateralTokenType);

    console.log('\n=== BEFORE DEPOSIT ===');
    const ledgerBefore = ledger(simulator.getLedger());
    console.log('firstFree BEFORE:', ledgerBefore.depositorCommitments.firstFree());
    console.log('root BEFORE:', ledgerBefore.depositorCommitments.root().field);

    // Execute deposit
    asWallet(simulator, user)
      .executeImpureCircuit(
        'depositToCollateralPool',
        collateralCoin,
        depositAmount,
        complianceToken,
        true
      );

    console.log('\n=== AFTER DEPOSIT ===');
    const ledgerAfter = ledger(simulator.getLedger());
    const firstFree = ledgerAfter.depositorCommitments.firstFree();
    const currentRoot = ledgerAfter.depositorCommitments.root();
    console.log('firstFree AFTER:', firstFree);
    console.log('root AFTER:', currentRoot.field);

    const history = Array.from(ledgerAfter.depositorCommitments.history());
    console.log('history length:', history.length);
    history.forEach((root, idx) => {
      console.log(`  Root ${idx}: field = ${root.field}`);
    });

    // Step 3: Get the commitment hash that was inserted
    // We need to compute what the deposit circuit created
    const privateState = simulator.getPrivateState();
    console.log('\n=== PRIVATE STATE (what test stored) ===');
    console.log('Has currentDepositorCommitment?', !!privateState.currentDepositorCommitment);

    // For this debug test, let's manually create a test commitment to search for
    // We'll use a known value - just 32 bytes of 0x01
    const testCommitment = new Uint8Array(32);
    testCommitment.fill(0x01);

    console.log('\n=== TEST 1: findPathForLeaf with TEST commitment (0x01...) ===');
    try {
      const path1 = ledgerAfter.depositorCommitments.findPathForLeaf(testCommitment);
      console.log('Result:', path1 === null ? 'null' : path1 === undefined ? 'undefined' : 'found!');
      if (path1) {
        console.log('  path.leaf:', Array.from(path1.leaf.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
      }
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    console.log('\n=== TEST 2: pathForLeaf at index 0 with TEST commitment ===');
    try {
      const path2 = ledgerAfter.depositorCommitments.pathForLeaf(0n, testCommitment);
      console.log('Result: path retrieved');
      console.log('  path.leaf (first 8):', Array.from(path2.leaf.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
      console.log('  leaf matches input?', Array.from(path2.leaf).every((b, i) => b === testCommitment[i]));
      console.log('  Number of siblings:', path2.path.length);
      console.log('  All siblings zero?', path2.path.every((entry: any) => entry.sibling.field === 0n));
    } catch (e) {
      console.log('ERROR:', (e as Error).message);
    }

    // Step 4: Now try to manually enumerate what's in the tree
    console.log('\n=== TEST 3: Enumerate tree by trying pathForLeaf at each index ===');
    for (let i = 0n; i < firstFree; i++) {
      try {
        // Get path at this index with a dummy leaf
        const dummyLeaf = new Uint8Array(32);
        dummyLeaf.fill(0xFF);
        const path = ledgerAfter.depositorCommitments.pathForLeaf(i, dummyLeaf);
        console.log(`Index ${i}:`);
        console.log(`  path.leaf (first 8): ${Array.from(path.leaf.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`  Leaf matches dummy? ${Array.from(path.leaf).every((b, idx) => b === dummyLeaf[idx])}`);

        // Try with a different dummy to see if path.leaf changes
        const dummyLeaf2 = new Uint8Array(32);
        dummyLeaf2.fill(0xAA);
        const path2 = ledgerAfter.depositorCommitments.pathForLeaf(i, dummyLeaf2);
        console.log(`  With different dummy, path.leaf (first 8): ${Array.from(path2.leaf.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`  CONCLUSION: pathForLeaf just sets path.leaf to whatever you pass in!`);
      } catch (e) {
        console.log(`Index ${i}: ERROR - ${(e as Error).message}`);
      }
    }

    // Step 5: Try to find what's ACTUALLY at index 0
    console.log('\n=== TEST 4: What is the ACTUAL commitment at index 0? ===');
    console.log('We cannot retrieve it from the tree API!');
    console.log('The tree only stores HASHES, not the original leaf data.');
    console.log('So there is NO WAY to retrieve the actual commitment hash from the tree!');

    console.log('\n=== TEST 5: Can we compute what the root SHOULD be? ===');
    console.log('For a single element at index 0, the root should be:');
    console.log('hash(hash(hash(...hash(commitment, 0), 0)..., 0)) with 20 levels');
    console.log('But we cannot verify this without implementing the Merkle hash function ourselves.');

    // This test is mainly for debugging - we don't expect it to pass
    expect(firstFree).toBe(1n);
  });

  it('should test if findPathForLeaf works with commitment from getPrivateStateAfterDeposit', async () => {
    const { getPrivateStateAfterDeposit } = await import('./test-utils.js');

    const fixture = createStateraTestFixture(1);
    const { simulator, userWallets, collateralTokenType } = fixture;
    const user = userWallets[0];

    // Add oracle
    const oraclePk = createMockOraclePk();
    simulator
      .as(simulator.getPrivateState())
      .executeImpureCircuit('addTrustedOracle', oraclePk);

    // Deposit
    const depositAmount = 1000n;
    const collateralCoin = createCollateralCoin(depositAmount);
    const complianceToken = createMockComplianceToken(user.coinPublicKey, oraclePk);

    prepareCoinForReceive(simulator, collateralCoin, collateralTokenType);

    asWallet(simulator, user)
      .executeImpureCircuit(
        'depositToCollateralPool',
        collateralCoin,
        depositAmount,
        complianceToken,
        true
      );

    // Use getPrivateStateAfterDeposit to get the correct commitment
    const privateStateWithCommitment = getPrivateStateAfterDeposit(
      simulator,
      user,
      depositAmount,
      collateralTokenType
    );

    const storedCommitment = privateStateWithCommitment.currentDepositorCommitment;

    console.log('\n=== TEST: findPathForLeaf with commitment from getPrivateStateAfterDeposit ===');
    console.log('Has commitment?', !!storedCommitment);
    if (storedCommitment) {
      console.log('Commitment (ALL 32):', Array.from(storedCommitment).map(b => b.toString(16).padStart(2, '0')).join(''));
      console.log('Type:', typeof storedCommitment);
      console.log('Is Uint8Array?', storedCommitment instanceof Uint8Array);
      console.log('Length:', storedCommitment.length);

      const ledgerAfter = ledger(simulator.getLedger());
      const currentRoot = ledgerAfter.depositorCommitments.root();
      console.log('Current root:', currentRoot.field);

      const history = Array.from(ledgerAfter.depositorCommitments.history());
      console.log('History:');
      history.forEach((root, idx) => {
        console.log(`  Root ${idx}: ${root.field} ${root.field === currentRoot.field ? '← CURRENT' : ''}`);
      });

      console.log('\n--- Testing findPathForLeaf ---');
      try {
        const path = ledgerAfter.depositorCommitments.findPathForLeaf(storedCommitment);
        console.log('Result:', path === null ? 'null' : path === undefined ? 'undefined' : 'FOUND!');

        if (path) {
          console.log('✅ Path found!');
          console.log('  path.leaf (ALL 32):', Array.from(path.leaf).map(b => b.toString(16).padStart(2, '0')).join(''));
          console.log('  Matches our commitment?', Array.from(path.leaf).every((b, i) => b === storedCommitment[i]));
        } else {
          console.log('❌ Path NOT found - findPathForLeaf is definitely buggy');
        }
      } catch (e) {
        console.log('ERROR:', (e as Error).message);
      }

      console.log('\n--- Testing pathForLeaf at index 0 ---');
      try {
        const path = ledgerAfter.depositorCommitments.pathForLeaf(0n, storedCommitment);
        console.log('Result: path retrieved');
        console.log('  path.leaf matches our commitment?', Array.from(path.leaf).every((b, i) => b === storedCommitment[i]));
        console.log('  Number of siblings:', path.path.length);

        // Check first few siblings
        console.log('  First 3 siblings:');
        for (let i = 0; i < Math.min(3, path.path.length); i++) {
          console.log(`    Sibling ${i}: field = ${(path.path[i] as any).sibling.field}, goes_left = ${(path.path[i] as any).goes_left}`);
        }

        // Now try to verify this path with checkRoot
        console.log('\n--- Verifying path with checkRoot ---');
        const { merkleTreePathRootNoLeafHash } = await import('@midnight-ntwrk/compact-runtime');
        try {
          const computedRoot = merkleTreePathRootNoLeafHash(20, path);
          console.log('Computed root from path:', computedRoot.field);
          console.log('Current tree root:      ', currentRoot.field);
          console.log('Roots match?', computedRoot.field === currentRoot.field);

          // Check if it matches any historical root
          const matchingHistoryIdx = history.findIndex(r => r.field === computedRoot.field);
          if (matchingHistoryIdx >= 0) {
            console.log(`✅ Computed root matches historical root ${matchingHistoryIdx}!`);
          } else {
            console.log('❌ Computed root does NOT match ANY historical root!');
          }

          // Try checkRoot
          const checkResult = ledgerAfter.depositorCommitments.checkRoot(computedRoot);
          console.log('checkRoot result:', checkResult);
        } catch (e) {
          console.log('ERROR computing/checking root:', (e as Error).message);
        }
      } catch (e) {
        console.log('ERROR:', (e as Error).message);
      }
    }

    expect(storedCommitment).toBeDefined();
  });
});
