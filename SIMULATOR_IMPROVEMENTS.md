# Simulator Package - Missing Features & Improvements

## Current State ✅
- [x] Core simulator with circuit execution
- [x] Wallet management
- [x] Balance tracking
- [x] Logging system with log levels
- [x] Custom error classes with codes
- [x] Snapshot/restore functionality
- [x] Assertion helpers
- [x] Token type utilities

## Missing Features 🔧

### 1. Test Fixture Builder
**Problem**: Each test manually creates fixtures with boilerplate
**Solution**: Add `TestFixtureBuilder` class

```typescript
const fixture = new TestFixtureBuilder()
  .withContract(MyContract)
  .withWallets(5)
  .withTokens(['DUST', 'sUSD', 'sADA'])
  .withInitialBalances({
    user0: { DUST: 1000n },
    user1: { DUST: 2000n }
  })
  .build();
```

### 2. Coin Builder
**Problem**: Creating coins requires manual nonce generation and formatting
**Solution**: Add fluent `CoinBuilder` class

```typescript
const coin = new CoinBuilder()
  .ofType(tokenType)
  .withValue(1000n)
  .withNonce(generateNonce())
  .build();

// Or simpler:
const coin = simulator.createCoin(tokenType, 1000n);
```

### 3. Private State Builder
**Problem**: Creating complex private states is verbose and error-prone
**Solution**: Add `PrivateStateBuilder` class

```typescript
const state = new PrivateStateBuilder<MyState>()
  .forWallet(wallet)
  .withMetadata({ collateral: 1000n, debt: 500n })
  .withDepositorLeaf(...)
  .build();
```

### 4. Circuit Argument Builder
**Problem**: Circuit arguments are positional and hard to maintain
**Solution**: Add type-safe builders

```typescript
const args = new CircuitArgs()
  .add('amount', 1000n)
  .add('oraclePrice', 1_000_000n)
  .add('oraclePk', oraclePk)
  .build();

simulator.executeImpureCircuit('withdraw', ...args);
```

### 5. Mock Generators
**Problem**: Creating mocks (oracles, compliance tokens) requires boilerplate
**Solution**: Add mock generator utilities

```typescript
const mocks = simulator.createMocks({
  oracles: ['oracle1', 'oracle2'],
  complianceTokens: { user1: { did: 'mock-did', validFor: '1year' } }
});
```

### 6. Ledger Inspector
**Problem**: Inspecting ledger state requires manual accessor creation
**Solution**: Add `LedgerInspector` class

```typescript
const inspector = simulator.inspectLedger();
console.log(inspector.getMerkleTreeStatus('depositorCommitments'));
console.log(inspector.getMapContents('depositorNullifiers'));
console.log(inspector.getGlobalState('isPaused'));
```

### 7. Type Descriptor Registry
**Problem**: Type descriptors are recreated everywhere
**Solution**: Add `TypeRegistry` for reusable descriptors

```typescript
const types = new TypeRegistry()
  .register('Bytes32', new CompactTypeBytes(32))
  .register('Uint64', new CompactTypeUnsignedInteger(18446744073709551615n, 8))
  .register('DepositorLeaf', new DepositorLeafDescriptor());

const hash = persistentHash(types.get('DepositorLeaf'), leaf);
```

### 8. Hash Helpers
**Problem**: Hashing requires manual descriptor creation
**Solution**: Add helper functions

```typescript
const hash = simulator.hashStruct('DepositorLeaf', leafData);
const commitment = simulator.commitTo('MintMetadata', metadata, randomizer);
```

### 9. Scenario Runner
**Problem**: Common test scenarios (deposit → mint → repay) are repetitive
**Solution**: Add pre-built scenarios

```typescript
const scenario = simulator.runScenario('depositMintRepay', {
  user: wallet,
  depositAmount: 1000n,
  mintAmount: 500n,
  repayAmount: 200n
});

// Returns { deposits, mints, repays, finalState }
```

### 10. Circuit Execution Chain
**Problem**: Chaining multiple circuits is verbose
**Solution**: Add fluent API

```typescript
simulator
  .asWallet(adminWallet)
  .circuit('addOracle', oraclePk)
  .asWallet(userWallet)
  .circuit('deposit', collateralCoin, 1000n, true)
  .circuit('mint', 500n)
  .getState();
```

### 11. Balance Assertions (Enhanced)
**Problem**: Current assertions are basic
**Solution**: Add more sophisticated assertions

```typescript
// Assert balance changes
await simulator.assertBalanceChanges(
  () => simulator.executeImpureCircuit('mint', 500n),
  {
    [user1]: { sUSD: +500n, DUST: 0n },
    [contract]: { sUSD: -500n }
  }
);

// Assert balances across multiple wallets
simulator.assertBalanceSheet({
  user1: { sUSD: 500n, ADA: 1000n },
  user2: { sUSD: 0n, ADA: 2000n },
  contract: { sUSD: 1000n, ADA: 3000n }
});
```

### 12. Time Travel
**Problem**: Testing time-dependent logic is hard
**Solution**: Add time manipulation

```typescript
simulator.advanceTime(86400); // 1 day in seconds
simulator.setTimestamp(futureTimestamp);
```

### 13. Event/Output Tracking
**Problem**: Tracking outputs across multiple operations is manual
**Solution**: Add event tracking

```typescript
const tracker = simulator.startTracking();

// ... execute circuits ...

const events = tracker.getEvents();
console.log(events.outputs); // All outputs
console.log(events.stateChanges); // State changes
console.log(events.circuitCalls); // Circuit calls
```

### 14. Batch Operations
**Problem**: Running same operation for multiple wallets is repetitive
**Solution**: Add batch helpers

```typescript
// Deposit for multiple users at once
simulator.batchExecute(
  userWallets,
  (wallet) => ({
    circuit: 'deposit',
    args: [createCoin(1000n), 1000n, true],
    asWallet: wallet
  })
);
```

### 15. Contract State Diff
**Problem**: Hard to see what changed after circuit execution
**Solution**: Add state diff utility

```typescript
const before = simulator.captureState();
simulator.executeImpureCircuit('mint', 500n);
const after = simulator.captureState();

const diff = simulator.diffStates(before, after);
console.log(diff);
// {
//   ledger: { depositorCommitments: { firstFree: 0n → 1n } },
//   privateState: { mint_metadata: { debt: 0n → 500n } },
//   outputs: [{ recipient: ..., value: 500n }]
// }
```

## Priority Order 📋

**High Priority** (Most useful for current tests):
1. Coin Builder
2. Ledger Inspector
3. Enhanced Balance Assertions
4. Mock Generators
5. Private State Builder

**Medium Priority**:
6. Test Fixture Builder
7. Circuit Execution Chain
8. Type Descriptor Registry
9. Hash Helpers
10. Batch Operations

**Low Priority** (Nice to have):
11. Circuit Argument Builder
12. Scenario Runner
13. Time Travel
14. Event Tracking
15. State Diff

## Implementation Plan

1. Start with **Coin Builder** and **Mock Generators** (most immediate value)
2. Add **Ledger Inspector** (useful for debugging Merkle tree issues)
3. Enhance **Balance Assertions** (frequently used in tests)
4. Add **Private State Builder** (reduces boilerplate)
5. Consider others based on test needs

Would you like me to implement any of these?
