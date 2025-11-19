# @statera/simulator

A comprehensive testing simulator for Midnight Compact contracts. This package provides an easy-to-use framework for deploying, testing, and interacting with Compact contracts in a simulated environment.

## Features

- **Contract Deployment**: Easy deployment and initialization of Compact contracts
- **Wallet Management**: Create and manage test wallets with automatic key generation
- **Balance Tracking**: Track token balances across multiple wallets and token types
- **Circuit Execution**: Execute both pure and impure circuits with state management
- **Output Management**: Easily access and inspect circuit outputs
- **Type-Safe**: Full TypeScript support with generic types for contract-specific state

## Installation

```bash
yarn add @statera/simulator
```

## Quick Start

```typescript
import { ContractSimulator, WalletManager, generateNonce } from '@statera/simulator';
import { MyContract } from './my-contract';

// Create wallets
const walletManager = new WalletManager();
const adminWallet = walletManager.createWallet('admin');
const userWallet = walletManager.createWallet('user');

// Deploy contract
const simulator = ContractSimulator.deploy(new MyContract.Contract({}), {
  initialPrivateState: { secretKey: adminWallet.secretKey },
  nonce: generateNonce(),
  coinPublicKey: adminWallet.coinPublicKey,
  constructorArgs: [initParam1, initParam2]
});

// Execute circuits as admin
simulator.as({ secretKey: adminWallet.secretKey })
  .executeImpureCircuit('mint', 1000n);

// Execute circuits as user
simulator.as({ secretKey: userWallet.secretKey })
  .executeImpureCircuit('transfer', recipientPubKey, 100n);

// Check balances
const balance = simulator.getBalance(userWallet.coinPublicKey, tokenType);
console.log(`User balance: ${balance}`);

// Get outputs
const outputs = simulator.getOutputs();
console.log(`Generated ${outputs.length} outputs`);
```

## API Reference

### ContractSimulator

The main class for simulating contract interactions.

#### Constructor

```typescript
new ContractSimulator<TPrivateState>(
  contract: ContractWithCircuits<TPrivateState>,
  config: ContractConfig<TPrivateState>
)
```

#### Static Methods

- `deploy<TPrivateState>(contract, config)` - Deploy a new contract with a random address

#### Instance Methods

- `as(privateState)` - Switch to a different user's private state
- `executeCircuit(name, ...args)` - Execute a pure circuit
- `executeImpureCircuit(name, ...args)` - Execute an impure circuit
- `getBalance(recipient, tokenType)` - Get balance for a specific token
- `getAllBalances(recipient)` - Get all token balances for a recipient
- `getOutputByRecipient(recipient)` - Get a single output for a recipient
- `getOutputsByRecipient(recipient)` - Get all outputs for a recipient
- `getOutputs()` - Get all outputs from the last circuit execution
- `getPrivateState()` - Get the current private state
- `getZswapLocalState()` - Get the ZSwap local state
- `getLedger()` - Get the current ledger state

### WalletManager

Manages test wallets and their keys.

#### Methods

- `createWallet(name?)` - Create a new wallet with random keys
- `createWalletFromKey(secretKey, name?)` - Create a wallet from an existing key
- `createWallets(count, namePrefix?)` - Create multiple wallets at once
- `getWallet(name)` - Get a wallet by name
- `getAllWallets()` - Get all registered wallets
- `removeWallet(name)` - Remove a wallet
- `clear()` - Clear all wallets
- `static createPrivateState(wallet)` - Create a private state object from a wallet

### BalanceTracker

Tracks and displays token balances.

#### Methods

- `setBalance(walletKey, tokenType, amount)` - Set a balance
- `getBalance(walletKey, tokenType)` - Get a balance
- `getAllBalances(walletKey)` - Get all balances for a wallet
- `updateFromSimulator(simulator, recipient, walletKey?)` - Update balances from a simulator
- `getBalanceChanges(walletKey, previousBalances)` - Calculate balance changes
- `printBalances(walletKey, tokenNames?)` - Print formatted balances
- `printAllBalances(tokenNames?)` - Print all wallet balances
- `clear()` - Clear all tracked balances

### Utility Functions

- `randomBytes(length)` - Generate random bytes
- `toHex(bytes)` - Convert bytes to hex string
- `fromHex(hex)` - Convert hex string to bytes
- `pad(str, length)` - Pad a string to a specific length
- `createCoinPublicKey(hex?)` - Create a coin public key
- `generateNonce()` - Generate a random nonce
- `generateSecretKey()` - Generate a random secret key

## Example: Complete Test Flow

```typescript
import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad
} from '@statera/simulator';
import { tokenType } from '@midnight-ntwrk/ledger';
import { MyTokenContract } from './my-token-contract';

describe('Token Contract Tests', () => {
  let simulator: ContractSimulator<MyPrivateState>;
  let walletManager: WalletManager;
  let balanceTracker: BalanceTracker;
  let adminWallet: Wallet;
  let userWallet: Wallet;
  let tokenColorType: TokenType;

  beforeEach(() => {
    // Setup wallets
    walletManager = new WalletManager();
    adminWallet = walletManager.createWallet('admin');
    userWallet = walletManager.createWallet('user');

    // Deploy contract
    simulator = ContractSimulator.deploy(
      new MyTokenContract.Contract({}),
      {
        initialPrivateState: { secretKey: adminWallet.secretKey },
        nonce: generateNonce(),
        coinPublicKey: adminWallet.coinPublicKey,
        constructorArgs: [adminWallet.publicKey]
      }
    );

    // Calculate token type
    tokenColorType = tokenType(
      pad('my-token', 32),
      simulator.contractAddress
    );

    // Setup balance tracker
    balanceTracker = new BalanceTracker();
  });

  it('should mint tokens', () => {
    // Mint as admin
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('mint', 1000n);

    // Check balance
    const balance = simulator.getBalance(
      adminWallet.coinPublicKey,
      tokenColorType
    );
    expect(balance).toBe(1000n);

    // Track balance
    balanceTracker.updateFromSimulator(
      simulator,
      adminWallet.coinPublicKey,
      'admin'
    );
    balanceTracker.printBalances('admin');
  });

  it('should transfer tokens', () => {
    // Mint tokens
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('mint', 1000n);

    // Get coin for transfer
    const coin = simulator.getOutputByRecipient(adminWallet.coinPublicKey);

    // Transfer to user
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('transfer', userWallet.coinPublicKey, coin, 500n);

    // Check balances
    const userBalance = simulator.getBalance(
      userWallet.coinPublicKey,
      tokenColorType
    );
    expect(userBalance).toBe(500n);
  });
});
```

## Best Practices

1. **Use WalletManager**: Always use the WalletManager to create and manage test wallets
2. **Switch Context**: Use `as()` to switch between different user contexts
3. **Track Balances**: Use BalanceTracker to monitor changes during tests
4. **Generate Fresh Nonces**: Always generate new nonces for each test
5. **Type Safety**: Leverage TypeScript generics for contract-specific state types

## License

MIT
