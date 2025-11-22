# Simulator Usage Examples

## Example 1: Using with Ada Statera Protocol

```typescript
import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad
} from '@statera/simulator'
import { tokenType } from '@midnight-ntwrk/ledger'
import { NetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id'
import { AdaStateraProtocol } from '@statera/ada-statera-protocol'

// Set network ID for testing
setNetworkId(NetworkId.Undeployed)

describe('Ada Statera Protocol Tests', () => {
  let simulator: ContractSimulator<AdaStateraPrivateState>
  let walletManager: WalletManager
  let adminWallet: Wallet
  let userWallet: Wallet

  beforeEach(() => {
    // Create wallets
    walletManager = new WalletManager()
    adminWallet = walletManager.createWallet('admin')
    userWallet = walletManager.createWallet('user')

    // Deploy contract
    simulator = ContractSimulator.deploy(new AdaStateraProtocol.Contract({}), {
      initialPrivateState: { secretKey: adminWallet.secretKey },
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey,
      constructorArgs: [
        /* your constructor args */
      ]
    })
  })

  it('should execute contract circuits', () => {
    // Execute as admin
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('deposit', depositAmount)

    // Execute as user
    simulator
      .as({ secretKey: userWallet.secretKey })
      .executeImpureCircuit('withdraw', withdrawAmount)

    // Check outputs
    const outputs = simulator.getOutputs()
    console.log(`Generated ${outputs.length} outputs`)
  })
})
```

## Example 2: Token Contract Testing

```typescript
import {
  ContractSimulator,
  WalletManager,
  BalanceTracker,
  generateNonce,
  pad
} from '@statera/simulator'
import { tokenType, encodeCoinInfo } from '@midnight-ntwrk/ledger'

describe('Token Contract', () => {
  let simulator: ContractSimulator<TokenPrivateState>
  let walletManager: WalletManager
  let balanceTracker: BalanceTracker
  let tokenColorType: TokenType

  beforeEach(() => {
    walletManager = new WalletManager()
    balanceTracker = new BalanceTracker()

    // Create admin wallet
    const adminWallet = walletManager.createWallet('admin')

    // Deploy contract
    simulator = ContractSimulator.deploy(new TokenContract.Contract({}), {
      initialPrivateState: { secretKey: adminWallet.secretKey },
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey
    })

    // Calculate token type
    tokenColorType = tokenType(pad('my-token', 32), simulator.contractAddress)
  })

  it('should mint and track balances', () => {
    const adminWallet = walletManager.getWallet('admin')!

    // Mint tokens
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('mint', 1000n)

    // Check balance
    const balance = simulator.getBalance(
      adminWallet.coinPublicKey,
      tokenColorType
    )
    expect(balance).toBe(1000n)

    // Track with BalanceTracker
    balanceTracker.updateFromSimulator(
      simulator,
      adminWallet.coinPublicKey,
      'admin'
    )

    // Print balances
    const tokenNames = new Map([[tokenColorType.toString(), 'MyToken']])
    balanceTracker.printBalances('admin', tokenNames)
  })

  it('should handle transfers', () => {
    const adminWallet = walletManager.getWallet('admin')!
    const userWallet = walletManager.createWallet('user')

    // Mint to admin
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('mint', 1000n)

    // Get coin for transfer
    const coin = simulator.getOutputByRecipient(adminWallet.coinPublicKey)
    expect(coin).toBeDefined()

    // Transfer to user
    simulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit(
        'transfer',
        encodeCoinInfo(coin!),
        userWallet.coinPublicKey,
        500n
      )

    // Check user balance
    const userBalance = simulator.getBalance(
      userWallet.coinPublicKey,
      tokenColorType
    )
    expect(userBalance).toBe(500n)

    // Track balance changes
    balanceTracker.updateFromSimulator(
      simulator,
      adminWallet.coinPublicKey,
      'admin'
    )
    balanceTracker.updateFromSimulator(
      simulator,
      userWallet.coinPublicKey,
      'user'
    )

    balanceTracker.printAllBalances()
  })
})
```

## Example 3: Multi-Contract Testing

```typescript
import {
  ContractSimulator,
  WalletManager,
  generateNonce
} from '@statera/simulator'

describe('Multi-Contract Interaction', () => {
  let tokenSimulator: ContractSimulator<TokenPrivateState>
  let dexSimulator: ContractSimulator<DexPrivateState>
  let walletManager: WalletManager

  beforeEach(() => {
    walletManager = new WalletManager()
    const adminWallet = walletManager.createWallet('admin')

    // Deploy token contract
    tokenSimulator = ContractSimulator.deploy(new TokenContract.Contract({}), {
      initialPrivateState: { secretKey: adminWallet.secretKey },
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey
    })

    // Deploy DEX contract
    dexSimulator = ContractSimulator.deploy(new DexContract.Contract({}), {
      initialPrivateState: { secretKey: adminWallet.secretKey },
      nonce: generateNonce(),
      coinPublicKey: adminWallet.coinPublicKey,
      constructorArgs: [tokenSimulator.contractAddress]
    })
  })

  it('should interact between contracts', () => {
    const adminWallet = walletManager.getWallet('admin')!
    const userWallet = walletManager.createWallet('user')

    // Mint tokens
    tokenSimulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('mint', 1000n)

    // Get minted coin
    const coin = tokenSimulator.getOutputByRecipient(adminWallet.coinPublicKey)

    // Provide liquidity to DEX
    dexSimulator
      .as({ secretKey: adminWallet.secretKey })
      .executeImpureCircuit('provideLiquidity', coin)

    // User swaps
    dexSimulator
      .as({ secretKey: userWallet.secretKey })
      .executeImpureCircuit('swap', swapAmount)

    // Check balances in both contracts
    const tokenBalance = tokenSimulator.getBalance(
      userWallet.coinPublicKey,
      tokenType
    )
    console.log(`User token balance: ${tokenBalance}`)
  })
})
```

## Example 4: Advanced Balance Tracking

```typescript
import { BalanceTracker, WalletManager } from '@statera/simulator'

it('should track balance changes over time', () => {
  const balanceTracker = new BalanceTracker()
  const walletManager = new WalletManager()
  const wallet = walletManager.createWallet('trader')

  // Initial mint
  simulator
    .as({ secretKey: wallet.secretKey })
    .executeImpureCircuit('mint', 1000n)

  balanceTracker.updateFromSimulator(simulator, wallet.coinPublicKey, 'trader')

  // Save previous state
  const previousBalances = balanceTracker.getAllBalances('trader')

  // Perform trades
  simulator
    .as({ secretKey: wallet.secretKey })
    .executeImpureCircuit('trade', tradeParams)

  balanceTracker.updateFromSimulator(simulator, wallet.coinPublicKey, 'trader')

  // Calculate and display changes
  const changes = balanceTracker.getBalanceChanges('trader', previousBalances)

  for (const [token, change] of Object.entries(changes)) {
    const sign = change > 0n ? '+' : ''
    console.log(`${token}: ${sign}${change}`)
  }
})
```

## Tips and Best Practices

### 1. Always Generate Fresh Nonces

```typescript
// Good
const nonce1 = generateNonce()
const nonce2 = generateNonce()

// Bad - reusing nonces
const nonce = generateNonce()
// Don't use the same nonce multiple times
```

### 2. Use WalletManager for Organization

```typescript
// Create multiple test users at once
const walletManager = new WalletManager()
const users = walletManager.createWallets(10, 'user')

// Easy access by name
const admin = walletManager.getWallet('admin')
const user5 = walletManager.getWallet('user5')
```

### 3. Track Balances for Complex Tests

```typescript
const balanceTracker = new BalanceTracker()

// Before operation
balanceTracker.updateFromSimulator(simulator, wallet.coinPublicKey, 'before')

// Perform operation
simulator.executeImpureCircuit('operation')

// After operation
balanceTracker.updateFromSimulator(simulator, wallet.coinPublicKey, 'after')

// Compare
const changes = balanceTracker.getBalanceChanges(
  'after',
  balanceTracker.getAllBalances('before')
)
```

### 4. Use Type-Safe Private State

```typescript
interface MyContractPrivateState {
  secretKey: Uint8Array
  customData: string
}

const privateState =
  WalletManager.createPrivateState<MyContractPrivateState>(wallet)
// Add your custom fields
privateState.customData = 'test'

simulator.as(privateState)
```

### 5. Test Error Conditions

```typescript
it('should fail with insufficient balance', () => {
  expect(() => {
    simulator
      .as({ secretKey: poorUser.secretKey })
      .executeImpureCircuit('transfer', largeAmount)
  }).toThrow('Insufficient balance')
})
```
