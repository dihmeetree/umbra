# Statera Protocol

A privacy-preserving, over-collateralized stablecoin protocol built on the Midnight blockchain.

[![Tests](https://img.shields.io/badge/tests-70%20passing-success)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)]()
[![Midnight](https://img.shields.io/badge/Midnight-Compact-purple)]()

## Overview

**Statera** enables users to deposit collateral (ADA) privately and mint sUSD (Statera USD) tokens while maintaining complete privacy of their financial positions through zero-knowledge proofs. Inspired by Aave's lending mechanics and adapted for Midnight's privacy-first architecture.

### Key Features

- 🔒 **Privacy-First**: All collateral amounts and debt positions are stored off-chain using zero-knowledge witnesses
- 💎 **Over-Collateralized**: Requires collateral ratios above 100% to ensure stability
- 🛡️ **Liquidation Protection**: Stakers provide liquidity to cover liquidated positions
- 🌐 **Decentralized**: No central authority controls user funds or positions
- ⚡ **Fast & Efficient**: Optimized circuit execution with comprehensive testing

## Architecture

```
statera/
├── packages/
│   ├── contracts/ada-statera-protocol/  # Smart contract (Compact)
│   ├── simulator/                       # Testing framework
│   ├── api/                            # API for interacting with protocol
│   ├── cli/                            # Command-line interface
│   ├── server/                         # Backend services
│   └── ui/                             # Frontend application
└── docs/                               # Documentation
```

## Quick Start

### Prerequisites

- Node.js 18+ or Bun
- Yarn or npm
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/dihmeetree/statera.git
cd statera

# Install dependencies
bun install

# Build all packages
bun run build
```

### Running Tests

```bash
# Run all tests
bun test

# Run contract tests only
cd packages/contracts/ada-statera-protocol
bun test

# Run specific test file
bun test protocol-integration.test.ts
```

## Protocol Features

### For Borrowers

1. **Deposit Collateral**: Lock ADA as collateral in a privacy-preserving manner
2. **Mint sUSD**: Borrow synthetic USD tokens against your collateral
3. **Manage Position**: Repay debt, withdraw collateral, monitor health factor
4. **Privacy Guaranteed**: All position data remains private via zero-knowledge proofs

### For Stakers

1. **Provide Liquidity**: Stake sUSD tokens in the stability pool
2. **Earn Rewards**: Receive collateral from liquidated positions
3. **Risk Mitigation**: Help maintain protocol stability
4. **Withdraw Anytime**: Claim rewards and withdraw stake at any time

### For Liquidators

1. **Monitor Positions**: Identify undercollateralized positions
2. **Execute Liquidations**: Liquidate risky positions to protect protocol
3. **Earn Incentives**: Receive liquidation incentives (default: 5%)

## Testing Infrastructure

The protocol includes a **comprehensive test infrastructure** with:

### Test Builders

Fluent APIs for constructing test scenarios:

```typescript
// Simple deposit and mint
new DepositBuilder(simulator, fixture)
  .forUser(user)
  .amount(TestData.deposits.STANDARD)
  .execute()

new MintBuilder(simulator, fixture)
  .forUser(user)
  .withCollateral(TestData.deposits.STANDARD)
  .amount(TestData.mints.AT_LVT)
  .execute()
```

### Test Data Factories

Centralized constants for consistent testing:

```typescript
import { TestData } from './test-data'

const depositAmount = TestData.deposits.STANDARD // 1000n
const mintAmount = TestData.mints.AT_LVT // 700n
const totalDebt = TestData.calc.calculateTotalDebt(mintAmount)
```

### State Inspection

Visual debugging and state comparison:

```typescript
import { inspectState } from './state-inspector'

const inspector = inspectState(simulator)
inspector.snapshot('before-mint')
// ... execute operations ...
inspector.snapshot('after-mint')
console.log(inspector.printDiff('before-mint', 'after-mint'))
```

### Simulator Enhancements

History tracking and performance metrics:

```typescript
import { withHistory } from '@statera/simulator'

const tracker = withHistory(simulator)
const metrics = tracker.getMetrics()
console.log(`Average duration: ${metrics.averageDuration}ms`)
```

See [TESTING.md](packages/contracts/ada-statera-protocol/TESTING.md) for complete testing guide.

## Documentation

- **[Testing Guide](packages/contracts/ada-statera-protocol/TESTING.md)** - Comprehensive guide to writing tests
- **[Improvements](packages/contracts/ada-statera-protocol/IMPROVEMENTS.md)** - Recent infrastructure improvements
- **[Contract README](packages/contracts/ada-statera-protocol/README.md)** - Smart contract documentation
- **[Simulator README](packages/simulator/README.md)** - Testing framework documentation

## Package Overview

### [@statera/ada-statera-protocol](packages/contracts/ada-statera-protocol)

The core smart contract written in Midnight's Compact language. Implements:

- Collateralized debt positions (CDPs)
- Synthetic stablecoin minting (sUSD)
- Stability pool for liquidations
- Privacy-preserving position management

**Status**: ✅ 70 tests passing

### [@statera/simulator](packages/simulator)

Advanced testing framework for Midnight Compact contracts:

- Contract deployment and simulation
- Wallet management
- Balance tracking
- History tracking and metrics
- State inspection tools

### [@statera/api](packages/api)

TypeScript API for interacting with the Statera protocol.

### [@statera/cli](packages/cli)

Command-line interface for protocol operations.

### [@statera/server](packages/server)

Backend services including liquidation monitoring.

### [@statera/ui](packages/ui)

Frontend application for user interactions.

## Development

### Project Structure

```
packages/
├── contracts/ada-statera-protocol/
│   ├── src/
│   │   ├── adaStateraProtocol.compact    # Main contract
│   │   ├── CustomLibrary.compact         # Helper functions
│   │   ├── witnesses.ts                  # Witness functions
│   │   ├── witness-errors.ts             # Error handling
│   │   └── __tests__/                    # Test suite
│   │       ├── test-builders.ts          # Fluent test APIs
│   │       ├── test-data.ts              # Test constants
│   │       ├── state-inspector.ts        # State debugging
│   │       └── test-helpers/             # Organized helpers
│   ├── TESTING.md                        # Testing guide
│   └── IMPROVEMENTS.md                   # Recent improvements
└── simulator/
    └── src/
        ├── ContractSimulator.ts          # Core simulator
        ├── SimulatorExtensions.ts        # History tracking
        └── ...
```

### Running Development Server

```bash
# Start development server
bun run dev

# Watch mode for tests
bun test --watch
```

### Building

```bash
# Build all packages
bun run build

# Build specific package
cd packages/contracts/ada-statera-protocol
bun run build
```

## Protocol Parameters

| Parameter                      | Default  | Description                                              |
| ------------------------------ | -------- | -------------------------------------------------------- |
| Liquidation Threshold          | 80%      | Collateral ratio below which positions can be liquidated |
| Loan-to-Value (LVT)            | 70%      | Maximum borrowing ratio against collateral               |
| Minimum Collateral Ratio (MCR) | 110%     | Minimum safe collateral ratio                            |
| Borrowing Fee                  | 0.5%     | Fee charged on minting sUSD                              |
| Redemption Fee                 | 0.5%     | Fee charged on redeeming sUSD for collateral             |
| Liquidation Incentive          | 5%       | Reward for liquidators                                   |
| Minimum Debt                   | 100 sUSD | Minimum debt position size                               |

## Recent Improvements

### Test Infrastructure (January 2025)

✅ **Witness Function Type Safety**

- Custom error classes with context
- Validation helpers
- Better error messages

✅ **Test Organization**

- Split test-utils into focused modules
- Domain-specific helper files
- Improved code organization

✅ **Test Data Factories**

- Centralized constants
- Pre-configured scenarios
- Calculation helpers

✅ **Simulator Enhancements**

- History tracking
- Event logging
- Performance metrics

✅ **State Inspection Tools**

- Snapshot and comparison
- Visual debugging
- JSON export

See [IMPROVEMENTS.md](packages/contracts/ada-statera-protocol/IMPROVEMENTS.md) for details.

## Contributing

We welcome contributions! Please see our contributing guidelines (coming soon).

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Ensure all tests pass
6. Submit a pull request

## Security

This protocol is currently in **development**. Do not use in production without:

- ✅ Comprehensive security audit
- ✅ Oracle integration for price feeds
- ✅ Emergency pause mechanisms
- ✅ Governance implementation
- ✅ Extensive testing on testnet

## License

MIT License - see LICENSE file for details

## Links

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/dihmeetree/statera/issues)
- **Midnight Network**: [midnight.network](https://midnight.network)

## Acknowledgments

Built with:

- [Midnight Compact](https://midnight.network) - Privacy-preserving smart contract language
- [TypeScript](https://www.typescriptlang.org/) - Type-safe development
- [Bun](https://bun.sh/) - Fast JavaScript runtime
- [Vitest](https://vitest.dev/) - Testing framework

Inspired by:

- [Aave](https://aave.com/) - Lending protocol mechanics
- [Liquity](https://www.liquity.org/) - Stability pool design

---

**Built with [Claude Code](https://claude.com/claude-code) via [Happy](https://happy.engineering)**
