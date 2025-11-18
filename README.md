# Statera Protocol

> Privacy-preserving over-collateralized stablecoin protocol on Midnight blockchain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Midnight Network](https://img.shields.io/badge/Midnight-TestNet-blue)](https://midnight.network)
[![Node Version](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](https://nodejs.org)

## Overview

**Statera** is a decentralized, privacy-first stablecoin protocol built on the [Midnight blockchain](https://midnight.network) using Compact smart contracts and zero-knowledge proofs. Inspired by Aave's lending mechanics, Statera enables users to deposit collateral (tDUST) privately and mint sUSD (Statera USD) while maintaining complete confidentiality of their financial positions.

### Key Features

- 🔒 **Privacy-First**: All collateral amounts and debt positions stored off-chain using witness functions
- 💰 **Over-Collateralized**: Configurable collateral ratios (default: 120% MCR, 80% LVT) ensure stability
- ⚖️ **Liquidation Protection**: Community-funded stability pool covers undercollateralized positions
- 🌐 **Decentralized Governance**: Multi-admin system with configurable protocol parameters
- 🔐 **KYC Integration**: Support for trusted oracle-based compliance tokens
- 📊 **Real-time State**: Observable contract state via RxJS streams

## Protocol Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Statera Protocol                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Collateral Pool        Stability Pool      Governance  │
│  (tDUST → sUSD)        (Staker Rewards)      (Admins)   │
│       │                      │                  │       │
│       ├──► Depositors        ├──► Stakers       │       │
│       │    • Mint sUSD       │    • Earn ADA    │       │
│       │    • Health Factor   │    • Cover Liq.  │       │
│       └──► Withdraw          └──► Withdraw      └─────► │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Protocol Parameters

| Parameter                          | Default | Description                                      |
| ---------------------------------- | ------- | ------------------------------------------------ |
| **MCR** (Minimum Collateral Ratio) | 120%    | Minimum collateral required to maintain position |
| **LVT** (Loan-to-Value Threshold)  | 80%     | Maximum debt you can take against collateral     |
| **Liquidation Threshold**          | 90%     | Health factor below 1.0 triggers liquidation     |

## Project Structure

This is a **TurboRepo monorepo** with the following packages:

```
statera-protocol/
├── packages/
│   ├── contracts/ada-statera-protocol/  # Compact smart contract
│   │   ├── src/adaStateraProtocol.compact  # Main contract logic
│   │   ├── src/CustomLibrary.compact       # Helper functions
│   │   ├── src/witnesses.ts                # Off-chain witness implementations
│   │   └── src/managed/                    # Generated TypeScript bindings
│   │
│   ├── api/                    # Contract API wrapper
│   │   ├── src/index.ts        # StateraAPI class
│   │   ├── src/common-types.ts # Shared type definitions
│   │   └── src/utils.ts        # Utility functions
│   │
│   ├── cli/                    # Command-line interface
│   │   ├── src/index.ts        # Interactive CLI
│   │   ├── src/test-full-flow.ts  # Integration tests
│   │   └── src/launcher/       # Standalone/testnet modes
│   │
│   ├── server/                 # Backend liquidation service
│   │   └── src/server.ts       # Express + Socket.IO server
│   │
│   └── ui/                     # Web frontend (React + Vite)
│       ├── src/components/     # UI components
│       └── src/providers/      # Context providers
│
├── package.json                # Root workspace config
├── turbo.json                  # TurboRepo configuration
└── yarn.lock                   # Dependency lock file
```

## Prerequisites

### Required Tools

1. **Node.js** ≥ 22.0.0

   ```bash
   node -v  # Should output v22.x.x or higher
   ```

2. **Yarn** (v4.9.2 via Corepack)

   ```bash
   corepack enable
   yarn --version  # Should output 4.9.2
   ```

3. **Compact Compiler** (`compactc`)
   - Installation: [Midnight Compact Compiler Guide](https://docs.midnight.network/develop/tutorial/building/#midnight-compact-compiler)
   - Verify installation:
     ```bash
     compactc --version
     ```

4. **Docker** (optional, for local indexer/proof server)
   - Required for running standalone mode
   - [Install Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Midnight Ecosystem Setup

- **Lace Wallet**: [Chrome Extension Setup Guide](https://docs.midnight.network/develop/tutorial/using/chrome-ext)
- **tDUST Tokens**: [Faucet Guide](https://docs.midnight.network/develop/tutorial/using/proof-server)
- **TestNet Access**: Required for testnet mode

## Quick Start

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/statera-protocol/statera-protocol.git
cd statera-protocol

# Install all dependencies (this may take a few minutes)
yarn install
```

### 2. Build All Packages

The monorepo uses TurboRepo for efficient builds with caching:

```bash
# Build all packages in dependency order
yarn build

# This runs:
# 1. Compile Compact contract → TypeScript bindings
# 2. Build @statera/ada-statera-protocol
# 3. Build @statera/api
# 4. Build @statera/cli
# 5. Build @statera/ui
```

**Build Output**:

```
packages/contracts/ada-statera-protocol/dist/  # Compiled contract + ZK configs
packages/api/dist/                             # API package
packages/cli/dist/                             # CLI executable
packages/ui/dist/                              # Static web assets
```

## Usage

### Option 1: Command-Line Interface (CLI)

The CLI provides an interactive terminal interface for all protocol operations.

#### A. Standalone Mode (No TestNet Required)

Runs with local indexer and proof server using Docker:

```bash
cd packages/cli

# Start local Midnight infrastructure + CLI
yarn standalone

# Or build and run separately
yarn build
bun run dist/launcher/standalone.js
```

**What happens**:

- Deploys contract to local network
- Starts indexer and proof server in Docker containers
- Launches interactive CLI menu

#### B. TestNet Mode

Connect to Midnight TestNet with a live contract:

```bash
cd packages/cli

# Set environment variables
export CONTRACT_ADDRESS="0200..."  # Get from deployment or use existing
export INDEXER_URI="https://indexer.testnet-02.midnight.network/api/v1/graphql"
export INDEXER_WS_URI="wss://indexer.testnet-02.midnight.network/api/v1/graphql/ws"
export PROOF_SERVER_URI="http://13.53.62.251:6300/"
export NETWORK_ID="TestNet"

# Run CLI
yarn testnet-remote
```

#### CLI Menu Options

```
Statera Protocol CLI
─────────────────────────────────────────
1. Check your stake reward (Stakers)
2. Deposit tDUST into collateral pool
3. Deposit sUSD into stability pool (Stakers)
4. Withdraw collateral
5. Mint sUSD (borrow against collateral)
6. Repay sUSD
7. Withdraw stake rewards
8. Withdraw from stability pool
9. Check private state
10. Add admin (Super Admin only)
11. Reset protocol config (Admin only)
12. Set sUSD token type (Admin only)
13. Transfer admin role (Super Admin only)
14. Add trusted KYC oracle (Admin only)
15. Remove trusted KYC oracle (Admin only)
0. Exit
─────────────────────────────────────────
Choose an option:
```

### Option 2: Web UI (React Frontend)

#### Setup Environment

Create `packages/ui/.env`:

```bash
# Required environment variables
VITE_CONTRACT_ADDRESS=0200a03ee06ac2eb8a4cafe8490dc472e0943bf21d8baa4bec46405fd9ea9e89321a
VITE_NETWORK_ID=TestNet
VITE_LOGGING_LEVEL=info
VITE_INDEXER_URL=https://indexer.testnet-02.midnight.network/api/v1/graphql
VITE_INDEXER_WS_URL=wss://indexer.testnet-02.midnight.network/api/v1/graphql/ws
VITE_PROOF_SERVER_URI=http://13.53.62.251:6300/
```

#### Build and Run

```bash
cd packages/ui

# Build the UI package
yarn build

# Start development server
yarn dev

# Or start production server
yarn start
```

**Access**: Open `http://localhost:5173` (dev) or `http://localhost:8080` (prod)

#### Features

- 🔗 **Lace Wallet Integration**: Connect via Midnight DApp Connector
- 📊 **Real-time Dashboard**: View collateral, debt, and health factor
- 💱 **Collateral Management**: Deposit, withdraw, mint, repay
- 🏦 **Stability Pool**: Stake sUSD and earn liquidation rewards
- 👤 **Role Detection**: Different UI for admins vs. regular users

### Option 3: Backend Server (Liquidation Bot)

Automated liquidation monitoring service:

```bash
cd packages/server

# Set environment variables
export CONTRACT_ADDRESS="0200..."
export INDEXER_URI="https://indexer.testnet-02.midnight.network/api/v1/graphql"
export INDEXER_WS_URI="wss://indexer.testnet-02.midnight.network/api/v1/graphql/ws"
export PROOF_SERVER_URI="http://13.53.62.251:6300/"

# Run server
yarn dev
```

**Endpoints**:

- `GET /health` - Health check
- `GET /api/positions` - List all collateral positions
- `POST /api/liquidate/:positionId` - Trigger liquidation

## Development

### Running Individual Package Builds

```bash
# Build only the contract
yarn turbo run build --filter=@statera/ada-statera-protocol

# Build contract + API
yarn turbo run build --filter=@statera/api

# Build everything the CLI depends on
yarn turbo run build --filter=@statera/cli...
```

### Type Checking

```bash
# Check all packages
yarn check-types

# Check specific package
cd packages/cli
npx tsc --noEmit
```

### Linting

```bash
# Lint all packages
yarn lint

# Fix auto-fixable issues
yarn lint --fix
```

### Testing

```bash
# Run full integration test
cd packages/cli
yarn build
bun run dist/test-full-flow.js
```

**Test Coverage**:

- ✅ Deposit → Withdraw → Re-deposit (closed position reactivation)
- ✅ Mint sUSD → Repay → Re-mint
- ✅ Partial withdrawals maintaining active position
- ✅ Stability pool deposits and withdrawals
- ✅ Health factor calculations

## Contract Deployment

### Deploy New Contract

```typescript
import { StateraAPI } from '@statera/api';
import { createWalletAndMidnightProvider } from './wallet-utils';

// Setup providers
const providers = {
  privateStateProvider: levelPrivateStateProvider(...),
  publicDataProvider: indexerPublicDataProvider(...),
  zkConfigProvider: new NodeZkConfigProvider(...),
  proofProvider: httpClientProofProvider(...),
  walletProvider: await createWalletAndMidnightProvider(wallet),
  midnightProvider: await createWalletAndMidnightProvider(wallet),
};

// Deploy contract
const api = await StateraAPI.deployStateraContract(providers, logger);

console.log('Contract Address:', api.deployedContractAddress);

// Initialize protocol
await api.setSUSDColor();  // Set sUSD token type
await api.addTrustedOracle(oraclePk);  // Add KYC oracle
```

### Join Existing Contract

```typescript
const api = await StateraAPI.joinStateraContract(
  providers,
  contractAddress, // "0200..."
  logger
)
```

## Protocol Operations

### For Depositors

```typescript
// 1. Deposit collateral
await api.depositToCollateralPool(100) // 100 tDUST

// 2. Mint sUSD (borrow)
await api.mint_sUSD(40) // Mint 40 sUSD (50% LTV)

// 3. Repay debt
await api.repay(20) // Repay 20 sUSD

// 4. Withdraw collateral
await api.withdrawCollateral(50, 1) // Withdraw 50 tDUST, oracle price = 1
```

### For Stakers

```typescript
// 1. Deposit to stability pool
await api.depositToStakePool(100) // 100 sUSD

// 2. Check rewards
const rewardTx = await api.checkStakeReward()

// 3. Withdraw rewards (liquidation ADA)
await api.withdrawStakeReward(10) // 10 tDUST

// 4. Withdraw principal
await api.withdrawStake(50) // 50 sUSD
```

### For Admins

```typescript
// Update protocol parameters
await api.reset(
  90, // liquidationThreshold (90%)
  80, // LVT (80%)
  120 // MCR (120%)
)

// Add new admin
await api.addAdmin('zpktest1...')

// Add trusted KYC oracle
await api.addTrustedOracle('0x123...')
```

## Witness Functions

Statera uses **witnesses** for private off-chain computation:

| Witness                            | Purpose                                                    |
| ---------------------------------- | ---------------------------------------------------------- |
| `secret_key()`                     | Returns user's private key for ID generation               |
| `get_mintmetadata_private_state()` | Retrieves current collateral and debt                      |
| `set_mint_metadata()`              | Updates private state after operations                     |
| `division()`                       | Performs off-chain division for health factor calculations |

**How it works**:

1. User initiates transaction (e.g., mint sUSD)
2. Witness retrieves private state (collateral: 1000, debt: 0)
3. Contract verifies hash matches on-chain commitment
4. Operation executes, witness updates private state
5. New hash committed to ledger

For detailed explanation, see [CLAUDE.md](./CLAUDE.md)

## Troubleshooting

### Common Issues

**1. "Contract address not configured"**

```bash
# Ensure environment variable is set
export CONTRACT_ADDRESS="0200..."  # For server/CLI
# Or add to .env file for UI
echo 'VITE_CONTRACT_ADDRESS="0200..."' >> packages/ui/.env
```

**2. "compactc: command not found"**

```bash
# Install Compact compiler
# Follow: https://docs.midnight.network/develop/tutorial/building/#midnight-compact-compiler

# Verify installation
compactc --version
```

**3. "Insufficient funds" in standalone mode**

```bash
# The standalone launcher automatically funds wallets
# If issues persist, check Docker containers are running:
docker ps | grep midnight
```

**4. TypeScript errors after pulling updates**

```bash
# Clean and rebuild
yarn clean  # If available
rm -rf node_modules packages/*/node_modules packages/*/dist
yarn install
yarn build
```

**5. "Invalid private state provided"**

- This indicates a mismatch between off-chain and on-chain state
- Clear private state storage and restart wallet
- In CLI: Delete `.level-private-state/` directory

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Follow** code quality standards:
   - Run `yarn check-types` before committing
   - Run `yarn lint` and fix any issues
   - Add tests for new features
4. **Commit** with clear messages following [Conventional Commits](https://www.conventionalcommits.org/)
5. **Push** to your fork and submit a **Pull Request**

### Code Quality Checklist

- [ ] All TypeScript type checks pass
- [ ] No linting errors
- [ ] Code follows existing patterns (see [CLAUDE.md](./CLAUDE.md))
- [ ] Integration tests pass (`test-full-flow.ts`)
- [ ] Documentation updated (if adding features)

## Architecture Documentation

For detailed technical documentation, see:

- **[CLAUDE.md](./CLAUDE.md)** - Development guidelines, commit standards, code quality rules
- **[Witness System Explained](./docs/witnesses.md)** - How privacy-preserving computation works
- **[Contract Documentation](./packages/contracts/ada-statera-protocol/README.md)** - Compact contract specification

## Resources

### Midnight Blockchain

- [Official Documentation](https://docs.midnight.network/)
- [Compact Language Guide](https://docs.midnight.network/develop/compact/)
- [Tutorial: Building DApps](https://docs.midnight.network/develop/tutorial/building/)

### Statera Protocol

- [GitHub Repository](https://github.com/statera-protocol/statera-protocol)
- [Issue Tracker](https://github.com/statera-protocol/statera-protocol/issues)
- [Discussions](https://github.com/statera-protocol/statera-protocol/discussions)

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by **Aave Protocol** lending mechanics
- Built with **Midnight blockchain** and Compact language
- Uses **Zero-Knowledge Proofs** for privacy preservation
- Community-driven stability pool design

---

**Built with ❤️ for privacy-preserving DeFi**
