# Private Polymarket: Anonymous Trading with Full Custody

## Overview

A privacy layer for Polymarket that enables anonymous trading while maintaining full self-custody of funds. Users trade through a shared pool wallet on Polygon, with ownership tracked privately on Midnight blockchain.

**Key Tokens:**

- **Polygon side**: USDC (for Polymarket trades)
- **Midnight side**:
  - USDM (Midnight's native stablecoin - public)
  - $POLY (our private token, 1:1 with USDM - used for private balances)

**Token Flow:**

```
User deposits USDM → Converts to $POLY (private) → Trades/balances in $POLY
                                                 → Bridge converts $POLY to USDC for Polymarket
```

```
┌──────────────────────────────────────────────────────────────────┐
│                           ARCHITECTURE                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│      POLYGON (Public)                    MIDNIGHT (Private)      │
│      ════════════════                    ══════════════════      │
│                                                                  │
│   ┌─────────────────────┐              ┌─────────────────────┐   │
│   │    Pool Wallet      │              │    Private Ledger   │   │
│   │                     │              │                     │   │
│   │   - USDC balance    │◄────────────►│   - User balances   │   │
│   │   - Outcome tokens  │   Relayer    │   - Positions       │   │
│   │   - All markets     │              │   - Order book      │   │
│   └─────────────────────┘              └─────────────────────┘   │
│            │                                      ▲              │
│            │                                      │              │
│            ▼                                      │              │
│   ┌─────────────────────┐              ┌─────────────────────┐   │
│   │     Polymarket      │              │        Users        │   │
│   │     (CLOB/AMM)      │              │    (Private keys)   │   │
│   └─────────────────────┘              └─────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Core Principles

1. **Full Self-Custody**: Users always control their funds via Midnight private keys
2. **1:1 Token Backing**: Every position on Midnight is backed by real tokens in the pool
3. **Anonymous Trading**: Pool wallet is the only on-chain identity; individual users are hidden
4. **Real-Time Execution**: Trades execute on Polymarket with minimal latency
5. **No Hedging/Synthetics**: Pool is a pure pass-through, no risk exposure

---

## How It Works

### Deposit Flow

```
 User                       Midnight                              Polygon
  │                            │                                     │
  │──────  Deposit USDM ──────►│                                     │
  │        (public tx)         │                                     │
  │                            │                                     │
  │                     ┌──────┴─────┐                               │
  │                     │ Convert to │                               │
  │                     │   $POLY    │                               │
  │                     │ (private)  │                               │
  │                     └──────┬─────┘                               │
  │                            │                                     │
  │      Private balance:      │───── Bridge to Pool (batched) ─────►│
  │          +$POLY            │      (converts $POLY → USDC)        │
  │                            │                                     │
```

**Privacy**:

1. User deposits USDM (public on Midnight)
2. Converts to $POLY (now private - this is where anonymity begins)
3. When needed for trades, $POLY is bridged and converted to USDC on Polygon
4. Pool wallet receives USDC from bridge, not from individual users

### Trading Flow

```
 User                       Midnight                    Relayer                 Polymarket
  │                            │                           │                         │
  │─── Buy 1000 KC @ $0.25 ───►│                           │                         │
  │    (signed, encrypted)     │                           │                         │
  │                            │──── Verify balance ──────►│                         │
  │                            │   (ZK proof: user has     │                         │
  │                            │    sufficient $POLY)      │                         │
  │                            │                           │───── Execute trade ────►│
  │                            │                           │  (Pool buys KC tokens)  │
  │                            │                           │                         │
  │                            │◄──── Trade confirmed ─────│                         │
  │                            │                           │                         │
  │     Private balance:       │                           │                         │
  │       -250 $POLY           │                           │                         │
  │     +1000 KC tokens        │                           │                         │
```

**What relayer sees**: "Valid ZK proof requesting KC token purchase"
**What relayer doesn't see**: Which user made the request

### Selling Positions

```
 User wants to sell 1000 KC tokens
              │
              ▼
     ┌────────────────────┐
     │  Internal match?   │──── YES ───► Match with another user buying KC
     │ (check order book) │            (instant, no Polygon tx, max privacy)
     └─────────┬──────────┘
               │ NO
               ▼
     ┌────────────────────┐
     │   Pool sells on    │
     │    Polymarket      │
     └─────────┬──────────┘
               │
               ▼
      Pool: -1000 KC, +USDC
 User on Midnight: -1000 KC, +$POLY
```

### Market Resolution

```
Market: "Who wins Super Bowl?"
Result: KC Chiefs win

Pool Wallet Action:
  - Redeem all KC tokens → $1.00 each
  - All other outcome tokens → $0.00

Midnight Ledger Update:
  - Users holding KC: position converts to $POLY
  - Users holding other outcomes: position → 0
```

### Withdrawal Flow

```
 User                       Midnight                              Polygon
  │                            │                                     │
  │──── Withdraw 1500 $POLY ──►│                                     │
  │     (to fresh address)     │                                     │
  │                            │                                     │
  │                     ┌──────┴──────┐                              │
  │                     │ Convert to  │                              │
  │                     │    USDM     │                              │
  │                     │  (public)   │                              │
  │                     └──────┬──────┘                              │
  │                            │                                     │
  │   Private balance:         │──────── Batched withdrawal ────────►│
  │     -1500 $POLY            │  (converts to USDC, sends to addr)  │
  │                            │        (mixed with others)          │
```

**Withdrawal Options:**

1. **To Polygon (USDC)**: $POLY → Bridge → USDC sent to fresh Polygon address
2. **To Midnight (USDM)**: $POLY → Convert back to USDM on Midnight (public, but fresh address)

**Privacy**: Withdrawals are batched. Observer sees pool sending to multiple addresses in one transaction.

---

## Data Model

### Midnight Private Ledger

```
UserBalance {
  poly: u64,                                        // $POLY balance (private)
  positions: Map<MarketId, Map<OutcomeId, u64>>     // Outcome token positions
}

// Example User:
{
  poly: 5000,                                       // 5000 $POLY available
  positions: {
    "super-bowl-2025": {
      "KC": 5000,
      "DAL": 2000
    },
    "presidential-election-2028": {
      "candidate-a": 10000
    }
  }
}
```

### Pool Wallet State (Polygon)

```
Pool must always hold:
  - USDC: ≥ sum of all user $POLY balances (1:1 backing for withdrawals)
  - Per market/outcome: exactly sum of all user positions

Example:
  Midnight says users own:
    50,000 $POLY (idle balance)
    50,000 KC tokens
    30,000 DAL tokens

  Pool wallet must hold:
    50,000 USDC ✓ (backing for $POLY balances)
    50,000 KC tokens ✓
    30,000 DAL tokens ✓
```

---

## Market Types Supported

### Binary Markets (YES/NO)

```
Market: "Will Bitcoin hit $100k by Dec 2025?"
Outcomes: YES, NO

User can buy/sell YES or NO tokens
Resolution: Winner = $1, Loser = $0
```

### Multi-Outcome Markets

```
Market: "Who wins Super Bowl 2025?"
Outcomes: KC, BUF, PHI, DAL, DET, ... (32 teams)

User can buy/sell any outcome token
Resolution: Winner = $1, All others = $0
```

### Internal Matching

```
Binary:     Buyer of YES ↔ Seller of YES
Multi:      Buyer of KC ↔ Seller of KC (same outcome only)
```

---

## Order Types

### Market Order

Execute immediately at best available price on Polymarket.

### Limit Order

Specify minimum/maximum acceptable price.

- If internal match exists at that price → instant fill
- If not → either rest on internal book or reject

### Partial Fills

Large orders may fill partially if liquidity is limited.

```
User: Sell 10,000 KC @ $0.30 min
Available liquidity: 3,000 @ $0.31

Result:
  Filled: 3,000 KC @ $0.31 (+$930)
  Remaining: 7,000 KC (still in user balance)
```

---

## Self-Custody & Recovery

### Normal Operation

- User's Midnight private key controls their balance
- Can trade anytime
- Can withdraw to any address anytime
- No one can freeze funds

### Recovery Hierarchy

Three levels of recovery, depending on what's still working:

```
┌────────────────────────────────────────────────────────────────────┐
│                         RECOVERY PRIORITY                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1. NORMAL (Relayer + Midnight working)                            │
│     ════════════════════════════════════                           │
│     User → Relayer → Batched withdrawal → Fast & cheap             │
│                                                                    │
│                          │                                         │
│                          │ Relayer down?                           │
│                          ▼                                         │
│                                                                    │
│  2. DIRECT (Midnight still working)                                │
│     ═══════════════════════════════════                            │
│     User → Midnight → ZK Proof → Pool Contract → Funds released    │
│     (No relayer needed, user interacts with Midnight directly)     │
│                                                                    │
│                          │                                         │
│                          │ Midnight also down?                     │
│                          ▼                                         │
│                                                                    │
│  3. EMERGENCY (Last resort - both down)                            │
│     ═══════════════════════════════════                            │
│     30-day timeout → Emergency mode → Use last synced snapshot     │
│     (Anonymity broken, but funds recovered)                        │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Level 1: Normal Withdrawal

```
 User                       Relayer                  Pool Contract
  │                            │                           │
  │──── Request withdrawal ───►│                           │
  │                            │──── Batch with others ───►│
  │                            │                           │
  │◄───────────────────────────┼──────── Funds sent ───────│
```

- Fast, gas-efficient (batched)
- Full privacy preserved

### Level 2: Direct Withdrawal (Relayer Down)

```
 User                       Midnight                 Pool Contract
  │                            │                           │
  │─── Request withdrawal ────►│                           │
  │   (direct to Midnight)     │                           │
  │                            │──── Generate ZK proof ───►│
  │                            │   (signed by validators)  │
  │                            │                           │
  │                            │    Pool verifies proof,   │
  │                            │      releases funds       │
  │◄───────────────────────────┼───────────────────────────│
```

- Slower (not batched), higher gas
- Privacy preserved
- No relayer dependency

### Level 3: Emergency Withdrawal (Midnight Down)

Only needed if Midnight network itself fails. Uses last known state snapshot.

**Pool Contract (Polygon):**

```solidity
contract PoolWithRecovery {
    uint256 public lastMidnightSync;
    bytes32 public lastStateRoot;  // Merkle root of balances
    bool public emergencyModeActive;

    // Sync state from Midnight periodically
    function syncState(bytes32 stateRoot, bytes calldata proof) external {
        require(verifyMidnightStateProof(stateRoot, proof));
        lastStateRoot = stateRoot;
        lastMidnightSync = block.timestamp;
    }

    // Anyone can trigger after 30 days of no Midnight sync
    function activateEmergencyMode() external {
        require(block.timestamp > lastMidnightSync + 30 days);
        emergencyModeActive = true;
    }

    // User proves balance from last snapshot
    function emergencyWithdraw(
        bytes calldata merkleProof,
        uint256 amount,
        address recipient
    ) external {
        require(emergencyModeActive);
        require(verifyMerkleProof(merkleProof, lastStateRoot, amount));

        IERC20(usdc).transfer(recipient, amount);
    }
}
```

**Recovery Flow:**

1. Midnight hasn't synced for 30 days
2. Anyone activates emergency mode
3. User proves their balance from last snapshot (Merkle proof)
4. Pool contract releases funds

**Tradeoff**: Anonymity broken, but funds recovered. Only used in catastrophic failure.

### Summary

| Scenario      | Recovery Path       | Privacy     | Speed  |
| ------------- | ------------------- | ----------- | ------ |
| Normal        | Relayer batches     | ✓ Preserved | Fast   |
| Relayer down  | Direct via Midnight | ✓ Preserved | Slower |
| Midnight down | Emergency snapshot  | ✗ Broken    | Slow   |

---

## Trust Model

### Relayer

**Responsibilities:**

- Execute trades on Polymarket on behalf of pool
- Cannot see which user is behind each trade
- Cannot steal funds (doesn't hold keys to user balances)

**Trust Assumptions:**

- Relayer could censor trades (mitigated by slashing)
- Relayer could front-run (mitigated by encrypted orders + TEE)

**Decentralization Path:**

- Multiple relayers with threshold decryption
- No single relayer sees complete order
- K-of-N required to decrypt and execute

### Pool Wallet Keys

**Options (in order of decentralization):**

1. **Single Operator** (MVP)
   - Simple but centralized
   - Operator is trusted party

2. **MPC (Multi-Party Computation)**
   - Keys split across N parties
   - Threshold signing (e.g., 3-of-5)
   - No single party can move funds

3. **TEE (Trusted Execution Environment)**
   - Keys held in SGX/Nitro enclave
   - Protocol logic enforced by hardware
   - Verifiable attestation

4. **Smart Contract + Committee**
   - Pool is a multisig (Safe)
   - Rotating committee of stakers
   - On-chain governance for key operations

---

## Privacy Guarantees

### What's Private

| Data              | Visible To                      |
| ----------------- | ------------------------------- |
| User identity     | Only user                       |
| User balances     | Only user                       |
| Individual trades | Only user + relayer (encrypted) |
| Position sizes    | Only user                       |

### What's Public

| Data                            | Visible To |
| ------------------------------- | ---------- |
| Pool wallet address             | Everyone   |
| Pool's total holdings           | Everyone   |
| Aggregate trade volume          | Everyone   |
| Pool ←→ Polymarket transactions | Everyone   |

### Anonymity Set

The pool wallet IS the anonymity set. All users appear as one entity on Polygon.

```
Observer sees: "Pool wallet bought 10,000 KC tokens"
Observer doesn't know: Which of 1,000 users requested it
```

---

## Fee Structure

| Fee Type       | Amount   | Purpose                          |
| -------------- | -------- | -------------------------------- |
| Trading fee    | 0.1-0.5% | Protocol revenue                 |
| Polymarket fee | ~0.5%    | Passed through                   |
| Gas costs      | Variable | Batched to reduce per-user cost  |
| Withdrawal fee | Flat     | Cover gas for batched withdrawal |

---

## Risks & Mitigations

### Pool Wallet Hack

**Risk**: Pool is a honeypot holding all user funds.
**Mitigation**:

- MPC/multisig key management
- Rate-limited withdrawals
- Insurance fund
- Split across multiple pool wallets

### Relayer Censorship

**Risk**: Relayer refuses to execute certain trades.
**Mitigation**:

- Slashing for provable censorship
- Multiple competing relayers
- Fallback: direct execution (breaks anonymity)

### Midnight Consensus Failure

**Risk**: Midnight network goes down.
**Mitigation**:

- State snapshots to decentralized storage
- Emergency recovery via Polygon contract
- Dual-proof system (can prove balance from either)

### Front-Running

**Risk**: Relayer or MEV bots front-run large trades.
**Mitigation**:

- Encrypted order submission
- TEE-based order decryption
- Private mempool integration

---

## MVP Scope

### Phase 1: Core Functionality

- [ ] Midnight contract for private ledger
- [ ] Pool wallet on Polygon (single operator)
- [ ] Relayer service (centralized)
- [ ] Deposit/withdraw flows
- [ ] Binary market trading (YES/NO)
- [ ] Basic UI

### Phase 2: Enhanced Features

- [ ] Multi-outcome markets
- [ ] Internal order matching
- [ ] Limit orders
- [ ] Multiple relayers

### Phase 3: Decentralization

- [ ] MPC key management for pool
- [ ] Decentralized relayer network
- [ ] Emergency recovery contract
- [ ] On-chain governance

---

## Technical Stack

| Component      | Technology                        |
| -------------- | --------------------------------- |
| Private ledger | Midnight (Compact contracts)      |
| Pool wallet    | Polygon (Safe multisig)           |
| Relayer        | Node.js/Rust service              |
| Bridge         | Custom Midnight ←→ Polygon bridge |
| Frontend       | React/SolidJS                     |
| Proofs         | ZK proofs via Midnight            |

---

## Open Questions

1. **Bridge Security**: How to securely bridge assets between Midnight and Polygon?

2. **MEV Protection**: How to prevent MEV extraction on Polygon side?

3. **Compliance**: How to handle regulatory requirements (KYC for large amounts)?

4. **Market Making**: Should the pool provide liquidity or purely pass-through?

5. **Governance**: How are protocol upgrades decided?

---

## Comparison to Alternatives

| Feature         | Direct Polymarket | Tornado + Trading | Private Polymarket  |
| --------------- | ----------------- | ----------------- | ------------------- |
| Privacy         | None              | Funding only      | Full                |
| Self-custody    | Yes               | Yes               | Yes                 |
| Real-time       | Yes               | Yes               | Yes (~2-5s latency) |
| Gas efficiency  | High              | Low               | Medium (batched)    |
| Regulatory risk | Low               | High              | Medium              |
| Complexity      | Low               | Medium            | High                |
