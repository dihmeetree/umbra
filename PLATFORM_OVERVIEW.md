# TLSNotary Oracle Platform for Midnight Contracts

## Overview

A **cryptographically verifiable oracle platform** built on TLSNotary that enables Midnight smart contracts to trustlessly consume real-world data from public APIs. Instead of blind trust, users get mathematical proof that data originates from legitimate sources like CoinGecko, CoinPaprika, or any HTTPS API.

## The Platform

An oracle infrastructure that bridges external data sources to Midnight's privacy-preserving smart contracts through:

- **TLSNotary Protocol**: Cryptographic proof of TLS sessions with public APIs
- **Multi-Notary Consensus**: Independent verification from distributed notary providers
- **BLS12-381 Schnorr Signatures**: Compact-compatible signatures for on-chain verification
- **Merkle Proofs**: Selective disclosure of session data while maintaining privacy
- **Verifiable Attestations**: Complete audit trail from API response to contract execution

## Real-World Use Case: Privacy-Preserving Prediction Markets

### The Scenario

A user builds a betting contract on Midnight where:

- Users deposit **NIGHT** (privacy tokens) to place bets
- Predictions are on public market data (e.g., "Will ADA exceed $1.50 by Friday?")
- Winners are determined by real-world price data
- All bet amounts and user positions remain **private** (Midnight's zero-knowledge properties)
- Only the settlement outcome is revealed

### The Dual Challenge

**Challenge 1: The Oracle Problem**

- Smart contracts are isolated - they cannot fetch external data
- The contract needs ADA's price from CoinGecko to settle bets
- Traditional oracles require trusting a centralized operator

**Challenge 2: The Privacy Paradox**

- Midnight contracts preserve user privacy through zero-knowledge proofs
- But settlement requires transparent, verifiable price data
- How do you maintain privacy while ensuring settlement data is trustworthy?

## The Solution: TLSNotary Verified Oracles

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Trusted Public API Source                    │
│              (CoinGecko, CoinPaprika, etc.)                 │
└─────────────────────────────────────────────────────────────┘
                        ↓ HTTPS/TLS
┌─────────────────────────────────────────────────────────────┐
│                   TLSNotary Prover                          │
│  • Establishes MPC-TLS connection with notary witness       │
│  • Fetches price data through cryptographically proven      │
│    connection to api.coingecko.com                          │
│  • Generates attestation with exact HTTP response           │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Multi-Notary Verification Layer                │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│    │  Notary 1    │  │  Notary 2    │  │  Notary 3    │     │
│    │  • Verifies  │  │  • Verifies  │  │  • Verifies  │     │
│    │    TLS proof │  │    TLS proof │  │    TLS proof │     │
│    │  • Signs with│  │  • Signs with│  │  • Signs with│     │
│    │    BLS key   │  │    BLS key   │  │    BLS key   │     │
│    └──────────────┘  └──────────────┘  └──────────────┘     │
│           ✓                  ✓                 ✓            │
│        Requires 2-of-3 notary consensus for validity        │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│                  Attestation Package                        │
│  • Oracle data (price, timestamp, source)                   │
│  • TLSNotary attestation (proves API connection)            │
│  • Multi-notary Schnorr signatures (2-of-3 consensus)       │
│  • Merkle proof (links data to verified session)            │
└─────────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Midnight Smart Contract (Compact)              │
│  • Verifies Schnorr signatures from whitelisted notaries    │
│  • Validates Merkle proof                                   │
│  • Checks timestamp freshness                               │
│  • Settles bets based on verified price data                │
│  • Maintains user privacy through ZK proofs                 │
└─────────────────────────────────────────────────────────────┘
```

### How It Solves Both Challenges

#### 1. **Trustless Data Verification**

**Traditional Oracle (Trust-based):**

```
❌ Platform: "ADA is $1.48, trust me"
❌ User: "How do I know you're not lying?"
❌ Platform: "You just have to trust us"
```

**TLSNotary Oracle (Proof-based):**

```
✅ Platform: "Here's cryptographic proof:"
   • TLS session with api.coingecko.com (proven by notary)
   • HTTP response: {"cardano":{"usd":1.48}}
   • Timestamp: 2025-01-15 14:00:05 UTC
   • 3 independent notaries verified and signed
   • Merkle proof linking price to session

✅ User: "I can verify all of this myself - math doesn't lie"
```

**What users can verify:**

- ✓ Connection was to the claimed API endpoint (DNS name in attestation)
- ✓ Exact HTTP response body from the API
- ✓ When the data was fetched (cryptographically bound timestamp)
- ✓ Multiple independent notaries confirmed the session
- ✓ Price extraction logic is deterministic and transparent

#### 2. **Privacy + Transparency**

The oracle provides **selective transparency**:

```
Private (Zero-Knowledge):
• Who placed bets → Hidden
• Bet amounts → Hidden
• User positions → Hidden
• User identities → Hidden

Public (Verifiable):
• Settlement price → Verified by TLSNotary
• Price source → api.coingecko.com (proven)
• Settlement timestamp → Notary-signed
• Final outcome → Transparent
```

This preserves Midnight's privacy guarantees while ensuring settlement fairness.

### Complete User Flow

**Phase 1: Bet Creation**

```typescript
// User Alice (identity private)
circuit.placeBet({
  prediction: "ADA > $1.50",
  settlement_time: "2025-01-15 14:00 UTC",
  stake: 100 NIGHT  // Amount hidden in ZK proof
});
```

**Phase 2: Oracle Fetches Data (Settlement Time)**

```rust
// Oracle service (you or third-party)
let prover = OracleProver::new(notary_configs, threshold: 2);

// Fetch via TLSNotary
let package = prover.fetch_and_prove(
  &ApiEndpoint::coingecko(),
  timestamp: settlement_time
).await?;

// Result:
AttestationPackage {
  oracle_data: {
    price: 1_480_000,  // $1.48
    timestamp: 1736949605,
    source: "api.coingecko.com/..."
  },
  tlsn_attestation: { /* MPC-TLS proof */ },
  signatures: [
    { pk: NOTARY_1_PK, sig: sig1 },  ✓
    { pk: NOTARY_2_PK, sig: sig2 },  ✓
    { pk: NOTARY_3_PK, sig: sig3 }   ✓
  ],
  merkle_proof: { /* Session data commitment */ }
}
```

**Phase 3: Contract Settlement**

```typescript
circuit.settleBets(attestation_package) {
  // 1. Verify cryptographic proofs
  assert(verify_multi_sig(package.signatures, threshold: 2));
  assert(verify_merkle_proof(package.oracle_data, package.merkle_proof));
  assert(verify_timestamp_freshness(package.timestamp));

  // 2. Extract verified price
  let settlement_price = package.oracle_data.price; // $1.48

  // 3. Settle bets (ZK proofs maintain privacy)
  for bet in active_bets {
    if (settlement_price > bet.target_price) {
      // Alice predicted correctly (her identity still hidden)
      payout(bet.user, bet.stake * payout_multiplier);
    } else {
      // Bet lost (stake distributed to winners)
      distribute_to_pool(bet.stake);
    }
  }
}
```

**Phase 4: User Verification**

```
Any user can verify the settlement was fair:

✓ Check notary signatures (2-of-3 consensus)
✓ Verify TLSNotary attestation proves connection to CoinGecko
✓ Inspect HTTP response body: {"cardano":{"usd":1.48}}
✓ Confirm timestamp matches settlement window
✓ Validate Merkle proof links price to verified session

Result: Mathematical certainty the price was real and fair
```

## Platform Features

### **For Contract Developers**

**Simple Integration:**

```typescript
import { OracleVerifier } from '@your-platform/oracle-midnight';

circuit BettingContract {
  @public
  fn settleBet(attestation: AttestationPackage) {
    // One-line verification
    let price = OracleVerifier.verify_and_extract(attestation);

    // Use verified price for settlement
    settle_based_on_price(price);
  }
}
```

**Supported Data Sources:**

- Cryptocurrency prices (CoinGecko, CoinPaprika, CoinCap)
- Stock prices (Alpha Vantage, Yahoo Finance)
- Weather data (OpenWeatherMap)
- Sports scores (ESPN API)
- Any HTTPS JSON API

### **For End Users**

**Complete Transparency:**

- View attestation packages for any settlement
- Independently verify TLSNotary proofs
- Check which notaries signed off
- Audit the exact API response used
- Verify timestamp authenticity

**Privacy Preservation:**

- Your bet amounts remain hidden (ZK proofs)
- Your positions are private
- Only you know your strategy
- Settlement is fair without revealing your data

### **For Platform Operators**

**Automated & Trustless:**

- No manual price updates required
- Cryptographic proof prevents disputes
- Multi-notary consensus ensures reliability
- Audit trail for regulatory compliance
- Fallback mechanisms if notaries are down

**Decentralized Trust:**

- Not dependent on single oracle provider
- Multiple independent notary operators
- Community can verify notary behavior
- Governance over notary whitelist

## Security Guarantees

### **Attack Resistance**

**Scenario: Malicious operator tries fake price**

```
Operator submits: price = $2.00 (real was $1.48)

❌ TLSNotary attestation shows CoinGecko returned $1.48
❌ Merkle proof doesn't match fake data
❌ Notaries refuse to sign (data mismatch)
❌ Contract rejects (insufficient signatures)

Result: Attack fails - users are protected
```

**Scenario: Single notary compromised**

```
1 of 3 notaries is malicious and signs fake data

❌ Requires 2-of-3 threshold
❌ Honest notaries (2) refuse to sign fake data
❌ Only 1 valid signature obtained
❌ Contract rejects (threshold not met)

Result: Attack fails - consensus prevents fraud
```

### **Mathematical Guarantees**

- **Data Authenticity**: TLSNotary proves connection to claimed API (can't fake without breaking TLS)
- **Consensus**: Multiple notaries must independently verify (prevents single point of failure)
- **Binding**: Merkle proofs cryptographically link data to verified session (can't cherry-pick data)
- **Freshness**: Timestamps are notary-signed (can't replay old data)
- **Privacy**: ZK proofs hide user data while settlement data remains verifiable

## Why This Matters

### **Enables New Use Cases**

1. **Privacy-Preserving DeFi**
   - Private positions, public settlements
   - Prediction markets without revealing strategies
   - Betting platforms with hidden stake amounts

2. **Trustless Gaming**
   - Provably fair outcomes based on real-world events
   - No trust required in game operators
   - Transparent settlement logic

3. **Verifiable Automation**
   - Smart contracts that react to real-world data
   - Insurance products triggered by verified events
   - Automated trading based on proven price feeds

### **The Paradigm Shift**

**Before:** "Trust the platform operator to be honest about external data"

**After:** "Verify cryptographic proofs - trust math, not humans"

This transforms oracles from **trusted intermediaries** into **verifiable infrastructure**, unlocking the full potential of smart contracts that need real-world data while maintaining privacy and trustlessness.

---

## Platform Vision

Build a **decentralized oracle network** where:

- Anyone can run a notary node
- Contracts choose their trust model (which notaries, what threshold)
- Users can verify every data point
- Privacy and transparency coexist
- Smart contracts finally bridge to the real world without compromising on trustlessness

The result: **Truly decentralized applications** that combine Midnight's privacy guarantees with cryptographically proven real-world data.
