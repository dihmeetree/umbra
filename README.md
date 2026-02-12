# Spectra

A post-quantum private cryptocurrency with DAG-BFT consensus, written in Rust.

Spectra is designed from the ground up to be **anonymous**, **unlinkable**, **untraceable**, **quantum-resistant**, and **instantly final** — with no trusted setup required.

## Key Features

### Full Zero-Knowledge Privacy

- **Stealth addresses** — each transaction output uses a unique one-time address derived via Kyber KEM, making recipients unlinkable across transactions
- **Nullifier-based spending** — inputs reveal a deterministic nullifier derived from secret key material, preventing double-spends without revealing the spender's identity. Input commitments are never published — only a one-way `proof_link` is revealed, preventing graph analysis between inputs and outputs
- **Confidential amounts** — all values are hidden behind Rescue Prime commitments; validators verify correctness via zk-STARK proofs without learning any amounts
- **zk-STARK proofs** — balance and spend validity are proven in zero knowledge with no trusted setup and post-quantum security
- **Encrypted messaging** — arbitrary messages (up to 1 MiB) can be attached to transactions (max 16 per tx), encrypted so only the recipient can read them. All metadata including routing tags is inside the ciphertext — no plaintext metadata is exposed on-chain

### Quantum Resistance

All cryptographic primitives are post-quantum secure:

| Primitive | Algorithm | Security |
|-----------|-----------|----------|
| Signatures | CRYSTALS-Dilithium5 | NIST Level 5 (~256-bit classical) |
| Key encapsulation | CRYSTALS-Kyber1024 | NIST Level 5 |
| Commitments & Merkle tree | Rescue Prime (Rp64_256) | STARK-friendly, post-quantum |
| General hashing | BLAKE3 | 256-bit (128-bit quantum via Grover) |
| Zero-knowledge proofs | zk-STARKs (winterfell) | ~127-bit conjectured security |

No trusted setup is required. All proofs are transparent.

### Consensus: Proof of Verifiable Participation (PoVP)

A novel consensus mechanism that is **neither Proof of Work nor Proof of Stake**:

1. **Equal participation** — validators post an identical constant bond. Consensus power is *not* proportional to wealth. The bond exists solely for Sybil resistance.
2. **VRF committee selection** — each epoch, a committee of 21 validators is selected uniformly at random via a Verifiable Random Function. Selection is unbiased and unpredictable.
3. **DAG structure** — the ledger is a Directed Acyclic Graph, not a linear chain. Multiple vertices can be produced in parallel, enabling high throughput.
4. **Instant finality** — the committee runs asynchronous BFT. Once 2/3+1 members certify a vertex, it is irreversibly final. No probabilistic finality, no confirmation delays.

```
Epoch N:
  1. epoch_seed = H(previous_epoch_final_state)
  2. Each validator evaluates VRF(key, epoch_seed)
  3. Validators below threshold join the committee
  4. Committee members propose vertices containing transactions
  5. Vertices reference 1..8 parent vertices (forming the DAG)
  6. Committee runs BFT: 2/3+1 votes = instant finality
  7. After 1000 vertices, rotate to epoch N+1
```

**Why not PoW?** No energy waste. No mining hardware arms race. Instant finality instead of probabilistic.

**Why not PoS?** No wealth-proportional power. No "rich get richer" dynamics. All validators are equal. Selection is purely random, not stake-weighted.

## Project Structure

```
spectra/
  src/
    lib.rs                  Protocol constants, hashing utilities
    crypto/
      keys.rs               Dilithium5 signing + Kyber1024 KEM keypairs
      stealth.rs            Stealth address generation and detection
      commitment.rs         Rescue Prime commitments with field element conversions
      nullifier.rs          Nullifier derivation and double-spend tracking
      proof.rs              Merkle tree (Rescue Prime), depth-20 padding, canonical roots
      encryption.rs         Kyber KEM + BLAKE3 authenticated encryption
      vrf.rs                Verifiable Random Function for committee selection
      stark/
        mod.rs              STARK module root, proof options, type aliases
        convert.rs          Goldilocks field element conversion utilities
        rescue.rs           Rescue Prime round function, MDS/ARK constants
        types.rs            BalanceStarkProof, SpendStarkProof, witness types
        balance_air.rs      AIR for balance proofs (commitment openings + sum + range proofs)
        balance_prover.rs   Prover for balance STARK proofs
        spend_air.rs        AIR for spend proofs (nullifier + Merkle membership + proof_link)
        spend_prover.rs     Prover for spend STARK proofs
        verify.rs           STARK verification wrappers
    transaction/
      mod.rs                Transaction, TxInput, TxOutput types and validation
      builder.rs            TransactionBuilder API for constructing transactions
    consensus/
      mod.rs                PoVP design documentation
      dag.rs                DAG data structure (vertices, tips, ancestors)
      bft.rs                BFT voting, certification, committee selection
    state.rs                Chain state, Ledger: Merkle tree, nullifier set, DAG coordination
    network.rs              P2P protocol message types and serialization
    wallet.rs               Key management, output scanning, tx building
    main.rs                 End-to-end demo
```

**~7,500 lines of Rust** across 27 source files with **87 tests**.

## Building

Requires a C compiler (for the PQClean backends used by `pqcrypto-dilithium` and `pqcrypto-kyber`).

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

All 87 tests cover:

- Post-quantum key generation, signing, and KEM roundtrips
- Stealth address generation and detection (correct and wrong recipient)
- Rescue Prime commitments and field element conversions
- Nullifier determinism and double-spend detection
- Merkle tree construction, path verification, and depth-20 canonical padding
- Encrypted message roundtrips, authentication, and tamper detection
- VRF evaluation, verification, and committee selection statistics
- DAG insertion, diamond merges, finalized ordering
- BFT vote collection, leader rotation, duplicate rejection, cross-epoch replay prevention
- Network message serialization roundtrips, oversized message rejection
- Proof_link derivation and domain separation
- zk-STARK proof generation and verification (balance and spend roundtrips)
- Range proof enforcement: values >= 2^59 rejected, boundary value accepted
- Proof transplant rejection: tampered tx_content_hash fails verification
- Public input deserialization: allocation bounds, truncation, roundtrips
- Transaction building with STARK proof generation
- Wallet scanning, balance tracking, spending with change
- End-to-end: fund, transfer, message decrypt, bystander non-detection

## Demo

```bash
cargo run --release
```

Runs an end-to-end demonstration:

1. Generates post-quantum keypairs for Alice and Bob
2. Funds Alice via a simulated coinbase transaction (with zk-STARK proofs)
3. Alice sends 25,000 units to Bob with an encrypted message
4. Bob scans and decrypts his payment and message
5. Eve (bystander) scans the same transaction and finds nothing
6. Creates 30 validators, selects a committee via VRF
7. Builds a DAG with parallel vertices and diamond merges
8. Applies transactions to chain state with Merkle tree tracking

## Transaction Model

Spectra uses a UTXO model with full zero-knowledge privacy:

```
Transaction {
    inputs:        [Nullifier + ProofLink + SpendStarkProof]
    outputs:       [Commitment + StealthAddress + EncryptedNote]
    fee:           u64 (public)
    chain_id:      Hash (replay protection across networks)
    expiry_epoch:  u64 (transaction expiration)
    balance_proof: BalanceStarkProof
    messages:      [EncryptedPayload]  (optional)
    tx_binding:    Hash (binds all fields together)
}
```

- **Inputs** reveal a nullifier, a proof_link, and a zk-STARK spend proof. The proof demonstrates in zero knowledge that: (1) the nullifier is correctly derived from a secret spend key and a committed output, (2) that committed output exists in the global Merkle tree, and (3) the proof_link is correctly derived from the commitment and a random nonce. The actual commitment is never revealed — only the one-way proof_link is public, preventing graph analysis between inputs and outputs. No amounts or keys are revealed.
- **Outputs** contain a Rescue Prime commitment to the amount, a stealth address for the recipient, and the note data (amount + blinding factor) encrypted to the recipient's Kyber key.
- **Balance proof** is a zk-STARK proving that all input and output commitments open correctly and that sum(inputs) = sum(outputs) + fee. The proof is bound to the `tx_content_hash` to prevent proof transplant attacks. No values are revealed.
- **Replay protection** — each transaction includes a `chain_id` (network identifier) and `expiry_epoch` (after which the tx is invalid), preventing cross-chain and stale-transaction replay.
- **tx_binding** — the hash of all transaction content, included in proof challenges. Any modification to inputs, outputs, fee, chain_id, or expiry_epoch invalidates the balance proof.
- **Messages** are Kyber-encrypted payloads (with 24-byte nonce + BLAKE3 MAC) that only the recipient can decrypt.

## Zero-Knowledge Proof System

Spectra uses **zk-STARKs** (via the [winterfell](https://github.com/facebook/winterfell) library) for all transaction validity proofs:

### Dual Hash Design

- **Rescue Prime** (`Rp64_256` over the Goldilocks field) — used for all values proven inside STARK circuits: commitments, nullifiers, Merkle tree nodes
- **BLAKE3** — used for non-proven operations: vertex IDs, transaction IDs, state roots, VRF, network hashing

### Balance Proof (1 per transaction)

Proves in zero knowledge:
1. Each input/output commitment opens correctly under Rescue Prime
2. Sum of input values = sum of output values + fee
3. All values are in [0, 2^59) — prevents inflation via field-arithmetic wraparound
4. Proof is bound to the transaction's content hash

### Spend Proof (1 per input)

Proves in zero knowledge:
1. The nullifier is correctly derived: `Rescue(spend_auth, commitment) == nullifier`
2. The commitment exists as a leaf in the depth-20 Merkle tree with the given root
3. The proof_link is correctly derived: `Rescue(commitment, link_nonce) == proof_link`

### Proof Characteristics

| Property | Value |
|----------|-------|
| Trusted setup | None (transparent) |
| Post-quantum | Yes (hash-based) |
| Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| Hash in circuit | Rescue Prime (Rp64_256) |
| Security | ~127-bit conjectured (Goldilocks quadratic extension max) |
| Range proof | 59-bit via bit decomposition (integrated in balance AIR) |
| Balance proof size | ~40 KB |
| Spend proof size | ~33 KB |

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `COMMITTEE_SIZE` | 21 | BFT committee members per epoch |
| `MIN_COMMITTEE_SIZE` | 4 | Minimum committee for BFT safety |
| `BFT_QUORUM` | dynamic | `(committee_size * 2) / 3 + 1` votes for finality |
| `EPOCH_LENGTH` | 1,000 | Vertices per epoch before rotation |
| `MAX_PARENTS` | 8 | Max parent references per DAG vertex |
| `MAX_TXS_PER_VERTEX` | 10,000 | Max transactions per vertex |
| `VERTEX_INTERVAL_MS` | 500 | Target interval between vertices |
| `MAX_MESSAGES_PER_TX` | 16 | Max messages per transaction |
| `MAX_MESSAGE_SIZE` | 64 KiB | Max encrypted message per transaction |
| `MAX_ENCRYPT_PLAINTEXT` | 1 MiB | Max plaintext for Kyber encryption |
| `MAX_NETWORK_MESSAGE_BYTES` | 16 MiB | Max serialized network message |
| `VALIDATOR_BOND` | 1,000,000 | Constant bond for validator registration |
| `MERKLE_DEPTH` | 20 | Canonical commitment tree depth (~1M outputs) |
| `RANGE_BITS` | 59 | Bit width for value range proofs |
| `MAX_TX_IO` | 16 | Max inputs or outputs per transaction (range-proof safe) |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `pqcrypto-dilithium` | CRYSTALS-Dilithium5 post-quantum signatures |
| `pqcrypto-kyber` | CRYSTALS-Kyber1024 post-quantum key encapsulation |
| `pqcrypto-traits` | Trait definitions for PQ crypto types |
| `blake3` | Fast, quantum-secure hashing |
| `winterfell` | zk-STARK prover/verifier (Rescue Prime, Goldilocks field) |
| `zeroize` | Secure memory clearing for secret key material |
| `serde` + `bincode` | Serialization |
| `rand` | Cryptographic randomness |
| `hex` | Hex encoding for display |
| `thiserror` | Error type derivation |

## Security Model

### Zero-Knowledge Proofs

All transaction validity is verified via zk-STARKs:

- **Full zero knowledge** — validators verify correctness without learning any secret values (amounts, keys, output identities)
- **Sound** — a forged proof cannot pass verification without breaking the underlying hash function
- **Transparent** — no trusted setup required, all proofs are publicly verifiable
- **Post-quantum** — STARK security is hash-based, not reliant on discrete log or factoring

### Security Hardening

- **Vertex signature verification** — every DAG vertex must carry a valid Dilithium5 signature from its proposer; unsigned vertices are rejected at insertion time
- **Full transaction validation on apply** — `apply_transaction()` calls `validate_structure()` before any state mutation, verifying all zk-STARK proofs (balance + spend) and structural integrity
- **VRF anti-grinding** — VRF outputs include a `proof_commitment` (hash of the proof) enabling a commit-reveal scheme that prevents validators from grinding on epoch seeds
- **Plaintext size limits** — `encrypt_with_shared_secret` rejects plaintexts exceeding `MAX_ENCRYPT_PLAINTEXT`, preventing memory exhaustion attacks
- **Secure memory clearing** — all secret key material (`SigningSecretKey`, `KemSecretKey`, `SharedSecret`, `BlindingFactor`, `StealthSpendInfo`) is zeroized on drop via the `zeroize` crate
- **Vote round validation** — BFT `receive_vote()` rejects votes for rounds other than the current round, preventing future-round injection attacks
- **Chain-bound vote signatures** — vote signatures include `chain_id`, preventing cross-chain vote replay attacks
- **Transaction expiry enforcement** — `validate_structure()` enforces `expiry_epoch`, rejecting stale transactions
- **127-bit STARK security** — proof verification requires at least 127-bit conjectured security (maximum for Goldilocks quadratic extension), up from the original 95-bit threshold
- **BLAKE3 keyed MAC** — authenticated encryption uses `blake3::Hasher::new_keyed()` (proper keyed mode) rather than feeding key material as data
- **No plaintext metadata** — `TxMessage` contains only the encrypted payload; all routing tags and metadata are inside the ciphertext, preventing traffic analysis
- **Message count limits** — transactions are limited to 16 messages (`MAX_MESSAGES_PER_TX`), enforced during validation
- **KEM reuse for note encryption** — stealth address KEM shared secret is reused for encrypting note data, avoiding a redundant second KEM encapsulation per output
- **Domain-separated address IDs** — `address_id()` uses `hash_domain` for proper domain separation
- **Constant-time comparison** — all cryptographic verification (nullifiers, MACs, proof challenges, VRF outputs, tx bindings, stealth address detection) uses constant-time equality checks to prevent timing side-channel attacks
- **Length-prefixed hashing** — `hash_concat` encodes the length of each input before hashing, preventing domain confusion from concatenation ambiguity
- **Proof-link-bound proofs** — spend and balance proofs both derive the same proof_link from the commitment, preventing proof mix-and-match attacks while keeping the commitment private
- **Proof transplant prevention** — balance proofs include `tx_content_hash` in their public inputs, preventing a valid proof from being reused in a different transaction
- **Epoch-bound votes** — BFT vote signatures include the epoch number, preventing cross-epoch replay attacks
- **Round monotonicity** — DAG vertices must have a strictly higher round number than all parents, preventing causal ordering violations
- **Minimum committee size** — committee selection falls back to all active validators if VRF selects fewer than `MIN_COMMITTEE_SIZE`, guaranteeing BFT safety
- **Canonical Merkle depth** — commitment tree is always padded to depth 20 with precomputed zero-subtree hashes, ensuring consistent STARK circuit verification regardless of tree size
- **Range proofs** — all committed values are proven to be in [0, 2^59) via bit decomposition within the balance AIR; with MAX_IO = 16 per side, the maximum sum is 16 * 2^59 = 2^63 < p (Goldilocks), preventing inflation via field-arithmetic wraparound
- **Network message limits** — serialized messages are rejected above `MAX_NETWORK_MESSAGE_BYTES`; bincode deserialization uses size-limited options to prevent allocation-based DoS from crafted internal length fields
- **Key size validation** — public keys are validated on deserialization, preventing malformed key injection
- **Deserialization bounds** — public input deserialization rejects unreasonable counts (> 256 inputs/outputs) to prevent allocation DoS
- **Overflow protection** — all arithmetic uses `checked_add` to prevent overflow; fee accumulation overflow is an explicit error
- **Transaction I/O limits** — inputs and outputs are capped at `MAX_TX_IO` (16), ensuring range proof sums stay within the Goldilocks field (16 * 2^59 < p) and preventing inflation via field-arithmetic wraparound
- **Complete content hash binding** — `tx_content_hash` covers all encrypted payload fields including MACs and KEM ciphertexts, preventing undetected tampering of encrypted notes or messages
- **Domain-separated hashing** — all critical hashes (`tx_id`, `vertex_id`, stealth key derivation, content hash) use BLAKE3 `new_derive_key` for proper cryptographic domain separation
- **Chain ID enforcement** — `apply_transaction()` explicitly checks `chain_id` against the chain state, providing defense-in-depth beyond the implicit binding via balance proofs

## Production Roadmap

This is a working prototype demonstrating the full architecture. A production deployment would additionally require:

- **Persistent storage** — on-disk commitment tree and nullifier set (e.g., RocksDB-backed Merkle tree)
- **P2P networking** — libp2p transport with Noise protocol (Kyber upgrade path for post-quantum handshakes)
- **Mempool management** — transaction prioritization, conflict resolution, fee market
- **Formal security audit** — cryptographic protocol review and implementation audit

## License

MIT
