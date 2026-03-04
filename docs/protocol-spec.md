# Umbra Protocol Specification

Version: 0.1.0-draft
Status: Living document
Last updated: 2026-03-03

---

## Table of Contents

1. [Overview](#1-overview)
2. [Notation and Terminology](#2-notation-and-terminology)
3. [Protocol Constants](#3-protocol-constants)
4. [Data Structures](#4-data-structures)
   - 4.1 [Hash](#41-hash)
   - 4.2 [Keys](#42-keys)
   - 4.3 [Transaction](#43-transaction)
   - 4.4 [DAG Vertex](#44-dag-vertex)
   - 4.5 [BFT Messages](#45-bft-messages)
5. [Transaction Lifecycle](#5-transaction-lifecycle)
   - 5.1 [Construction](#51-construction)
   - 5.2 [Validation](#52-validation)
   - 5.3 [Mempool](#53-mempool)
   - 5.4 [Inclusion](#54-inclusion)
   - 5.5 [Finality](#55-finality)
6. [DAG-BFT Consensus Protocol](#6-dag-bft-consensus-protocol)
   - 6.1 [Epochs and Committee Selection](#61-epochs-and-committee-selection)
   - 6.2 [Vertex Proposal](#62-vertex-proposal)
   - 6.3 [Voting and Certification](#63-voting-and-certification)
   - 6.4 [Equivocation and Slashing](#64-equivocation-and-slashing)
   - 6.5 [Epoch Rotation](#65-epoch-rotation)
7. [State Transitions](#7-state-transitions)
   - 7.1 [Transfer](#71-transfer)
   - 7.2 [Validator Registration](#72-validator-registration)
   - 7.3 [Validator Deregistration](#73-validator-deregistration)
   - 7.4 [Coinbase](#74-coinbase)
8. [Network Protocol](#8-network-protocol)
   - 8.1 [P2P Handshake](#81-p2p-handshake)
   - 8.2 [Message Types](#82-message-types)
   - 8.3 [Gossip and Deduplication](#83-gossip-and-deduplication)
   - 8.4 [Dandelion++ Transaction Routing](#84-dandelion-transaction-routing)
9. [Serialization](#9-serialization)
10. [RPC API](#10-rpc-api)

---

## 1. Overview

Umbra is a post-quantum private cryptocurrency with DAG-BFT consensus. It provides:

- **Full transaction privacy**: amounts, sender, and receiver are hidden.
- **Post-quantum security**: all cryptographic primitives resist known quantum attacks.
- **Instant deterministic finality**: a certified vertex cannot be reverted.
- **No trusted setup**: proofs are transparent zk-STARKs.
- **Sybil-resistant validator set**: bonding curve scales superlinearly with validator count.

The protocol has two distinct participant roles:

| Role | Description |
|---|---|
| **Validator** | Posts a bond, participates in committee selection, proposes/votes on vertices |
| **User** | Creates and broadcasts transactions; scans outputs to detect received funds |

Full nodes maintain the full DAG and state. Light clients receive Merkle proofs over committed state roots.

---

## 2. Notation and Terminology

| Symbol | Meaning |
|---|---|
| `H(x)` | BLAKE3 hash of byte string `x`, producing 32 bytes |
| `H_d(domain, x)` | Domain-separated BLAKE3 via `new_derive_key(domain)`: `domain` is the key derivation context; `x` is the sole input; no manual length prefix |
| `H_concat(x1, x2, ...)` | Multi-part BLAKE3 with length-prefixed inputs |
| `RP(x)` | Rescue Prime hash over the Goldilocks field (Rp64_256) |
| `Sign(sk, m)` | Hybrid signature: Dilithium5(sk_d, m) AND SPHINCS+(sk_s, m) |
| `Verify(pk, m, sig)` | True iff both Dilithium5 and SPHINCS+ signatures verify |
| `KEM.Enc(pk)` | Kyber1024 encapsulation: returns (shared_secret, ciphertext) |
| `KEM.Dec(sk, ct)` | Kyber1024 decapsulation: returns shared_secret |
| `AEAD.Enc(k, n, m)` | ChaCha20-Poly1305 authenticated encryption |
| `AEAD.Dec(k, n, c)` | ChaCha20-Poly1305 authenticated decryption |
| `\|\|` | Byte concatenation |
| `[n]` | Integer encoded as 4-byte little-endian unless noted |
| `f` | Maximum Byzantine faults tolerated: `f = floor((K-1)/3)` |
| `K` | BFT committee size (21) |
| `q` | BFT quorum: `q = floor(2K/3) + 1 = 15` |

---

## 3. Protocol Constants

These constants are defined in `src/lib.rs::constants` and are protocol-level — changing them produces an incompatible network.

| Constant | Value | Description |
|---|---|---|
| `COMMITTEE_SIZE` | 21 | BFT committee members per epoch |
| `MIN_COMMITTEE_SIZE` | 7 | Minimum committee size (f=2, q=5) |
| `MAX_VALIDATORS` | 10,000 | Maximum registered validator count |
| `MIN_VALIDATORS` | 4 | Minimum validators for BFT safety |
| `VALIDATOR_BASE_BOND` | 1,000,000 | Base bond amount (base units) |
| `BOND_SCALING_FACTOR` | 100 | Sybil resistance scaling factor |
| `SLASH_REGISTRATION_COOLDOWN_EPOCHS` | 10 | Post-slash elevated bond window |
| `SLASH_BOND_MULTIPLIER` | 3 | Bond multiplier during cooldown |
| `MAX_TXS_PER_VERTEX` | 10,000 | Maximum transactions per vertex |
| `VERTEX_INTERVAL_MS` | 500 | Target vertex production interval |
| `MAX_VERTEX_TIMESTAMP_DRIFT_SECS` | 60 | Maximum future timestamp drift |
| `BFT_QUORUM` | 15 | Fallback quorum (`floor(2*21/3)+1`) |
| `EPOCH_LENGTH` | 1,000 | Vertices per epoch before rotation |
| `COMMITTEE_ELIGIBILITY_DELAY_EPOCHS` | 2 | Epochs after registration before a validator is committee-eligible |
| `MAX_PARENTS` | 8 | Maximum parent vertex references |
| `MAX_PEERS` | 64 | Maximum simultaneous peer connections |
| `MAX_NETWORK_MESSAGE_BYTES` | 16,777,216 | Maximum deserialized message size (16 MiB) |
| `P2P_PADDING_BUCKET` | 1,024 | Frame padding granularity (bytes) |
| `DANDELION_STEM_HOPS` | 2 | Dandelion++ stem phase hops |
| `DANDELION_TIMEOUT_MS` | 5,000 | Stem phase timeout before fluffing |
| `DANDELION_STEM_DELAY_MIN_MS` | 100 | Minimum stem forward delay |
| `DANDELION_STEM_DELAY_MAX_MS` | 500 | Maximum stem forward delay |
| `PEER_MSG_RATE_LIMIT` | 100.0 | Token bucket refill rate (msgs/s) |
| `PEER_MSG_BURST` | 200.0 | Maximum burst size |

**Bonding curve**: `required_bond(n) = BASE_BOND * (1 + n / SCALING_FACTOR)`
where `n` is the current active validator count.

---

## 4. Data Structures

### 4.1 Hash

```text
Hash = [u8; 32]   // BLAKE3 output
```

All hashes are 32 bytes. Domain separation is mandatory for all protocol hashes to prevent cross-context collisions.

### 4.2 Keys

**Signing key pair** (hybrid post-quantum):
```text
SigningPublicKey  = dilithium5_pk (2592 bytes) || sphincs_pk (64 bytes)
SigningSecretKey  = dilithium5_sk || sphincs_sk   [zeroize-on-drop]
Signature        = { dilithium: Vec<u8>,          // 4627 bytes
                     sphincs:   Vec<u8> }          // 29,792 bytes
```

A signature is valid iff BOTH component signatures verify. This AND composition means breaking either scheme alone is insufficient.

**KEM key pair**:
```text
KemPublicKey  = kyber1024_pk   (1568 bytes)
KemSecretKey  = kyber1024_sk   [zeroize-on-drop]
KemCiphertext = kyber1024_ct   (1568 bytes)
```

**Validator identity**:
```text
validator_id = H_d("umbra.validator", dilithium5_pk || sphincs_pk)
```

### 4.3 Transaction

```text
Transaction = {
    id:       TxId,       // H_d("umbra.txid", serialized fields)
    tx_type:  TxType,
    inputs:   Vec<TxInput>,
    outputs:  Vec<TxOutput>,
    fee:      u64,        // in base units
    timestamp: u64,       // unix milliseconds
    chain_id: Hash,
}

TxInput = {
    nullifier:  Nullifier,       // 32 bytes
    proof_link: Hash,            // one-way binding to commitment
    spend_proof: SpendStarkProof,
}

TxOutput = {
    commitment:     Hash,        // Rescue Prime commitment to (value, blinding)
    stealth_address: StealthAddress,
    encrypted_note:  EncryptedNote,
}

StealthAddress = {
    one_time_key:   Hash,         // derived one-time recipient identifier
    kem_ciphertext: KemCiphertext, // Kyber1024 ciphertext for recipient
}

EncryptedNote = {
    kem_ciphertext: KemCiphertext,
    nonce:          [u8; 24],     // XChaCha20-Poly1305 nonce
    ciphertext:     Vec<u8>,      // plaintext = version(1) || value(8) || blinding(32)
}
```

**TxType variants**:

| Variant | Description |
|---|---|
| `Transfer` | Standard private value transfer |
| `ValidatorRegister` | Bond deposit + VRF key registration |
| `ValidatorDeregister` | Bond withdrawal |
| `Coinbase` | Block reward issuance (committee leader only) |

**Transaction content hash** (binds all malleable fields):
```text
tx_content_hash = H_d("umbra.tx_content_hash",
    chain_id (32 bytes)
    || expiry_epoch (8 bytes LE)
    || fee (8 bytes LE)
    || tx_type_byte [|| tx_type_specific_fields]
    || input_count (4 bytes LE)
    || for each input: nullifier (32) || proof_link (32)
    || output_count (4 bytes LE)
    || for each output:
        commitment (32)
        || one_time_key (32)
        || len_le32(kem_ciphertext) || kem_ciphertext
        || len_le32(note_kem_ciphertext) || note_kem_ciphertext
        || note_nonce (24)
        || len_le32(note_ciphertext) || note_ciphertext
        || blake3_binding (32)
    || message_count (4 bytes LE)
    || for each message:
        len_le32(kem_ciphertext) || kem_ciphertext
        || nonce (24)
        || len_le32(ciphertext) || ciphertext
)
```
All length prefixes are 4-byte little-endian u32. The `chain_id` and `expiry_epoch` fields
bind the hash to the specific chain and epoch window, preventing cross-chain and replay attacks.

### 4.4 DAG Vertex

```text
Vertex = {
    id:           VertexId,            // H of header fields
    parents:      Vec<VertexId>,       // 1..MAX_PARENTS
    epoch:        u64,
    round:        u64,
    proposer:     SigningPublicKey,
    transactions: Vec<Transaction>,    // 0..MAX_TXS_PER_VERTEX
    timestamp:    u64,                 // unix millis; NOT in vertex id
    state_root:   Hash,
    signature:    Signature,
    vrf_proof:    VrfProof,
    vrf_output:   VrfOutput,
    protocol_version: u32,
}

VertexId = Hash   // H of (parents, epoch, round, proposer_fingerprint, tx_root,
                  //        presence_byte || vrf_output_value?, state_root, protocol_version)
                  // timestamp is NOT hashed into the vertex id
```

A vertex timestamp is validated on receipt: nodes reject vertices timestamped more than `MAX_VERTEX_TIMESTAMP_DRIFT_SECS` (60 s) into the future.

### 4.5 BFT Messages

```text
Vote = {
    voter:      SigningPublicKey,
    vertex_id:  VertexId,
    epoch:      u64,
    round:      u64,
    vote_type:  VoteType,   // VOTE or COMMIT
    signature:  Signature,
}

// Sign data: H_d("umbra.vote", epoch || round || vertex_id || vote_type)

Certificate = {
    vertex_id: VertexId,
    epoch:     u64,
    votes:     Vec<Vote>,  // >= q distinct committee members
}

EquivocationEvidence = {
    voter_id:   Hash,
    epoch:      u64,
    round:      u64,
    vote_a:     Vote,
    vote_b:     Vote,
}
```

---

## 5. Transaction Lifecycle

### 5.1 Construction

The wallet constructs a transaction as follows:

1. **Select inputs**: choose UTXOs from the nullifier-free output set whose combined committed value covers the transfer amount plus fee.
2. **Generate stealth address**: for each output, encapsulate against the recipient's KEM public key to derive a one-time key.
3. **Commit outputs**: for each output, choose a random blinding factor `r`, compute `C = RP(value, r)`.
4. **Encrypt note**: encrypt `version(1) || value(8 LE) || r(32)` to the recipient's KEM public key using XChaCha20-Poly1305.
5. **Prove spend** (per input): generate `SpendStarkProof` attesting:
   - Nullifier correctly derived from `spend_auth` and commitment.
   - Commitment is a leaf in the global Merkle tree at the current root.
   - `proof_link` correctly derived from commitment and a random nonce.
6. **Prove balance**: generate `BalanceStarkProof` attesting:
   - All commitments open correctly.
   - `sum(inputs) == sum(outputs) + fee`.
   - All values lie in `[0, 2^59)`.
7. **Sign**: sign the transaction content hash with the spending key pair.
8. **Broadcast**: submit to a node via RPC or P2P.

### 5.2 Validation

On receipt, nodes validate:

**Structural checks** (cheap, checked first):
- Number of inputs and outputs within bounds.
- All signatures have correct component sizes.
- No nullifier appears more than once within the transaction.
- `encrypted_note.ciphertext.len() <= MAX_ENCRYPTED_NOTE_CIPHERTEXT_SIZE` (256 bytes) for all outputs.
- Fee is at least `MIN_TX_FEE`.
- Timestamp within `±MAX_VERTEX_TIMESTAMP_DRIFT_SECS` of local time.
- Chain ID matches the local chain ID.

**Cryptographic checks**:
- Signature over `tx_content_hash` verifies under the spending public key.
- Each `SpendStarkProof` verifies.
- `BalanceStarkProof` verifies.

**State checks** (checked against chain state):
- No nullifier has already been spent (double-spend prevention).
- For `ValidatorRegister`: validator not already registered; bond output matches required bond; Merkle root valid.
- For `ValidatorDeregister`: validator is registered and not slashed; signature uses registered key.

### 5.3 Mempool

Valid transactions enter the fee-priority mempool:
- Transactions ordered by `fee / estimated_size` (fee rate).
- Duplicate nullifiers across mempool transactions: lower-fee transaction is evicted.
- Hard capacity limits: `MEMPOOL_MAX_TXS = 10,000` transactions or `MEMPOOL_MAX_BYTES = 50 MiB` total serialized size; when either limit is reached, the lowest-fee transaction is evicted.

### 5.4 Inclusion

Committee members include transactions from the mempool into proposed vertices, selecting by fee rate up to `MAX_TXS_PER_VERTEX` transactions.

### 5.5 Finality

A transaction is **final** when the vertex containing it receives a BFT certificate (quorum of `q` committee votes). Finality is instant and deterministic. A certified vertex is never reverted.

---

## 6. DAG-BFT Consensus Protocol

### 6.1 Epochs and Committee Selection

**Epoch seed derivation**:
```text
combined_vrf_mix = H_d("umbra.epoch.combined_mix", H_concat(bft_vrf_mix, dag_vrf_mix))
epoch_seed_new   = H_concat("umbra.epoch.seed", epoch_le64, prev_seed, state_root, combined_vrf_mix)
```
where `bft_vrf_mix` aggregates VRF proof commitments from BFT votes, `dag_vrf_mix` aggregates
deduplicated VRF output values from finalized vertex proposers, and `epoch_le64` is the
current epoch number as a little-endian 64-bit integer.

**VRF evaluation**: each active validator `v` with signing key `sk_v` computes:
```text
(vrf_output, vrf_proof) = VRF.prove(sk_v, epoch_seed)
```

The VRF output is a deterministic pseudorandom 32-byte value. It is verifiable by any party given `pk_v`.

**Committee membership test**:
```text
r = first 8 bytes of vrf_output, interpreted as u64 (little-endian)
selected if: r * total_validators < COMMITTEE_SIZE * 2^64
special case: if COMMITTEE_SIZE >= total_validators, all validators are selected
```
This selects each validator independently with probability `COMMITTEE_SIZE / total_validators`,
giving an expected committee of exactly `COMMITTEE_SIZE = 21` members for large validator sets.
If fewer than `MIN_COMMITTEE_SIZE = 7` are selected, all active validators serve as the committee.

**Properties**:
- Selection is unpredictable before the epoch seed is revealed.
- Selection is verifiable by any observer after revelation.
- Expected committee size is exactly `COMMITTEE_SIZE` for large validator sets.

### 6.2 Vertex Proposal

Committee members may produce vertices at any time after the epoch starts:

1. Gather pending transactions from the mempool.
2. Collect 1 to `MAX_PARENTS` tips from the local DAG view.
3. Compute the state root after applying all transactions.
4. Produce the vertex body and sign it:
```text
   vertex_id = H_d("umbra.vertex.id", parents || epoch || round || proposer_fingerprint || tx_root
                   || presence_byte || vrf_output_value? || state_root || protocol_version)
   signature = Sign(sk_v, vertex_id)
```
5. Attach the VRF proof demonstrating committee membership.
6. Broadcast the vertex to all peers.

**Vertex validation** (receivers check before relaying):
- `parents` are known and finalized or pending finalization.
- `1 <= len(parents) <= MAX_PARENTS`.
- `timestamp` not more than `MAX_VERTEX_TIMESTAMP_DRIFT_SECS` in the future.
- `signature` verifies under `proposer`.
- `vrf_proof` verifies and proposer passes the committee membership test: `r × total_validators < COMMITTEE_SIZE × 2^64` where `r` is the first 8 bytes of `vrf_output` as a little-endian u64.
- All included transactions pass structural and cryptographic checks.
- `state_root` matches the computed root after applying transactions.

### 6.3 Voting and Certification

BFT proceeds in rounds within each epoch:

```text
Phase 1 — PROPOSE:
  Leader broadcasts vertex.

Phase 2 — VOTE:
  Each committee member v that received and validated the vertex sends:
    vote = Vote { vertex_id, epoch, round, vote_type=VOTE, sig=Sign(sk_v, vote_sign_data) }
  vote_sign_data = H_d("umbra.vote", epoch || round || vertex_id || vote_type)

Phase 3 — CERTIFY:
  When any node collects q >= 15 valid VOTE messages for the same vertex_id
  from distinct committee members, it forms a Certificate and marks the vertex final.
```

**Quorum function** (runtime, accounts for variable committee size):
```text
dynamic_quorum(k) = floor(2k/3) + 1
```

A vertex is **certified** (final) when a `Certificate` containing at least `dynamic_quorum(k)` valid votes exists. Certified vertices are broadcast to all peers.

**Vote validation**:
- Voter is a current committee member (VRF proof on file).
- `epoch` and `round` match the current epoch and round.
- `vote_type` is included in the signed data (prevents type confusion).
- Signature verifies under the voter's key.
- No prior vote from this voter for this `(epoch, round)` — duplicate votes are rejected.

### 6.4 Equivocation and Slashing

Equivocation is when a validator votes for two different vertices in the same epoch and round:

```text
EquivocationEvidence = { voter_id, epoch, round, vote_a, vote_b }
  where vote_a.vertex_id != vote_b.vertex_id
```

Any node observing equivocation may include `EquivocationEvidence` in a subsequent vertex. On finalization of that vertex:

1. The equivocating validator is permanently slashed: their bond is destroyed.
2. The slashed validator is added to `slashed_validators` and may not re-register.
3. A `SLASH_REGISTRATION_COOLDOWN_EPOCHS`-epoch window begins during which new registrations cost `SLASH_BOND_MULTIPLIER × normal_bond`.

### 6.5 Epoch Rotation

After `EPOCH_LENGTH = 1000` finalized vertices:

1. Compute `epoch_seed` for epoch `N+1` from the current state root.
2. Each committee-eligible validator evaluates its VRF against the new seed.
3. Assemble the epoch `N+1` committee.
4. **Committee history is preserved** for cross-epoch equivocation verification.
5. Cache the old committee in `committee_history` before clearing epoch caches.

The epoch rotation order is critical:
- Committee for `N+1` is computed BEFORE clearing caches.
- `preserve_committee_history()` is called to retain the old committee.
- Then `clear_epoch_caches()` clears vote counters and seen sets.

---

## 7. State Transitions

### 7.1 Transfer

A `Transfer` transaction removes input commitments (by revealing their nullifiers) and adds output commitments to the UTXO set.

**Valid state transition**:
- All `nullifier` values are fresh (not in nullifier set).
- `BalanceStarkProof` verifies with the claimed `fee`.
- All `SpendStarkProof`s verify against the current Merkle root.

**State update**:
- Insert all input nullifiers into the nullifier set.
- Insert all output commitments into the Merkle tree.
- Deduct `fee` from the implicit balance (enforced by balance proof).

### 7.2 Validator Registration

A `ValidatorRegister` transaction:
- Includes a `bond_output`: a commitment to exactly `required_bond(n)` base units.
- Includes a KEM public key for P2P authentication.
- Is signed with the validator's signing key pair.

**Valid state transition**:
- Validator not already registered (unless this is a reregistration after prior deregistration).
- `bond_output.commitment` opens to `required_bond(n)` (verified by BalanceStarkProof).
- Fee is at least `MIN_TX_FEE`.

**State update**:
- Record `(validator_id, bond)` in the validator set.
- Insert bond commitment into the Merkle tree.
- Set `activation_epoch = current_epoch + COMMITTEE_ELIGIBILITY_DELAY_EPOCHS`. The validator is not eligible for committee selection until this epoch, preventing registration-timing attacks.

### 7.3 Validator Deregistration

A `ValidatorDeregister` transaction:
- Includes a `bond_return_output`: a commitment to the returned bond.
- Signed with the validator's registered key pair.
- Returns all bond funds minus fee.

**Valid state transition**:
- Validator is registered.
- Validator is not slashed.
- Cannot deregister if it would drop the active validator count below `MIN_VALIDATORS`.
- `bond_return_output.encrypted_note.ciphertext.len() <= MAX_ENCRYPTED_NOTE_CIPHERTEXT_SIZE`.
- Signature over `deregister_sign_data(chain_id, validator_id)` verifies.

**State update**:
- Remove validator from active set.
- Nullify the bond commitment (add its nullifier to the spent set).
- Add bond return commitment to the Merkle tree.

### 7.4 Coinbase

`Coinbase` transactions may only be produced by the current epoch's committee leader and must be included in the leader's own vertex. They issue new coins according to the emission schedule. Coinbase outputs follow the same commitment structure as `Transfer` outputs.

---

## 8. Network Protocol

### 8.1 P2P Handshake

All node-to-node connections are encrypted and mutually authenticated. The handshake proceeds over TCP:

```text
Step 1 — Hello (plaintext):
  Initiator → Responder: Hello { protocol_version, node_id, kem_pk, listen_addr }
  Responder → Initiator: Hello { protocol_version, node_id, kem_pk, listen_addr }
  Both: verify protocol_version matches.

Step 2 — KEM:
  Initiator → Responder: KemCiphertext
    (ss, ct) = KEM.Enc(responder.kem_pk)
  Session key: session_key = H_d("umbra.session", ss)

Step 3 — Auth:
  Initiator → Responder: Auth { sig = Sign(sk_i, H_d("umbra.auth", ss || initiator_pk || responder_pk)) }
  Responder → Initiator: Auth { sig = Sign(sk_r, H_d("umbra.auth", ss || initiator_pk || responder_pk)) }
  Both: verify the other's auth signature against their Hello-advertised signing key.

Step 4 — Encrypted transport:
  All subsequent messages: AEAD.Enc(session_key, nonce, payload)
  Nonces: 96-bit monotonically increasing counters (separate Tx/Rx).
  Frames padded to next multiple of P2P_PADDING_BUCKET (1024 bytes).
```

**Known limitations** (acknowledged in the implementation):
- The node's KEM keypair is static — compromise of the KEM secret key allows retroactive session key derivation. Periodic rekeying provides post-compromise recovery but not full forward secrecy.
- The `Hello` message is plaintext, leaking the KEM public key before the encrypted channel is established.

### 8.2 Message Types

The `Message` enum is the top-level wire type (bincode v2 serialization):

| Message | Direction | Description |
|---|---|---|
| `NewTransaction` | Any | Gossip a transaction |
| `NewVertex` | Any | Gossip a DAG vertex |
| `Vote` | Validator → Any | BFT vote |
| `Certificate` | Any | BFT certificate |
| `EquivocationEvidence` | Any | Slashing evidence |
| `GetSnapshot` | Node → Node | Request state snapshot |
| `Snapshot` | Node → Node | State snapshot response |
| `PeerList` | Any | Peer discovery |
| `Ping` / `Pong` | Any | Liveness check |

All messages include a domain-separated BLAKE3 message ID for gossip deduplication.

### 8.3 Gossip and Deduplication

Nodes maintain two rolling "seen" sets (each capped at 10,000 entries) to deduplicate gossip:

```text
seen_messages_current: Set<Hash>   // current generation
seen_messages_previous: Set<Hash>  // previous generation
```

On receiving a message with ID `mid`:
1. If `mid` is in either set: drop the message.
2. Otherwise: process the message, add `mid` to `seen_messages_current`.
3. When `seen_messages_current` reaches capacity: rotate — `previous = current`, `current = {}`.

**Rate limiting**: each peer is subject to a token-bucket rate limiter with `PEER_MSG_RATE_LIMIT = 100 msg/s` and `PEER_MSG_BURST = 200 msg` burst.

### 8.4 Dandelion++ Transaction Routing

To protect transaction origin privacy, Umbra implements Dandelion++ (F6):

```text
Stem phase:
  1. New transaction enters stem phase.
  2. Select one random peer as the next hop.
  3. Forward after a random delay in [DANDELION_STEM_DELAY_MIN_MS, DANDELION_STEM_DELAY_MAX_MS].
  4. Attempt up to DANDELION_STEM_HOPS (2) hops; however, in the current implementation
     receiving nodes immediately fluff rather than continuing the stem, so the effective
     stem length is 1 hop.
  5. If stem timeout (DANDELION_TIMEOUT_MS = 5000ms) expires without fluffing:
     fluff immediately (broadcast normally).

Fluff phase:
  Transaction is gossiped to all peers normally.
```

Stem transactions are tracked in `stem_txs` (max `MAX_STEM_TXS = 5000` entries) to prevent double-routing.

---

## 9. Serialization

All wire-format types use **bincode v2** with the legacy (serde) configuration:

```rust
bincode::serde::encode_to_vec(&value, bincode::config::legacy())
bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
```

**Size limits**:
- Transaction message ciphertext (`TxMessage.payload.ciphertext`): rejected if > `MAX_MESSAGE_SIZE = 65,536` bytes (64 KiB).
- Deserialized objects: `deserialize()` rejects inputs > `MAX_NETWORK_MESSAGE_BYTES = 16 MiB`.
- Snapshot blobs: assembled snapshots may exceed 16 MiB; use `deserialize_snapshot()`.

**Hashing helpers**:
- `hash_domain(domain: &[u8], data: &[u8]) -> Hash`: BLAKE3 keyed hash using `domain` as the key derivation context (`new_derive_key`), with `data` as the sole input — no manual length prefix.
- `hash_concat(parts: &[&[u8]]) -> Hash`: standard BLAKE3 over `len_u64le(p1) || p1 || len_u64le(p2) || p2 || ...` where length prefixes are 8-byte little-endian u64.

---

## 10. RPC API

Umbra nodes expose a JSON HTTP API (axum) on the configured RPC port:

| Endpoint | Method | Description |
|---|---|---|
| `/tx/submit` | POST | Submit a signed transaction |
| `/tx/{id}` | GET | Fetch transaction by ID |
| `/state/validators` | GET | List active validators |
| `/state/nullifier/{n}` | GET | Check if nullifier is spent |
| `/state/merkle_root` | GET | Current Merkle tree root |
| `/state/merkle_proof/{commitment}` | GET | Merkle inclusion proof for a commitment |
| `/health` | GET | Node health and sync status |
| `/metrics` | GET | Prometheus-compatible metrics |
| `/fee_estimate` | GET | Estimated fee rate for current mempool |
| `/light_client/header/{epoch}` | GET | Epoch header for light clients |

All endpoints return JSON. Error responses use `{ "error": "..." }` with appropriate HTTP status codes.
