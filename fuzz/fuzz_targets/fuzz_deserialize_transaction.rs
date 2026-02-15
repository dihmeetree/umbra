#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Transaction contains deeply nested types: TxInput (nullifier +
    // SpendStarkProof), TxOutput (commitment + StealthAddress with Kyber
    // ciphertext + EncryptedPayload), BalanceStarkProof, TxMessage, and
    // TxType enum variants with variable-length cryptographic keys.
    // Deserialization must never panic on arbitrary bytes.
    let _ = umbra::deserialize::<Transaction>(data);
});
