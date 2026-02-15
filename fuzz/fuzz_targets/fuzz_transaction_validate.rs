#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Deserialize a transaction, then exercise cheap non-STARK methods to
    // detect panics in field access and hashing logic on malformed inputs.
    // We intentionally skip validate_structure() because it invokes STARK
    // proof verification which is far too slow for fuzzing.
    if let Ok(tx) = umbra::deserialize::<Transaction>(data) {
        let _ = tx.tx_id();
        let _ = tx.tx_content_hash();
        let _ = tx.compute_fee();
        let _ = tx.estimated_size();
    }
});
