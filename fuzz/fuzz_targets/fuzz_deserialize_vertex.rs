#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra::consensus::dag::Vertex;

fuzz_target!(|data: &[u8]| {
    // Vertex wraps a Vec<Transaction> plus proposer public key, signature,
    // optional VRF proof, and DAG parent references.  Deserialization must
    // never panic on arbitrary bytes.
    let _ = umbra::deserialize::<Vertex>(data);
});
