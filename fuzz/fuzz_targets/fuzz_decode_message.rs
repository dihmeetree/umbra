#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra::network::decode_message;

fuzz_target!(|data: &[u8]| {
    // decode_message parses a 4-byte LE length prefix followed by a bincode
    // payload into one of 30+ Message enum variants.  It must never panic on
    // arbitrary input, returning None for anything it cannot decode.
    let _ = decode_message(data);
});
