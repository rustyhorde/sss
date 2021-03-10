#![no_main]
use libfuzzer_sys::fuzz_target;
use ssss::{gen_shares, SsssConfig};

fuzz_target!(|data: &[u8]| {
    let _ = gen_shares(&SsssConfig::default(), data);
});
