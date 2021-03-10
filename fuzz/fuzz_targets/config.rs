#![no_main]
use libfuzzer_sys::fuzz_target;
use ssss::{gen_shares, SsssConfig};

fuzz_target!(|config: SsssConfig| {
    let data = "correct horse battery staple".as_bytes();
    let _ = gen_shares(&config, data);
});