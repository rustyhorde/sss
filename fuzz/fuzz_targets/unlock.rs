#![no_main]
use libfuzzer_sys::fuzz_target;
use ssss::unlock;
use std::collections::HashMap;

fuzz_target!(|data: HashMap<u8, Vec<u8>>| {
    let _ = unlock(&data);
});