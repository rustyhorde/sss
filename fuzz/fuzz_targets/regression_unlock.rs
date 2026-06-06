// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `unlock` fuzz crashes.

use arbitrary::{Arbitrary, Unstructured};
use ssss::unlock;

/// Mirrors the `unlock` fuzz target body: decode the raw libFuzzer input into the
/// structured argument the way `libfuzzer-sys` does (`arbitrary_take_rest`), then
/// exercise `unlock`. Feeding the saved crash bytes through this reproduces the
/// exact input the fuzzer found.
fn run_unlock(data: &[u8]) {
    let u = Unstructured::new(data);
    if let Ok(shares) = Vec::<String>::arbitrary_take_rest(u) {
        let _ = unlock(&shares);
    }
}

#[test]
fn regression_empty() {
    run_unlock(&[]);
}

/// Regression for `crash-ef71bb25…`: a share string decoded to fewer than PREFIX
/// bytes, panicking on an out-of-range slice in `base62::decode`. Fixed by
/// returning `InvalidShareFormat` (also covered by the `base62` unit tests).
#[test]
fn regression_crash_ef71bb25() {
    const CRASH: &[u8] = &[0x75, 0x36, 0x3a, 0x23];
    run_unlock(CRASH);
}
