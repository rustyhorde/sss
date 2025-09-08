// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` testing utilities

#[cfg(test)]
use anyhow::{Result, anyhow};
use rand::{rngs::ThreadRng, seq::IteratorRandom};

#[doc(hidden)]
pub fn remove_random_entry<T>(rng: &mut ThreadRng, vec: &mut Vec<T>) {
    let _unused = (0..vec.len())
        .choose(rng)
        .map(|idx| Some(remove_idx(idx, vec)));
}

fn remove_idx<T>(idx: usize, vec: &mut Vec<T>) -> T {
    vec.remove(idx)
}

#[cfg(test)]
pub(crate) fn check_err_result<T>(result: Result<T>, expected: &str) -> Result<()> {
    assert!(result.is_err());
    match result {
        Ok(_) => Err(anyhow!("invalid error result")),
        Err(e) => {
            assert_eq!(format!("{e}"), expected);
            Ok(())
        }
    }
}
