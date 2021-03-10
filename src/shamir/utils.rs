// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` utils

use anyhow::Result;
use std::convert::TryFrom;

pub(crate) fn inc_key(tuple: (usize, Vec<u8>)) -> Result<(u8, Vec<u8>)> {
    Ok((u8::try_from(tuple.0 + 1)?, tuple.1))
}

pub(crate) fn filter_ok<T>(result: Result<T>) -> Option<T> {
    result.ok()
}

pub(crate) fn transpose<T>(v: &[Vec<T>]) -> Vec<Vec<T>>
where
    T: Clone,
{
    if let Some(first) = v.get(0) {
        (0..first.len())
            .map(|i| v.iter().map(|inner| inner[i].clone()).collect::<Vec<T>>())
            .collect()
    } else {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::transpose;

    #[test]
    fn transpose_empty_works() {
        let empty_vec: Vec<Vec<u8>> = vec![];
        assert!(transpose(&empty_vec).is_empty());
    }
}
