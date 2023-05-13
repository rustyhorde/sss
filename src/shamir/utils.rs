// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` utils

use anyhow::Result;

use crate::{
    base62::{decode, encode},
    error::SsssError::InvalidShareFormat,
};

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn encode_share(tuple: (usize, Vec<u8>)) -> Result<String> {
    let idx = u8::try_from(tuple.0)? + 1;
    let idx_enc = encode(&idx.to_be_bytes());
    let share_enc = encode(&tuple.1);
    Ok(format!("{idx_enc}:{share_enc}"))
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn decode_share(share: String) -> Result<(u8, Vec<u8>)> {
    let split_str = share.split(':').collect::<Vec<&str>>();
    if split_str.len() == 2 {
        let idx_bytes = decode(split_str[0])?;
        let idx = u8::from_be_bytes((&idx_bytes[..]).try_into()?);
        let share = decode(split_str[1])?;
        Ok((idx, share))
    } else {
        Err(InvalidShareFormat.into())
    }
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
