// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use rand::{Rng, rng};

use crate::error::SsssError::{BadCharacter, InvalidShareFormat};

const BASE: usize = 62;
const PREFIX: usize = 10;
const ALPHABET: [char; BASE] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z',
];

pub(crate) fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::new()
    } else {
        let mut nonce = [0u8; 10];
        rng().fill_bytes(&mut nonce);
        let mut input = nonce.to_vec();
        input[0] = 1;
        input.extend_from_slice(bytes);

        let mut result = String::new();
        let mut val = BigUint::from_bytes_be(&input);
        let base: BigUint = (BASE.to_owned() as u64).into();

        while val > BigUint::zero() {
            let remainder = val.mod_floor(&base).to_usize().unwrap_or(0);
            result.push(ALPHABET[remainder]);
            val /= &base;
        }

        result
    }
}

pub(crate) fn decode(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        Ok(vec![])
    } else {
        let mut val: BigUint = BigUint::zero();
        let mut base_mul = BigUint::one();
        let base: BigUint = (BASE.to_owned() as u64).into();

        for c in input.chars() {
            let remainder: BigUint = char_to_remainder(c)?.into();
            val += remainder * &base_mul;
            base_mul *= &base;
        }
        // A valid share always encodes a `PREFIX`-byte nonce ahead of at least
        // one payload byte (and the nonce's leading byte is forced non-zero), so
        // the decoded buffer is always longer than `PREFIX`. A shorter buffer
        // means the input was not produced by `encode`; reject it rather than
        // panicking on an out-of-range slice.
        let bytes = val.to_bytes_be();
        if bytes.len() < PREFIX {
            Err(InvalidShareFormat.into())
        } else {
            Ok(bytes[PREFIX..].to_vec())
        }
    }
}

fn char_to_remainder(c: char) -> Result<u64> {
    let i = match c {
        '0'..='9' => u64::from(c) % u64::from('0'),
        'A'..='Z' => u64::from(c) % u64::from('A') + 10,
        'a'..='z' => u64::from(c) % u64::from('a') + 36,
        _ => return Err(BadCharacter { c }.into()),
    };

    Ok(i)
}

#[cfg(test)]
mod test {
    use super::{decode, encode};
    use crate::utils::check_err_result;
    use anyhow::Result;

    #[test]
    fn encode_decode_roundtrips() -> Result<()> {
        let secret = "correct horse battery staple".as_bytes();
        assert_eq!(decode(&encode(secret))?, secret);
        Ok(())
    }

    #[test]
    fn decode_empty_is_empty() -> Result<()> {
        assert!(decode("")?.is_empty());
        Ok(())
    }

    #[test]
    fn decode_bad_character_errors() -> Result<()> {
        check_err_result(decode("hello:world"), "Base62 docoding bad character: :")
    }

    #[test]
    fn decode_short_buffer_errors() -> Result<()> {
        // A single base62 digit decodes to a buffer shorter than `PREFIX`; it
        // must be rejected instead of panicking on an out-of-range slice.
        check_err_result(decode("1"), "Invalid share format")
    }
}
