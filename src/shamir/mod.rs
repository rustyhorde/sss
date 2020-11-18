// Copyright (c) 2020 sss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `sss` Shamir's Secret Sharing

mod utils;

use crate::{error::Result, gf256};
use std::collections::HashMap;
use utils::{filter_ok, inc_key, transpose};

/// Create `parts` shares with a given minimum `threshold` required to reconstruct
/// the given secret.
pub fn split(secret: &[u8], parts: u8, threshold: u8) -> Result<HashMap<u8, Vec<u8>>> {
    let coeff_fn =
        |secret_byte: &u8| -> Vec<u8> { gf256::generate_coeffs(threshold, *secret_byte) };
    let gf_add_fn = |p: Vec<u8>| -> Vec<u8> { (1..=parts).map(|i| gf256::eval(&p, i)).collect() };

    Ok(
        transpose(secret.iter().map(coeff_fn).map(gf_add_fn).collect())
            .iter()
            .cloned()
            .enumerate()
            .map(inc_key)
            .filter_map(filter_ok)
            .collect(),
    )
}

/// Attempt to join the given `shares` into a secret.
pub fn join(shares: &HashMap<u8, Vec<u8>>) -> Vec<u8> {
    if !shares.is_empty() {
        let lengths: Vec<usize> = shares.values().map(Vec::len).collect();
        let len = lengths[0];
        let mut secret = vec![];
        if lengths.iter().all(|x| *x == len) {
            for i in 0..lengths[0] {
                let mut points = vec![vec![0; 2]; shares.len()];
                let mut j = 0;
                for (k, v) in shares {
                    points[j][0] = *k;
                    points[j][1] = v[i];
                    j += 1;
                }
                secret.push(gf256::interpolate(points));
            }
        }

        secret
    } else {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::{join, split};
    use crate::error::Result;
    use rand::{rngs::ThreadRng, seq::IteratorRandom, thread_rng};
    use std::collections::HashMap;

    #[test]
    fn split_and_join() -> Result<()> {
        let secret = "correct horse battery staple".as_bytes();
        let shares = split(&secret, 5, 3)?;

        // 5 parts should work
        let mut parts = shares.clone();
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 4 parts shoud work
        let mut rng = thread_rng();
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 3 parts should work
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 2 parts should not
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_ne!(join(&parts), secret);

        Ok(())
    }

    fn choose_idx(rng: &mut ThreadRng, map: &HashMap<u8, Vec<u8>>) -> Option<u8> {
        map.clone().keys().choose(rng).cloned()
    }

    fn print_parts(map: &HashMap<u8, Vec<u8>>) {
        for (k, v) in map {
            println!("Key: {}, Value: {:?}", k, v);
        }
    }
}
