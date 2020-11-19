// Copyright (c) 2020 sss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `sss` Shamir's Secret Sharing

mod utils;

use crate::{
    error::{Error, Result},
    gf256,
};
use getset::Setters;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use utils::{filter_ok, inc_key, transpose};

/// Configuration used to drive the [`gen_shares`] function.
///
/// # Notes
/// The default configuration will specify 5 shares with a
/// threshold of 3.  The maximum secret size is [u16::MAX] (65536)
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Setters)]
#[getset(set = "pub")]
pub struct SSSConfig {
    /// The total shares to be generate from a secret
    num_shares: u8,
    /// The threshold of valid shares required to unlock a secret
    /// This must be less than or equal to the number of shares
    threshold: u8,
    /// The maximum secret size in bytes
    max_secret_size: usize,
}

impl Default for SSSConfig {
    fn default() -> Self {
        SSSConfig {
            num_shares: 5,
            threshold: 3,
            max_secret_size: usize::from(u16::MAX),
        }
    }
}

impl SSSConfig {
    fn validate(&self) -> Result<()> {
        if self.num_shares == 0 || self.threshold == 0 {
            Err(Error::zero_p_or_t())
        } else if self.threshold > self.num_shares {
            Err(Error::invalid_threshold())
        } else {
            Ok(())
        }
    }
}

/// Generate shares based on the [`num_shares`](SSSConfig::set_num_shares) and [`threshold`](SSSConfig::set_threshold) given
/// in the configuration.  Using the default [`SSSConfig`] will generate 5 shares
/// of which 3 are required to unlock the secret.
///
/// # Errors
/// * This function will generate an error if `secret` is empty or larger than
/// [`max_secret_size`](SSSConfig::set_max_secret_size) in the configuration.
/// * This function will generate an error if either [`num_shares`](SSSConfig::set_num_shares) or [`threshold`](SSSConfig::set_threshold)
/// are 0.
/// * This function will generate an error if [`threshold`](SSSConfig::set_threshold) is greater than [`num_shares`](SSSConfig::set_num_shares)
///
/// # Example
/// ```
/// # use sss::{gen_shares, unlock, Error, SSSConfig};
/// #
/// # pub fn main() -> Result<(), Error> {
/// // Generate 5 shares from the given secret
/// let secret = "s3(r37".as_bytes();
/// let mut shares = gen_shares(&SSSConfig::default(), secret)?;
/// assert_eq!(shares.len(), 5);
///
/// // Remove a couple shares to show 3 will unlock the secret (4 or 5 shares will as well)
/// let _ = shares.remove(&2);
/// let _ = shares.remove(&5);
/// assert_eq!(shares.len(), 3);
/// let unlocked_secret = unlock(&shares)?;
/// assert_eq!(secret, unlocked_secret);
///
/// // Remove one more to show 2 shares will not unlock the secret
/// let _ = shares.remove(&1);
/// assert_eq!(shares.len(), 2);
/// let who_knows = unlock(&shares)?;
/// assert_ne!(secret, who_knows);
/// # Ok(())
/// # }
pub fn gen_shares(config: &SSSConfig, secret: &[u8]) -> Result<HashMap<u8, Vec<u8>>> {
    validate_split_args(config, secret)?;
    let SSSConfig {
        num_shares,
        threshold,
        max_secret_size: _,
    } = config;

    let coeff_fn =
        |secret_byte: &u8| -> Vec<u8> { gf256::generate_coeffs(*threshold, *secret_byte) };
    let gf_add_fn =
        |p: Vec<u8>| -> Vec<u8> { (1..=*num_shares).map(|i| gf256::eval(&p, i)).collect() };

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

fn validate_split_args(config: &SSSConfig, secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        Err(Error::secret_empty())
    } else if secret.len() > config.max_secret_size {
        Err(Error::max_secret_len())
    } else {
        config.validate()
    }
}

/// Attempt to unlock the secret given some [`shares`](gen_shares).
///
/// # Notes
/// * If there aren't enough shares to meet the threshold defined when
/// the shares were created the resulting vector of bytes will be gibberish.
/// * If there are more shares supplied than were defined when the shares
/// were created the resulting vector of bytes will be gibberish.
///
/// # Errors
/// * This function will generate an error if the `shares` map is empty.
/// * This function will generate an error if the `shares` within the map are not
/// all the same length.
///
/// # Example
/// ```
/// # use sss::{gen_shares, unlock, Error, SSSConfig};
/// #
/// # pub fn main() -> Result<(), Error> {
/// // Generate 5 shares from the given secret
/// let secret = "s3(r37".as_bytes();
/// let mut shares = gen_shares(&SSSConfig::default(), secret)?;
/// assert_eq!(shares.len(), 5);
///
/// // Remove a couple shares to show 3 will unlock the secret (4 or 5 shares will as well)
/// let _ = shares.remove(&2);
/// let _ = shares.remove(&5);
/// assert_eq!(shares.len(), 3);
/// let unlocked_secret = unlock(&shares)?;
/// assert_eq!(secret, unlocked_secret);
///
/// // Remove one more to show 2 shares will not unlock the secret
/// let _ = shares.remove(&1);
/// assert_eq!(shares.len(), 2);
/// let who_knows = unlock(&shares)?;
/// assert_ne!(secret, who_knows);
/// # Ok(())
/// # }
pub fn unlock(shares: &HashMap<u8, Vec<u8>>) -> Result<Vec<u8>> {
    let secret_len = validate_join_args(shares)?;
    let mut secret = vec![];

    for i in 0..secret_len {
        let mut points = vec![vec![0; 2]; shares.len()];
        for (idx, (k, v)) in shares.iter().enumerate() {
            points[idx][0] = *k;
            points[idx][1] = v[i];
        }
        secret.push(gf256::interpolate(points));
    }

    Ok(secret)
}

fn validate_join_args(shares: &HashMap<u8, Vec<u8>>) -> Result<usize> {
    if shares.is_empty() {
        Err(Error::shares_map_empty())
    } else {
        let lengths: Vec<usize> = shares.values().map(Vec::len).collect();
        let len = lengths[0];
        if len == 0 {
            Err(Error::shares_empty())
        } else if lengths.iter().all(|x| *x == len) {
            Ok(len)
        } else {
            Err(Error::share_length_mismatch())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{gen_shares, unlock, SSSConfig};
    use crate::{
        error::Result,
        utils::{check_err_result, remove_random_entry},
    };
    use rand::thread_rng;
    use std::collections::HashMap;

    #[test]
    fn empty_secret() -> Result<()> {
        let config = SSSConfig::default();
        let result = gen_shares(&config, &vec![]);
        check_err_result(result, "protocol: The given secret cannot be empty")
    }

    #[test]
    fn max_secret() -> Result<()> {
        let mut config = SSSConfig::default();
        let _ = config.set_max_secret_size(3);
        let result = gen_shares(&config, "abcd".as_bytes());
        check_err_result(
            result,
            "protocol: The maximum secret length has been exceeded",
        )
    }

    #[test]
    fn zero_parts() -> Result<()> {
        let mut config = SSSConfig::default();
        let _ = config.set_num_shares(0);
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(
            result,
            "protocol: The parts and threshold arguments cannot be 0",
        )
    }

    #[test]
    fn zero_threshold() -> Result<()> {
        let mut config = SSSConfig::default();
        let _ = config.set_threshold(0);
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(
            result,
            "protocol: The parts and threshold arguments cannot be 0",
        )
    }

    #[test]
    fn threshold_greater_than_parts() -> Result<()> {
        let mut config = SSSConfig::default();
        let _ = config.set_threshold(6);
        let result = gen_shares(&mut config, "a".as_bytes());
        check_err_result(
            result,
            "protocol: The threshold argument must be less than or equal to the parts argument",
        )
    }

    #[test]
    fn empty_share_map() -> Result<()> {
        let result = unlock(&HashMap::default());
        check_err_result(result, "protocol: The given shares map cannot be empty")
    }

    #[test]
    fn shares_of_differing_lengths() -> Result<()> {
        let mut bad_shares = HashMap::default();
        let _ = bad_shares.insert(1, "abc".as_bytes().to_vec());
        let _ = bad_shares.insert(2, "ab".as_bytes().to_vec());

        let result = unlock(&bad_shares);
        check_err_result(result, "protocol: The given shares have differing lengths")
    }

    #[test]
    fn empty_shares() -> Result<()> {
        let mut bad_shares = HashMap::default();
        let _ = bad_shares.insert(1, vec![]);
        let _ = bad_shares.insert(2, vec![]);

        let result = unlock(&bad_shares);
        check_err_result(result, "protocol: The given shares cannot be empty")
    }

    #[test]
    fn too_many_shares() -> Result<()> {
        let config = SSSConfig::default();
        let secret = "a".as_bytes();
        let mut shares = gen_shares(&config, secret)?;
        let _ = shares.insert(6, vec![55]);
        let unlocked = unlock(&shares)?;
        assert_ne!(unlocked, secret);
        Ok(())
    }

    #[test]
    fn split_and_join() -> Result<()> {
        let secret = "correct horse battery staple".as_bytes();
        let config = SSSConfig::default();
        let shares = gen_shares(&config, &secret)?;

        // 5 parts should work
        let mut parts = shares.clone();
        assert_eq!(parts.len(), 5);
        assert_eq!(unlock(&parts)?, secret);

        // 4 parts shoud work
        let mut rng = thread_rng();
        remove_random_entry(&mut rng, &mut parts);
        assert_eq!(parts.len(), 4);
        assert_eq!(unlock(&parts)?, secret);

        // 3 parts should work
        remove_random_entry(&mut rng, &mut parts);
        assert_eq!(parts.len(), 3);
        assert_eq!(unlock(&parts)?, secret);

        // 2 parts should not
        remove_random_entry(&mut rng, &mut parts);
        assert_eq!(parts.len(), 2);
        assert_ne!(unlock(&parts)?, secret);

        Ok(())
    }
}
