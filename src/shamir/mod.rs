// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` Shamir's Secret Sharing Scheme

mod utils;

use crate::{
    error::SsssError::{
        EmptySecret, EmptyShare, EmptySharesMap, SecretLength, ShareLengthMismatch, SharesZero,
        ThresholdToLow, ThresholdZero,
    },
    gf256,
};
use anyhow::{anyhow, Result};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use getset::Setters;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, hash::BuildHasher};
use utils::{filter_ok, inc_key, transpose};

/// Configuration used to drive the [`gen_shares`] function.
///
/// # Notes
/// The default configuration will specify 5 shares with a
/// threshold of 3.  The maximum secret size is [`u16::MAX`] (65536)
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Setters)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[getset(set = "pub")]
pub struct SsssConfig {
    /// The total shares to be generate from a secret
    num_shares: u8,
    /// The threshold of valid shares required to unlock a secret
    /// This must be less than or equal to the number of shares
    threshold: u8,
    /// The maximum secret size in bytes
    max_secret_size: usize,
}

impl Default for SsssConfig {
    fn default() -> Self {
        SsssConfig {
            num_shares: 5,
            threshold: 3,
            max_secret_size: usize::from(u16::MAX),
        }
    }
}

impl SsssConfig {
    fn validate(&self) -> Result<()> {
        if self.num_shares == 0 {
            Err(anyhow!(SharesZero))
        } else if self.threshold == 0 {
            Err(anyhow!(ThresholdZero))
        } else if self.threshold > self.num_shares {
            Err(anyhow!(ThresholdToLow {
                threshold: self.threshold,
                shares: self.num_shares
            }))
        } else {
            Ok(())
        }
    }
}

/// Generate shares based on the [`num_shares`](SsssConfig::set_num_shares) and [`threshold`](SsssConfig::set_threshold) given
/// in the configuration.  Using the default [`SsssConfig`] will generate 5 shares
/// of which 3 are required to unlock the secret.
///
/// # Errors
/// * This function will generate an error if `secret` is empty or larger than
/// [`max_secret_size`](SsssConfig::set_max_secret_size) in the configuration.
/// * This function will generate an error if either [`num_shares`](SsssConfig::set_num_shares) or [`threshold`](SsssConfig::set_threshold)
/// are 0.
/// * This function will generate an error if [`threshold`](SsssConfig::set_threshold) is greater than [`num_shares`](SsssConfig::set_num_shares)
///
/// # Example
/// ```
/// # use anyhow::Result;
/// # use ssss::{gen_shares, unlock, SsssConfig};
/// #
/// # pub fn main() -> Result<()> {
/// // Generate 5 shares from the given secret
/// let secret = "s3(r37".as_bytes();
/// let mut shares = gen_shares(&SsssConfig::default(), secret)?;
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
pub fn gen_shares(config: &SsssConfig, secret: &[u8]) -> Result<HashMap<u8, Vec<u8>>> {
    validate_split_args(config, secret)?;
    let SsssConfig {
        num_shares,
        threshold,
        max_secret_size: _,
    } = config;

    let coeff_fn =
        |secret_byte: &u8| -> Vec<u8> { gf256::generate_coeffs(*threshold, *secret_byte) };
    let gf_add_fn =
        |p: Vec<u8>| -> Vec<u8> { (1..=*num_shares).map(|i| gf256::eval(&p, i)).collect() };

    let secret: Vec<Vec<u8>> = secret.iter().map(coeff_fn).map(gf_add_fn).collect();
    Ok(transpose(&secret)
        .iter()
        .cloned()
        .enumerate()
        .map(inc_key)
        .filter_map(filter_ok)
        .collect())
}

fn validate_split_args(config: &SsssConfig, secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        Err(anyhow!(EmptySecret))
    } else if secret.len() > config.max_secret_size {
        Err(anyhow!(SecretLength {
            length: secret.len(),
            max: config.max_secret_size
        }))
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
/// # use anyhow::Result;
/// # use ssss::{gen_shares, unlock, SsssConfig};
/// #
/// # pub fn main() -> Result<()> {
/// // Generate 5 shares from the given secret
/// let secret = "s3(r37".as_bytes();
/// let mut shares = gen_shares(&SsssConfig::default(), secret)?;
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
pub fn unlock<S: BuildHasher>(shares: &HashMap<u8, Vec<u8>, S>) -> Result<Vec<u8>> {
    let secret_len = validate_join_args(shares)?;
    let mut secret = vec![];

    for i in 0..secret_len {
        let mut points = vec![vec![0; 2]; shares.len()];
        for (idx, (k, v)) in shares.iter().enumerate() {
            points[idx][0] = *k;
            points[idx][1] = v[i];
        }
        secret.push(gf256::interpolate(&points));
    }

    Ok(secret)
}

fn validate_join_args<S: BuildHasher>(shares: &HashMap<u8, Vec<u8>, S>) -> Result<usize> {
    if shares.is_empty() {
        Err(anyhow!(EmptySharesMap))
    } else {
        let lengths: Vec<usize> = shares.values().map(Vec::len).collect();
        let len = lengths[0];
        if len == 0 {
            Err(anyhow!(EmptyShare))
        } else if lengths.iter().all(|x| *x == len) {
            Ok(len)
        } else {
            Err(anyhow!(ShareLengthMismatch))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{gen_shares, unlock, SsssConfig};
    use crate::utils::{check_err_result, remove_random_entry};
    use anyhow::Result;
    use rand::thread_rng;
    use std::collections::{hash_map::RandomState, HashMap};

    #[test]
    fn empty_secret() -> Result<()> {
        let config = SsssConfig::default();
        let result = gen_shares(&config, &[]);
        check_err_result(result, "The secret cannot be empty")
    }

    #[test]
    fn max_secret() -> Result<()> {
        let mut config = SsssConfig::default();
        let _ = config.set_max_secret_size(3);
        let result = gen_shares(&config, "abcd".as_bytes());
        check_err_result(
            result,
            "The secret length \'4\' is longer than the maximum allowed \'3\'",
        )
    }

    #[test]
    fn zero_parts() -> Result<()> {
        let mut config = SsssConfig::default();
        let _ = config.set_num_shares(0);
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(result, "The number of shares must be greater than 0")
    }

    #[test]
    fn zero_threshold() -> Result<()> {
        let mut config = SsssConfig::default();
        let _ = config.set_threshold(0);
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(result, "The threshold must be greater than 0")
    }

    #[test]
    fn threshold_greater_than_parts() -> Result<()> {
        let mut config = SsssConfig::default();
        let _ = config.set_threshold(6);
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(
            result,
            "You have specified an invalid threshold.  It must be more than the number of shares. (6 <= 5)",
        )
    }

    #[test]
    fn empty_share_map() -> Result<()> {
        let s = RandomState::new();
        let hm = HashMap::with_hasher(s);
        let result = unlock(&hm);
        check_err_result(result, "The shares map cannot be empty")
    }

    #[test]
    fn shares_of_differing_lengths() -> Result<()> {
        let mut bad_shares: HashMap<u8, Vec<u8>, RandomState> = HashMap::default();
        let _unused = bad_shares.insert(1, "abc".as_bytes().to_vec());
        let _unused = bad_shares.insert(2, "ab".as_bytes().to_vec());

        let result = unlock(&bad_shares);
        check_err_result(result, "The shares must be the same length")
    }

    #[test]
    fn empty_shares() -> Result<()> {
        let mut bad_shares: HashMap<u8, Vec<u8>, RandomState> = HashMap::default();
        let _unused = bad_shares.insert(1, vec![]);
        let _unused = bad_shares.insert(2, vec![]);

        let result = unlock(&bad_shares);
        check_err_result(result, "A share cannot be empty")
    }

    #[test]
    fn too_many_shares() -> Result<()> {
        let config = SsssConfig::default();
        let secret = "abc".as_bytes();
        let mut shares = gen_shares(&config, secret)?;
        let _unused = shares.insert(6, vec![55, 43, 22]);
        let _unused = shares.insert(7, vec![33, 23, 112]);
        let _unused = shares.insert(8, vec![121, 23, 76]);
        let unlocked = unlock(&shares)?;
        assert_ne!(unlocked, secret);
        Ok(())
    }

    #[test]
    fn split_and_join() -> Result<()> {
        let secret = "correct horse battery staple".as_bytes();
        let config = SsssConfig::default();
        let shares = gen_shares(&config, secret)?;

        // 5 parts should work
        let mut parts = shares;
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
