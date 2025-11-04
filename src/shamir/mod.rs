// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` Shamir's Secret Sharing Scheme

mod utils;

use self::utils::{decode_share, encode_share, transpose};
use crate::{
    error::SsssError::{
        EmptySecret, EmptyShare, EmptySharesMap, SecretLength, ShareLengthMismatch, SharesZero,
        ThresholdToLow, ThresholdZero,
    },
    gf256,
};
use anyhow::Result;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bon::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration used to drive the [`gen_shares`] function.
///
/// # Notes
/// The default configuration will specify 5 shares with a
/// threshold of 3.  The maximum secret size is [`u16::MAX`] (65536)
#[derive(Builder, Clone, Copy, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct SsssConfig {
    /// The total shares to be generate from a secret
    #[builder(default = 5)]
    num_shares: u8,
    /// The threshold of valid shares required to unlock a secret
    /// This must be less than or equal to the number of shares
    #[builder(default = 3)]
    threshold: u8,
    /// The maximum secret size in bytes
    #[builder(default = usize::from(u16::MAX))]
    max_secret_size: usize,
}

impl Default for SsssConfig {
    fn default() -> Self {
        SsssConfig::builder().build()
    }
}

impl SsssConfig {
    fn validate(&self) -> Result<()> {
        if self.num_shares == 0 {
            Err(SharesZero.into())
        } else if self.threshold == 0 {
            Err(ThresholdZero.into())
        } else if self.threshold > self.num_shares {
            Err(ThresholdToLow {
                threshold: self.threshold,
                shares: self.num_shares,
            }
            .into())
        } else {
            Ok(())
        }
    }
}

/// Generate shares based on the `num_shares` and `threshold` given in the configuration.
///
/// Using the default [`SsssConfig`] will generate 5 shares of which 3 are required to unlock the secret.
///
/// # Errors
/// * This function will generate an error if `secret` is empty or larger than `max_secret_size` in the configuration.
/// * This function will generate an error if either `num_shares` or `threshold` are 0.
/// * This function will generate an error if `threshold` is greater than `num_shares`
///
/// # Example
/// ```
/// # use anyhow::Result;
/// # use ssss::{gen_shares, unlock, SsssConfig};
/// #
/// # pub fn main() -> Result<()> {
/// // Generate 5 shares from the given secret
/// let secret = "correct horse battery staple".as_bytes();
/// let config = SsssConfig::default();
///
/// // Generate 5 shares to be distributed, requiring a minimum of 3 later
/// // to unlock the secret
/// let mut shares = gen_shares(&config, &secret)?;
/// assert_eq!(shares.len(), 5);
///
/// # Ok(())
/// # }
pub fn gen_shares(config: &SsssConfig, secret: &[u8]) -> Result<Vec<String>> {
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
        .map(encode_share)
        .filter_map(Result::ok)
        .collect())
}

fn validate_split_args(config: &SsssConfig, secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        Err(EmptySecret.into())
    } else if secret.len() > config.max_secret_size {
        Err(SecretLength {
            length: secret.len(),
            max: config.max_secret_size,
        }
        .into())
    } else {
        config.validate()
    }
}

/// Attempt to unlock the secret given some [`shares`](gen_shares).
///
/// # Notes
/// * If there aren't enough shares to meet the threshold defined when
///   the shares were created the resulting vector of bytes will be gibberish.
/// * If there are more shares supplied than were defined when the shares
///   were created the resulting vector of bytes will be gibberish.
///
/// # Errors
/// * This function will generate an error if the `shares` map is empty.
/// * This function will generate an error if the `shares` within the map are not
///   all the same length.
///
/// # Example
/// ```
/// # use anyhow::Result;
/// # use rand::{thread_rng, rngs::ThreadRng};
/// # use ssss::{gen_shares, unlock, remove_random_entry, SsssConfig};
/// #
/// # pub fn main() -> Result<()> {
/// // Generate 5 shares from the given secret
/// let secret = "correct horse battery staple".as_bytes();
/// let config = SsssConfig::default();
///
/// // Generate 5 shares to be distributed, requiring a minimum of 3 later
/// // to unlock the secret
/// let mut shares = gen_shares(&config, &secret)?;
///
/// // Check that all 5 shares can unlock the secret
/// assert_eq!(shares.len(), 5);
/// assert_eq!(unlock(&shares)?, secret);
///
/// // Remove a random share from `shares` and check that 4 shares can unlock
/// // the secret
/// let mut rng = thread_rng();
/// remove_random_entry(&mut rng, &mut shares);
/// assert_eq!(shares.len(), 4);
/// assert_eq!(unlock(&shares)?, secret);
///
/// // Remove another random share from `shares` and check that 3 shares can unlock
/// // the secret
/// remove_random_entry(&mut rng, &mut shares);
/// assert_eq!(shares.len(), 3);
/// assert_eq!(unlock(&shares)?, secret);
///
/// // Remove another random share from `shares` and check that 2 shares *CANNOT*
/// // unlock the secret
/// remove_random_entry(&mut rng, &mut shares);
/// assert_eq!(shares.len(), 2);
/// assert_ne!(unlock(&shares)?, secret);
/// # Ok(())
/// # }
pub fn unlock(shares: &[String]) -> Result<Vec<u8>> {
    let decoded = shares
        .iter()
        .cloned()
        .map(decode_share)
        .filter_map(Result::ok)
        .collect();
    let secret_len = validate_join_args(&decoded)?;
    let mut secret = vec![];

    for i in 0..secret_len {
        let mut points = vec![vec![0; 2]; decoded.len()];
        for (idx, (k, v)) in decoded.iter().enumerate() {
            points[idx][0] = *k;
            points[idx][1] = v[i];
        }
        secret.push(gf256::interpolate(&points));
    }

    Ok(secret)
}

fn validate_join_args(shares: &HashMap<u8, Vec<u8>>) -> Result<usize> {
    if shares.is_empty() {
        Err(EmptySharesMap.into())
    } else {
        let lengths: Vec<usize> = shares.values().map(Vec::len).collect();
        let len = lengths[0];
        if len == 0 {
            Err(EmptyShare.into())
        } else if lengths.iter().all(|x| *x == len) {
            Ok(len)
        } else {
            for (k, v) in shares {
                eprintln!("{k}: {v:?} => {}", v.len());
            }
            Err(ShareLengthMismatch.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{SsssConfig, gen_shares, unlock, utils::encode_share};
    use crate::utils::{check_err_result, remove_random_entry};
    use anyhow::Result;
    use rand::rng;

    #[test]
    fn empty_secret() -> Result<()> {
        let config = SsssConfig::default();
        let result = gen_shares(&config, &[]);
        check_err_result(result, "The secret cannot be empty")
    }

    #[test]
    fn max_secret() -> Result<()> {
        let config = SsssConfig::builder().max_secret_size(3).build();
        let result = gen_shares(&config, "abcd".as_bytes());
        check_err_result(
            result,
            "The secret length \'4\' is longer than the maximum allowed \'3\'",
        )
    }

    #[test]
    fn zero_parts() -> Result<()> {
        let config = SsssConfig::builder().num_shares(0).build();
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(result, "The number of shares must be greater than 0")
    }

    #[test]
    fn zero_threshold() -> Result<()> {
        let config = SsssConfig::builder().threshold(0).build();
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(result, "The threshold must be greater than 0")
    }

    #[test]
    fn threshold_greater_than_parts() -> Result<()> {
        let config = SsssConfig::builder().threshold(6).build();
        let result = gen_shares(&config, "a".as_bytes());
        check_err_result(
            result,
            "You have specified an invalid threshold.  It must be less than or equal to the number of shares. (6 is not <= 5)",
        )
    }

    #[test]
    fn empty_share_map() -> Result<()> {
        let result = unlock(&[]);
        check_err_result(result, "The shares map cannot be empty")
    }

    #[test]
    fn shares_of_differing_lengths() -> Result<()> {
        let bad_shares = vec![
            encode_share((1, "abc".as_bytes().to_vec()))?,
            encode_share((2, "abcdef".as_bytes().to_vec()))?,
        ];
        let result = unlock(&bad_shares);
        check_err_result(result, "The shares must be the same length")
    }

    #[test]
    fn empty_shares() -> Result<()> {
        let bad_shares = vec![encode_share((1, vec![]))?];
        let result = unlock(&bad_shares);
        check_err_result(result, "A share cannot be empty")
    }

    #[test]
    fn too_many_shares() -> Result<()> {
        let config = SsssConfig::default();
        let secret = "abc".as_bytes();
        let mut shares = gen_shares(&config, secret)?;
        shares.push(encode_share((6, "abc".as_bytes().to_vec()))?);
        shares.push(encode_share((7, "def".as_bytes().to_vec()))?);
        shares.push(encode_share((8, "ghi".as_bytes().to_vec()))?);
        assert_eq!(shares.len(), 8);
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
        let mut rng = rng();
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
