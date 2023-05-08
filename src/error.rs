// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `ssss` Errors

#[derive(thiserror::Error, Debug)]
#[allow(variant_size_differences)]
pub(crate) enum SsssError {
    #[error("The threshold must be greater than 0")]
    ThresholdZero,
    #[error("The number of shares must be greater than 0")]
    SharesZero,
    #[error("You have specified an invalid threshold.  It must be less than or equal to the number of shares. ({} is not <= {})", threshold, shares)]
    ThresholdToLow { threshold: u8, shares: u8 },
    #[error("The secret cannot be empty")]
    EmptySecret,
    #[error(
        "The secret length '{}' is longer than the maximum allowed '{}'",
        length,
        max
    )]
    SecretLength { length: usize, max: usize },
    #[error("The shares map cannot be empty")]
    EmptySharesMap,
    #[error("A share cannot be empty")]
    EmptyShare,
    #[error("The shares must be the same length")]
    ShareLengthMismatch,
}
