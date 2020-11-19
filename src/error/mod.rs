// Copyright (c) 2020 sss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `sss` errors

mod codes;
mod sources;

crate use codes::ErrCode;
crate use sources::ErrSource;

use getset::Getters;
use serde_derive::{Deserialize, Serialize};
use std::fmt;

/// A result that must include an `crate::error::Error`
crate type Result<T> = std::result::Result<T, Error>;

/// An error from the library
#[derive(Debug, Deserialize, Getters, Serialize)]
#[get = "crate"]
pub struct Error {
    /// the code
    code: ErrCode,
    /// the reason
    reason: String,
    /// the source
    #[serde(skip)]
    source: Option<ErrSource>,
}

impl Error {
    /// Create a new error
    crate fn new<U>(code: ErrCode, reason: U, source: Option<ErrSource>) -> Self
    where
        U: Into<String>,
    {
        let reason = reason.into();

        Self {
            code,
            reason,
            source,
        }
    }

    crate fn secret_empty() -> Self {
        Self::new(ErrCode::Protocol, "The given secret cannot be empty", None)
    }

    crate fn max_secret_len() -> Self {
        Self::new(
            ErrCode::Protocol,
            "The maximum secret length has been exceeded",
            None,
        )
    }

    crate fn zero_p_or_t() -> Self {
        Self::new(
            ErrCode::Protocol,
            "The parts and threshold arguments cannot be 0",
            None,
        )
    }

    crate fn invalid_threshold() -> Self {
        Self::new(
            ErrCode::Protocol,
            "The threshold argument must be less than or equal to the parts argument",
            None,
        )
    }

    crate fn shares_map_empty() -> Self {
        Self::new(
            ErrCode::Protocol,
            "The given shares map cannot be empty",
            None,
        )
    }

    crate fn shares_empty() -> Self {
        Self::new(ErrCode::Protocol, "The given shares cannot be empty", None)
    }

    crate fn share_length_mismatch() -> Self {
        Self::new(
            ErrCode::Protocol,
            "The given shares have differing lengths",
            None,
        )
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(ref x) = self.source {
            Some(x)
        } else {
            None
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err: &(dyn std::error::Error) = self;
        let mut iter = err.chain();
        let _skip_me = iter.next();
        write!(f, "{}: {}", self.code, self.reason)?;

        for e in iter {
            writeln!(f)?;
            write!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl From<&str> for Error {
    fn from(text: &str) -> Self {
        let split = text.split(':');
        let vec = split.collect::<Vec<&str>>();
        let code = vec.get(0).unwrap_or_else(|| &"");
        let reason = vec.get(1).unwrap_or_else(|| &"");
        Self::new((*code).into(), *reason, None)
    }
}

impl From<String> for Error {
    fn from(text: String) -> Self {
        let split = text.split(':');
        let vec = split.collect::<Vec<&str>>();
        let code = vec.get(0).unwrap_or_else(|| &"");
        let reason = vec.get(1).unwrap_or_else(|| &"");
        Self::new((*code).into(), *reason, None)
    }
}
