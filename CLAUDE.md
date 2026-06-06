# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`ssss` is a Rust library crate implementing [Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). A secret (`&[u8]`) is split into `num_shares` encoded string shares; any `threshold` of them reconstructs the secret. Fewer than `threshold` shares (or more shares than were generated) yields gibberish rather than an error.

The public API is small and re-exported from `src/lib.rs`: `gen_shares`, `unlock`, `remove_random_entry`, and `SsssConfig` (built via the `bon` builder; default = 5 shares, threshold 3, max secret 65535 bytes).

## Commands

```bash
cargo build
cargo test                       # all unit tests (tests live in #[cfg(test)] modules)
cargo test split_and_join        # run a single test by name
cargo doc --no-deps --open       # doctests in lib.rs / shamir are the primary API examples

# Lints — CI runs clippy on nightly with pedantic; match that locally:
cargo +nightly clippy --all-features -- -D warnings
cargo +nightly fmt

# Fuzzing (requires `cargo install cargo-fuzz`, nightly toolchain):
cargo +nightly fuzz run gen_shares   # targets: config, gen_shares, unlock (see fuzz/)
```

MSRV is **1.85.1** (edition 2024). CI tests against 1.85.1/stable/beta/nightly across Linux, macOS, and Windows.

## Architecture

The crate is layered. Data flows: secret bytes → polynomial coefficients in GF(2⁸) → evaluated points → transposed per-share → base62-encoded strings; `unlock` reverses this via Lagrange interpolation.

- **`src/shamir/`** — the algorithm. `gen_shares` builds, per secret byte, a degree `threshold-1` polynomial whose constant term is the secret byte, evaluates it at `x = 1..=num_shares`, then `transpose`s so each share holds one point per byte. `unlock` decodes shares into a `HashMap<u8, Vec<u8>>` (key = share index `x`) and interpolates each byte position back. `src/shamir/utils.rs` holds `encode_share`/`decode_share` (the `"idx:data"` string format) and `transpose`.

- **`src/gf256/`** — all finite-field arithmetic over GF(2⁸). `add`/`sub` are XOR; `mul`/`div` use precomputed `LOG`/`EXP` tables in `constants.rs`. `generate_coeffs` produces random polynomial coefficients (re-rolling until the leading coefficient is non-zero so the degree is exact). `eval` is Horner's method; `interpolate` is Lagrange interpolation evaluated at `x = 0`.

- **`src/base62/`** — share encoding. `encode` prepends a random 10-byte nonce (first byte forced to `1`) so identical inputs produce different ciphertext, then converts the whole buffer through a `BigUint` into the 62-char alphabet. `decode` strips the nonce prefix. Uses `num-bigint`/`num-integer`/`num-traits`.

- **`src/error.rs`** — `SsssError` (`thiserror`). Validation lives in `validate_split_args`/`config.validate` (gen) and `validate_join_args` (unlock). The exact error message strings are asserted verbatim in tests via `check_err_result`, so changing a message requires updating its test.

- **`src/utils/mod.rs`** — `remove_random_entry` (public, used in examples/tests to drop shares) and the test-only `check_err_result` helper.

## Conventions

- **Lints are centralized and nightly-gated.** `src/lib.rs` carries a very large `#![cfg_attr(nightly, deny(...))]` block (hundreds of rustc lints) plus `clippy::all`/`clippy::pedantic` and rustdoc lints, all active only on nightly. The `unstable` feature additionally enables nightly-only feature lints. Do not scatter `#[allow]`/`#[deny]` attributes elsewhere unless locally necessary — and when you do allow, keep it narrow (see the existing `clippy::needless_pass_by_value` allows in `shamir/utils.rs`).
- `unsafe_code` is denied; this crate is `#![forbid]`-style safe Rust.
- The `fuzz` feature derives `arbitrary::Arbitrary` on `SsssConfig`; the `fuzz/` crate is a separate non-workspace member.
- Every source file starts with the dual MIT/Apache-2.0 license header.
- `build.rs` sets a `nightly` cfg flag (via `rustversion`) that gates the lint blocks above.
