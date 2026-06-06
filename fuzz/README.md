# Fuzzing `ssss`

This directory holds the [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
harness for the `ssss` crate. The targets exercise the public API
(`gen_shares`, `unlock`, `SsssConfig`) with libFuzzer-driven, `arbitrary`-derived
inputs.

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

`cargo-fuzz` requires a nightly toolchain. The fuzz crate is a separate,
non-workspace member and builds the parent crate with its `fuzz` feature enabled
(which derives `arbitrary::Arbitrary` on `SsssConfig`).

## Targets

| Target       | Input                     | What it checks |
| ------------ | ------------------------- | -------------- |
| `config`     | `SsssConfig`              | `gen_shares` never panics for an arbitrary config (fixed secret). |
| `gen_shares` | `&[u8]`                   | `gen_shares` never panics for an arbitrary secret (default config). |
| `unlock`     | `Vec<String>`             | `unlock` never panics for arbitrary, possibly-malformed share strings. |
| `roundtrip`  | `(SsssConfig, Vec<u8>)`   | Property test: whenever `gen_shares` succeeds, unlocking all shares reconstructs the original secret. |

## Running

```bash
# List the available targets
cargo +nightly fuzz list

# Build every target (CI runs this to catch API drift)
cargo +nightly fuzz build

# Fuzz a single target indefinitely
cargo +nightly fuzz run roundtrip

# Bounded smoke run (e.g. 30 seconds)
cargo +nightly fuzz run roundtrip -- -max_total_time=30
```

Crashing inputs are written to `fuzz/artifacts/<target>/`; the evolving corpus
lives in `fuzz/corpus/<target>/`. Both directories are git-ignored.
