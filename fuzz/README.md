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

## Continuous fuzzing

The `🐛 Fuzz 🐛` workflow (`.github/workflows/fuzz.yml`) runs on every push/PR and
nightly. The `fuzz-smoke` job fuzzes each target for 30 seconds in a parallel
matrix; if a target crashes, the offending inputs under
`fuzz/artifacts/<target>/` are uploaded as a `fuzz-crash-<target>-<run_id>`
workflow artifact. The `fuzz-regression` job runs the regression tests (below).

### Reproducing a CI crash locally

1. Open the failed Actions run and download the
   `fuzz-crash-<target>-<run_id>` artifact.
2. Drop the extracted `crash-*` file into `fuzz/artifacts/<target>/`.
3. Reproduce it against the same target:

   ```bash
   cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
   ```

Fix the underlying bug, then lock it in with a regression test.

## Regression tests

`fuzz_targets/regression_*.rs` are plain `cargo test` targets (declared as
`[[test]]` in `Cargo.toml`) that replay previously-found crash inputs so fixed
bugs stay fixed. They build without libFuzzer instrumentation:

```bash
cd fuzz && cargo test
```

They also run in CI via the `fuzz-regression` job. To add a new case, embed the
artifact bytes and replay them through a helper that mirrors the fuzz target
body:

- **`&[u8]` targets** (e.g. `gen_shares`): pass the bytes straight to the body.
- **`Arbitrary`-typed targets** (e.g. `unlock`, `config`, `roundtrip`): decode the
  raw libFuzzer input with `Arbitrary::arbitrary_take_rest` — exactly how
  `libfuzzer-sys` feeds the target — so the bytes reproduce the same input. See
  `fuzz_targets/regression_unlock.rs` for the pattern.
