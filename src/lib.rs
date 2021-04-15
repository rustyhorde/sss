// Copyright (c) 2020 ssss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! # `ssss`
//! A [Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) implementation in Rust
//!
//! To quote the Wikipedia article linked above:
//!
//! >Shamir's Secret Sharing is used to secure a secret in a distributed way, most often to secure other encryption keys.
//! The secret is split into multiple parts, called shares. These shares are used to reconstruct the original secret.
//!
//! >To unlock the secret via Shamir's secret sharing, you need a minimum number of shares. This is called the threshold,
//! and is used to denote the minimum number of shares needed to unlock the secret. Let us walk through an example:
//!
//! >>Problem: Company XYZ needs to secure their vault's passcode. They could use something standard, such as AES, but what
//! if the holder of the key is unavailable or dies? What if the key is compromised via a malicious hacker or the holder
//! of the key turns rogue, and uses their power over the vault to their benefit?
//!
//! >This is where ssss comes in. It can be used to encrypt the vault's passcode and generate a certain number of shares,
//! where a certain number of shares can be allocated to each executive within Company XYZ. Now, only if they pool their
//! shares can they unlock the vault. The threshold can be appropriately set for the number of executives, so the vault
//! is always able to be accessed by the authorized individuals. Should a share or two fall into the wrong hands,
//! they couldn't open the passcode unless the other executives cooperated.
//!
//! # Example
//!
//! ```
//! # use anyhow::Result;
//! # use rand::{thread_rng, rngs::ThreadRng, seq::IteratorRandom};
//! # use ssss::{unlock, gen_shares, SsssConfig};
//! # use std::{collections::HashMap, hash::Hash};
//! #
//! # fn main() -> Result<()> {
//! let secret = "correct horse battery staple".as_bytes();
//! let config = SsssConfig::default();
//!
//! // Generate 5 shares to be distributed, requiring a minimum of 3 later
//! // to unlock the secret
//! let mut shares = gen_shares(&config, &secret)?;
//!
//! // Check that all 5 shares can unlock the secret
//! assert_eq!(shares.len(), 5);
//! assert_eq!(unlock(&shares)?, secret);
//!
//! // Remove a random share from `shares` and check that 4 shares can unlock
//! // the secret
//! let mut rng = thread_rng();
//! remove_random_entry(&mut rng, &mut shares);
//! assert_eq!(shares.len(), 4);
//! assert_eq!(unlock(&shares)?, secret);
//!
//! // Remove another random share from `shares` and check that 3 shares can unlock
//! // the secret
//! remove_random_entry(&mut rng, &mut shares);
//! assert_eq!(shares.len(), 3);
//! assert_eq!(unlock(&shares)?, secret);
//!
//! // Remove another random share from `shares` and check that 2 shares *CANNOT*
//! // unlock the secret
//! remove_random_entry(&mut rng, &mut shares);
//! assert_eq!(shares.len(), 2);
//! assert_ne!(unlock(&shares)?, secret);
//! #
//! # Ok(())
//! # }
//! #
//! # fn remove_random_entry<T, U>(rng: &mut ThreadRng, map: &mut HashMap<T, U>)
//! # where
//! #     T: Clone + Hash + Eq,
//! # {
//! #     let _ = choose_idx(rng, map).and_then(|idx| map.remove(&idx));
//! # }
//! #
//! # fn choose_idx<T, U>(rng: &mut ThreadRng, map: &HashMap<T, U>) -> Option<T>
//! # where
//! #     T: Clone,
//! # {
//! #     map.clone().keys().choose(rng).cloned()
//! # }
//! ```
//!
// rustc lints
#![deny(
    absolute_paths_not_starting_with_crate,
    anonymous_parameters,
    array_into_iter,
    asm_sub_register,
    bare_trait_objects,
    bindings_with_variant_name,
    box_pointers,
    cenum_impl_drop_cast,
    clashing_extern_declarations,
    coherence_leak_check,
    confusable_idents,
    const_evaluatable_unchecked,
    const_item_mutation,
    dead_code,
    deprecated,
    deprecated_in_future,
    drop_bounds,
    elided_lifetimes_in_paths,
    ellipsis_inclusive_range_patterns,
    explicit_outlives_requirements,
    exported_private_dependencies,
    forbidden_lint_groups,
    function_item_references,
    illegal_floating_point_literal_pattern,
    improper_ctypes,
    improper_ctypes_definitions,
    incomplete_features,
    indirect_structural_match,
    inline_no_sanitize,
    invalid_value,
    irrefutable_let_patterns,
    keyword_idents,
    late_bound_lifetime_arguments,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_abi,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    mixed_script_confusables,
    mutable_borrow_reservation_conflict,
    no_mangle_generic_items,
    non_ascii_idents,
    non_camel_case_types,
    non_fmt_panic,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    nontrivial_structural_match,
    overlapping_range_endpoints,
    path_statements,
    pointer_structural_match,
    private_in_public,
    proc_macro_derive_resolution_fallback,
    redundant_semicolons,
    renamed_and_removed_lints,
    semicolon_in_expressions_from_macros,
    single_use_lifetimes,
    stable_features,
    temporary_cstring_as_ptr,
    trivial_bounds,
    trivial_casts,
    trivial_numeric_casts,
    type_alias_bounds,
    tyvar_behind_raw_pointer,
    unaligned_references,
    uncommon_codepoints,
    unconditional_recursion,
    uninhabited_static,
    unknown_lints,
    unnameable_test_items,
    unreachable_code,
    unreachable_patterns,
    unreachable_pub,
    unsafe_code,
    unstable_features,
    unstable_name_collisions,
    unsupported_naked_functions,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_braces,
    unused_comparisons,
    unused_crate_dependencies,
    unused_doc_comments,
    unused_extern_crates,
    unused_features,
    unused_import_braces,
    unused_imports,
    unused_labels,
    unused_lifetimes,
    unused_macros,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_qualifications,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    where_clauses_object_safety,
    while_true
)]
// nightly only lints
#![cfg_attr(
    nightly_lints,
    deny(disjoint_capture_drop_reorder, or_patterns_back_compat)
)]
// nightly or beta only lints
#![cfg_attr(
    any(beta_lints, nightly_lints),
    deny(
        legacy_derive_helpers,
        noop_method_call,
        proc_macro_back_compat,
        unsafe_op_in_unsafe_fn,
        unaligned_references,
    )
)]
// beta or stable only lints
#![cfg_attr(any(beta_lints, stable_lints), deny(safe_packed_borrows))]
// stable only lints
#![cfg_attr(
    stable_lints,
    deny(
        broken_intra_doc_links,
        invalid_codeblock_attributes,
        invalid_html_tags,
        missing_crate_level_docs,
        missing_doc_code_examples,
        non_autolinks,
        // private_doc_tests,
        private_intra_doc_links,
    )
)]
// clippy lints
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::clippy::default_trait_access)]
// rustdoc lints
#![cfg_attr(
    any(nightly_lints, beta_lints),
    deny(
        rustdoc::broken_intra_doc_links,
        rustdoc::invalid_codeblock_attributes,
        rustdoc::invalid_html_tags,
        rustdoc::missing_crate_level_docs,
        rustdoc::missing_doc_code_examples,
        // rustdoc::private_doc_tests,
        rustdoc::private_intra_doc_links,
    )
)]
#![cfg_attr(beta_lints, deny(rustdoc::non_autolinks))]
#![cfg_attr(nightly_lints, deny(rustdoc::bare_urls))]

mod error;
mod gf256;
mod shamir;
#[cfg(test)]
mod utils;
#[cfg(all(feature = "arbitrary", not(feature = "fuzz")))]
use arbitrary as _;

pub use shamir::gen_shares;
pub use shamir::unlock;
pub use shamir::SsssConfig;
