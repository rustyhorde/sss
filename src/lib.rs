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
//! # use rand::{thread_rng, rngs::ThreadRng, seq::IteratorRandom};
//! # use ssss::{unlock, gen_shares, Error, SSSSConfig};
//! # use std::{collections::HashMap, hash::Hash};
//! #
//! # fn main() -> Result<(), Error> {
//! let secret = "correct horse battery staple".as_bytes();
//! let config = SSSSConfig::default();
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
//! # let _ = choose_idx(rng, map).and_then(|idx| map.remove(&idx));
//! # }
//! #
//! # fn choose_idx<T, U>(rng: &mut ThreadRng, map: &HashMap<T, U>) -> Option<T>
//! # where
//! #     T: Clone,
//! # {
//! # map.clone().keys().choose(rng).cloned()
//! # }
//! ```
//!
#![feature(crate_visibility_modifier, error_iter)]
#![deny(
    absolute_paths_not_starting_with_crate,
    anonymous_parameters,
    array_into_iter,
    asm_sub_register,
    bare_trait_objects,
    bindings_with_variant_name,
    box_pointers,
    broken_intra_doc_links,
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
    illegal_floating_point_literal_pattern,
    improper_ctypes,
    improper_ctypes_definitions,
    incomplete_features,
    indirect_structural_match,
    inline_no_sanitize,
    invalid_codeblock_attributes,
    // invalid_html_tags,
    invalid_value,
    irrefutable_let_patterns,
    keyword_idents,
    late_bound_lifetime_arguments,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_copy_implementations,
    missing_crate_level_docs,
    missing_debug_implementations,
    // missing_doc_code_examples,
    missing_docs,
    mixed_script_confusables,
    mutable_borrow_reservation_conflict,
    no_mangle_generic_items,
    non_ascii_idents,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    nontrivial_structural_match,
    overlapping_patterns,
    path_statements,
    pointer_structural_match,
    // private_doc_tests,
    private_in_public,
    proc_macro_derive_resolution_fallback,
    redundant_semicolons,
    renamed_and_removed_lints,
    safe_packed_borrows,
    single_use_lifetimes,
    stable_features,
    trivial_bounds,
    trivial_casts,
    trivial_numeric_casts,
    type_alias_bounds,
    tyvar_behind_raw_pointer,
    unaligned_references,
    uncommon_codepoints,
    unconditional_recursion,
    unknown_lints,
    unnameable_test_items,
    unreachable_code,
    unreachable_patterns,
    unreachable_pub,
    unsafe_code,
    // unsafe_op_in_unsafe_fn,
    // unstable_features,
    unstable_name_collisions,
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
    while_true,
)]

mod error;
mod gf256;
mod shamir;
#[cfg(test)]
mod utils;

pub use error::Error;
pub use shamir::gen_shares;
pub use shamir::unlock;
pub use shamir::SSSSConfig;
