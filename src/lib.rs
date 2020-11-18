// Copyright (c) 2020 sss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `sss` A [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) implementation in Rust
//!
//! # Example
//!
//! ```rust
//! # use rand::{thread_rng, rngs::ThreadRng, seq::IteratorRandom};
//! # use sss::{join, split, Error};
//! # use std::{collections::HashMap};
//! #
//! # fn main() -> Result<(), Error> {
//! let secret = "correct horse battery staple".as_bytes();
//! // Generate 5 shares to be distributed, requiring a minimum of 3 later
//! // to reconstruct the secret
//! let shares = split(&secret, 5, 3)?;
//!
//! // Check that all 5 shares can reconstruct the secret
//! let mut shares_to_join = shares.clone();
//! assert_eq!(join(&shares_to_join), secret);
//!
//! // Remove a random share from `shares_to_join` and check that 4 shares can reconstruct
//! // the secret
//! let mut rng = thread_rng();
//! let _ = choose_idx(&mut rng, &shares_to_join).and_then(|idx| shares_to_join.remove(&idx));
//! assert_eq!(join(&shares_to_join), secret);
//!
//! // Remove another random share from `shares_to_join` and check that 3 shares can reconstruct
//! // the secret
//! let _ = choose_idx(&mut rng, &shares_to_join).and_then(|idx| shares_to_join.remove(&idx));
//! assert_eq!(join(&shares_to_join), secret);
//!
//! // Remove another random share from `shares_to_join` and check that 2 shares *CANNOT*
//! // reconstruct the secret
//! let _ = choose_idx(&mut rng, &shares_to_join).and_then(|idx| shares_to_join.remove(&idx));
//! assert_ne!(join(&shares_to_join), secret);
//! #
//! # Ok(())
//! # }
//!
//! fn choose_idx(rng: &mut ThreadRng, map: &HashMap<u8, Vec<u8>>) -> Option<u8> {
//!     map.clone().keys().choose(rng).cloned()
//! }
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
    private_doc_tests,
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

pub use error::ErrCode;
pub use error::Error;
pub use shamir::join;
pub use shamir::split;
