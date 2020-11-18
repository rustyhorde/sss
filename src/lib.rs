// Copyright (c) 2020 sss developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `sss`

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
    invalid_html_tags,
    invalid_value,
    irrefutable_let_patterns,
    keyword_idents,
    late_bound_lifetime_arguments,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_copy_implementations,
    missing_crate_level_docs,
    missing_debug_implementations,
    missing_doc_code_examples,
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

mod gf256;

use std::collections::HashMap;

/// Make some shares
pub fn split(secret: &[u8], parts: usize, threshold: usize) -> HashMap<usize, Vec<u8>> {
    let coeff_fn = |secret_byte: &u8| -> Vec<u8> { gf256::generate(threshold, *secret_byte) };
    let gf_add =
        |p: Vec<u8>| -> Vec<u8> { (1..=parts).map(|i| gf256::eval(&p, i as u8)).collect() };

    transpose(secret.iter().map(coeff_fn).map(gf_add).collect())
        .iter()
        .cloned()
        .enumerate()
        .map(inc_key)
        .collect()
}

fn inc_key(tuple: (usize, Vec<u8>)) -> (usize, Vec<u8>) {
    (tuple.0 + 1, tuple.1)
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>>
where
    T: Clone,
{
    if let Some(first) = v.get(0) {
        (0..first.len())
            .map(|i| v.iter().map(|inner| inner[i].clone()).collect::<Vec<T>>())
            .collect()
    } else {
        vec![]
    }
}

/// Join some shares
pub fn join(shares: &HashMap<usize, Vec<u8>>) -> Vec<u8> {
    if !shares.is_empty() {
        let lengths: Vec<usize> = shares.values().map(Vec::len).collect();
        let len = lengths[0];
        let mut secret = vec![];
        if lengths.iter().all(|x| *x == len) {
            for i in 0..lengths[0] {
                let mut points = vec![vec![0; 2]; shares.len()];
                let mut j = 0;
                for (k, v) in shares {
                    points[j][0] = *k as u8;
                    points[j][1] = v[i];
                    j += 1;
                }
                secret.push(gf256::interpolate(points));
            }
        }

        println!("Secret: {}", String::from_utf8_lossy(&secret));
        secret
    } else {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::{join, split};
    use rand::{rngs::ThreadRng, seq::IteratorRandom, thread_rng};
    use std::collections::HashMap;

    #[test]
    fn split_and_join() {
        let secret = "correct horst battery staple".as_bytes();
        let shares = split(&secret, 5, 3);

        // 5 parts should work
        let mut parts = shares.clone();
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 4 parts shoud work
        let mut rng = thread_rng();
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 3 parts should work
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_eq!(join(&parts), secret);

        // 2 parts should not
        let _ = choose_idx(&mut rng, &parts).and_then(|idx| parts.remove(&idx));
        print_parts(&parts);
        assert_ne!(join(&parts), secret);
    }

    fn choose_idx(rng: &mut ThreadRng, map: &HashMap<usize, Vec<u8>>) -> Option<usize> {
        map.clone().keys().choose(rng).cloned()
    }

    fn print_parts(map: &HashMap<usize, Vec<u8>>) {
        for (k, v) in map {
            println!("Key: {}, Value: {:?}", k, v);
        }
    }
}
