fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    nightly_lints();
    beta_lints();
    stable_lints();
}

#[rustversion::nightly]
fn nightly_lints() {
    println!("cargo:rustc-cfg=nightly_lints");
}

#[rustversion::not(nightly)]
fn nightly_lints() {}

#[rustversion::beta]
fn beta_lints() {
    println!("cargo:rustc-cfg=beta_lints");
}

#[rustversion::not(beta)]
fn beta_lints() {}

#[rustversion::stable]
fn stable_lints() {
    println!("cargo:rustc-cfg=stable_lints");
}

#[rustversion::not(stable)]
fn stable_lints() {}
