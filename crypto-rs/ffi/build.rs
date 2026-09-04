//! Generate `UniFFI` scaffolding from the UDL file at build time.
//! The resulting Rust code is injected into `lib.rs` via `uniffi::include_scaffolding!`.

fn main() {
    uniffi::generate_scaffolding("src/frappuccino.udl")
        .expect("UniFFI scaffolding generation failed");
    println!("cargo:rerun-if-changed=src/frappuccino.udl");
}
