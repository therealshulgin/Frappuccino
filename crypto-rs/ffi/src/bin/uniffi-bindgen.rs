//! `uniffi-bindgen` CLI — generates Kotlin (and later Swift, Python) bindings
//! from the `frappuccino.udl` file or from the compiled library.
//!
//! Usage (from crypto-rs/):
//!   cargo run --bin uniffi-bindgen -- \
//!       generate --library ../target/aarch64-linux-android/release/libfrappuccino_crypto_ffi.so \
//!       --language kotlin \
//!       --out-dir ../../mobile/build/generated/source/uniffi
//!
//! Or from the UDL file directly (host dev, no .so needed):
//!   cargo run --bin uniffi-bindgen -- \
//!       generate src/frappuccino.udl --language kotlin --out-dir <dir>

fn main() {
    uniffi::uniffi_bindgen_main();
}
