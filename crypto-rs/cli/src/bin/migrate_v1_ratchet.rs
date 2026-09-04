//! `migrate-v1-ratchet` — one-shot CLI to migrate a legacy V1 ratchet blob
//! (4844 bytes, no MAC) into the current V2 format (4876 bytes,
//! HMAC-authenticated). Created as part of RT-03 closure (Phase 4.1.4 of
//! `ROADMAP.md`): the runtime [`EphemeralRatchet::deserialize`] rejects V1
//! outright; this tool is the only audited path that still reads V1.
//!
//! **Inputs are PIN-sealed on disk** — neither the V1 nor the V2 payload
//! ever lives unencrypted on disk during the migration. The flow is:
//!
//! ```text
//!   read sealed_v1 file
//!     -> pin_store::open(pin, sealed_v1)   -> plain_v1 (Zeroizing)
//!     -> EphemeralRatchet::migrate_from_v1(plain_v1)
//!     -> ratchet.serialize()               -> plain_v2 (Vec<u8>)
//!     -> pin_store::seal(pin, plain_v2)    -> sealed_v2
//!   write sealed_v2 file
//! ```
//!
//! Usage:
//!
//! ```text
//!   frappuccino-migrate-v1-ratchet \
//!     --in  /opt/frappuccino/state/ratchet.v1.sealed \
//!     --out /opt/frappuccino/state/ratchet.v2.sealed \
//!     --pin 123456
//! ```
//!
//! Errors are surfaced to stderr; exit code 1 on any failure. The output
//! file is only written if the full migration round-trip succeeds — a
//! crash mid-flight leaves the V1 file untouched.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use frappuccino_crypto_core::pin_store;
use frappuccino_crypto_core::ratchet::EphemeralRatchet;

#[derive(Parser, Debug)]
#[command(
    name = "frappuccino-migrate-v1-ratchet",
    about = "Migrate a PIN-sealed V1 ratchet blob to V2 (RT-03)."
)]
struct Args {
    /// Path to the PIN-sealed V1 input file.
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,

    /// Path to write the PIN-sealed V2 output file.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,

    /// PIN that protects both the input and the output.
    #[arg(long)]
    pin: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.out.exists() {
        eprintln!(
            "error: output path already exists ({}). \
             Refusing to overwrite — move or delete it first.",
            args.out.display()
        );
        return ExitCode::FAILURE;
    }

    let sealed_v1 = match fs::read(&args.r#in) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.r#in.display());
            return ExitCode::FAILURE;
        }
    };

    // Phase 6.1.4-A : pin_store::open accepte maintenant &[u8]. args.pin
    // est une String CLI argument, on le convertit en bytes.
    let plain_v1 = match pin_store::open(args.pin.as_bytes(), &sealed_v1) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: PIN unseal failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let ratchet = match EphemeralRatchet::migrate_from_v1(&plain_v1) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "error: migrate_from_v1 failed (input is not a V1 blob \
                 or has wrong size): {e:?}"
            );
            return ExitCode::FAILURE;
        }
    };

    let plain_v2 = match ratchet.serialize() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: V2 serialize failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let sealed_v2 = match pin_store::seal(args.pin.as_bytes(), &plain_v2) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: PIN seal V2 failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = fs::write(&args.out, &sealed_v2) {
        eprintln!("error: write {}: {e}", args.out.display());
        return ExitCode::FAILURE;
    }

    eprintln!(
        "ok: migrated {} ({} bytes) → {} ({} bytes)",
        args.r#in.display(),
        sealed_v1.len(),
        args.out.display(),
        sealed_v2.len()
    );
    ExitCode::SUCCESS
}
