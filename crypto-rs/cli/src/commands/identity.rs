//! `frappuccino-cli identity` — derive and print an archive identity.
//!
//! Non-networked, read-only. Useful to:
//!   * verify a phrase matches the fingerprint printed at onboarding time,
//!   * dump the public keys before handing a phrase to an archive tool,
//!   * sanity-check a paper backup during drills.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_core::identity::ArchiveIdentity;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// BIP-39 mnemonic (12 words, French wordlist). Prompted on stderr if
    /// omitted. The CLI-flag form logs a warning — prefer the prompt.
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Optional passphrase (plausible-deniability 13th word). Empty if
    /// omitted on both the flag and the prompt.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Emit a one-line JSON object instead of the human-readable block.
    /// Stable shape: `{ed25519_pk, x25519_pk, fingerprint}`.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let mnemonic = crate::resolve_mnemonic(args.mnemonic.as_deref())?;
    let passphrase = crate::resolve_passphrase(args.passphrase.as_deref(), true)?;

    let archive = ArchiveIdentity::from_mnemonic(&mnemonic, &passphrase)
        .context("derive ArchiveIdentity from mnemonic")?;
    let id = archive.identity();

    let ed25519_hex = hex::encode(id.ed25519_pk());
    let x25519_hex = hex::encode(id.x25519_pk());
    let fingerprint = id.readable_fingerprint();

    if args.json {
        let obj = serde_json::json!({
            "ed25519_pk": ed25519_hex,
            "x25519_pk": x25519_hex,
            "fingerprint": fingerprint,
        });
        println!("{obj}");
    } else {
        println!("ed25519_pk   {ed25519_hex}");
        println!("x25519_pk    {x25519_hex}");
        println!("fingerprint  {fingerprint}");
    }
    Ok(())
}
