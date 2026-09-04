//! `frappuccino-cli decrypt` — decrypt (or inspect) a STRM blob.
//!
//! Offline replacement for `server-tools/stream_decrypt.py`:
//!   * `--inspect` : parse the header (magic, version, mode, `author_pk`
//!     [legacy V1/V2 only — V3 carries none], `grant_count`), print as
//!     human-readable or JSON. No mnemonic required.
//!   * default   : require a mnemonic + optional passphrase, decrypt the
//!     blob, write the plaintext to `--output` or stdout.
//!
//! The blob path `-` reads from stdin.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_core::bip39::{validate as bip39_validate, Language};
use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::decrypt::decrypt;
use frappuccino_crypto_stream::header::parse_header;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// STRM blob path. Use `-` to read from stdin.
    pub blob: PathBuf,

    /// Parse the header and print metadata without decrypting.
    /// When set, `--mnemonic` is ignored.
    #[arg(long)]
    pub inspect: bool,

    /// BIP-39 mnemonic. Prompted on stderr if omitted (unless `--inspect`).
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Optional passphrase.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Write plaintext to this file instead of stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Emit the `--inspect` output as one-line JSON. No effect outside of
    /// `--inspect`.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let blob = crate::read_blob(&args.blob)?;
    if args.inspect {
        return inspect(&blob, args.json);
    }

    let mnemonic = crate::resolve_mnemonic(args.mnemonic.as_deref())?;
    let passphrase = crate::resolve_passphrase(args.passphrase.as_deref(), true)?;

    // R-CR-2 (audit 2026-06-26) — defense-in-depth: gate the BIP-39 checksum
    // before deriving. `ArchiveIdentity::from_mnemonic` calls `mnemonic_to_seed`,
    // which only checks that each word is known, not the 4-bit checksum; a
    // mistyped-but-valid phrase would derive a different X25519 key and the
    // decrypt would fail with a generic WrongPin. Validating up front turns
    // that into a clear "wrong word or checksum" error (mirrors the Android
    // archive-restore gate in ArchiveModeActivity.kt).
    bip39_validate(&mnemonic, Language::French)
        .context("BIP-39 mnemonic invalid (wrong word or checksum mismatch)")?;

    let archive = ArchiveIdentity::from_mnemonic(&mnemonic, &passphrase)
        .context("derive ArchiveIdentity from mnemonic")?;

    let (plaintext, meta) = decrypt(&blob, &archive).context("STRM decrypt")?;

    if let Some(path) = &args.output {
        fs::write(path, &plaintext[..])
            .with_context(|| format!("write plaintext to {}", path.display()))?;
        eprintln!(
            "decrypted {} bytes (mode={}, version={}) → {}",
            meta.plaintext_len,
            mode_label(meta.mode),
            meta.version,
            path.display()
        );
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&plaintext[..])
            .context("write plaintext to stdout")?;
        stdout.flush().ok();
        eprintln!(
            "decrypted {} bytes (mode={}, version={})",
            meta.plaintext_len,
            mode_label(meta.mode),
            meta.version
        );
    }
    Ok(())
}

fn inspect(blob: &[u8], as_json: bool) -> Result<()> {
    // Single source of truth for the byte layout: `parse_header` resolves the
    // version-specific offsets (V3 has no author key; V1/V2 do). No mnemonic
    // or secret is involved.
    let parsed = parse_header(blob).context("parse STRM header")?;
    let header_size = parsed.header_end;
    let body_len = blob.len() - parsed.body_start;
    // `Some(hex)` for legacy V1/V2 blobs, `None` for V3 (no identity at rest).
    let author_hex = parsed.author_ed25519_pk.map(hex::encode);

    if as_json {
        let obj = serde_json::json!({
            "magic": "STRM",
            "version": parsed.version,
            "mode": parsed.mode,
            "mode_label": mode_label(parsed.mode),
            "author_ed25519_pk": author_hex, // null for V3
            "grant_count": parsed.grant_count,
            "blob_size": blob.len(),
            "header_size": header_size,
            "body_size": body_len,
        });
        println!("{obj}");
    } else {
        println!("magic            STRM");
        println!("version          0x{:02x}", parsed.version);
        println!(
            "mode             0x{:02x} ({})",
            parsed.mode,
            mode_label(parsed.mode)
        );
        match &author_hex {
            Some(h) => println!("author_pk        {h}"),
            None => println!("author_pk        (none — V3 carries no identity at rest)"),
        }
        println!("grant_count      {}", parsed.grant_count);
        println!("blob_size        {} bytes", blob.len());
        println!("header_size      {header_size} bytes");
        println!("body_size        {body_len} bytes");
    }
    Ok(())
}

fn mode_label(mode: u8) -> &'static str {
    match mode {
        1 => "SINGLE",
        2 => "CHUNKED",
        _ => "UNKNOWN",
    }
}
