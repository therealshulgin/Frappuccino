//! `frappuccino-cli` — desktop CLI wrapping the Rust crypto core.
//!
//! Replaces the legacy `server-tools/*.py` scripts (`stream_decrypt.py`,
//! `stream_archive.py`) for the non-networked paths: everything a local
//! inspector needs to verify an archive phrase or decrypt a captured STRM
//! blob without trusting a Python interpreter's dependency surface.
//!
//! Subcommands:
//! * `identity`        — derive pub keys + fingerprint from a mnemonic.
//! * `decrypt`         — decrypt (or `--inspect`) a STRM blob.
//! * `parity-test`     — replay every parity vector under a directory.
//! * `protocol-probe`  — live-probe a V2 relay (challenge + status).
//!
//! Secrets handling: mnemonics and passphrases are taken from
//! `/dev/stdin` by default (one per line). Explicit `--mnemonic`/`--passphrase`
//! flags exist for automation but log a warning to stderr so nobody uses them
//! in shell history by accident.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

mod commands;

#[derive(Debug, Parser)]
#[command(
    name = "frappuccino-cli",
    version,
    about = "Frappuccino CLI - offline crypto tooling; see --help for the subcommands",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Derive and print an archive identity from a BIP-39 mnemonic.
    Identity(commands::identity::Args),
    /// Decrypt (or inspect) a STRM blob.
    Decrypt(commands::decrypt::Args),
    /// Replay every parity vector under a directory (hashes / JSON fixtures).
    ParityTest(commands::parity_test::Args),
    /// Live-probe a V2 relay endpoint (challenge only; the `/auth/v2/status`
    /// lookup went with that route, R-SRV-1).
    ProtocolProbe(commands::protocol_probe::Args),
    /// Phase 4.4 — list and download archives via BIP-39 (rescue device).
    FetchArchive(commands::fetch_archive::Args),
    /// §10.11 — verify disclosed chunks against a Bitcoin OTS proof. No
    /// manifest and no mini-cert: the lean model stores neither.
    VerifyProvenance(commands::verify_provenance::Args),
}

fn main() {
    // Propagate a non-zero exit code when a subcommand fails, while keeping
    // panics reserved for actual logic bugs (never user-facing errors).
    if let Err(e) = run() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Identity(args) => commands::identity::run(&args),
        Command::Decrypt(args) => commands::decrypt::run(&args),
        Command::ParityTest(args) => commands::parity_test::run(&args),
        Command::ProtocolProbe(args) => commands::protocol_probe::run(&args),
        Command::FetchArchive(args) => commands::fetch_archive::run(&args),
        Command::VerifyProvenance(args) => commands::verify_provenance::run(&args),
    }
}

// ----------------------------------------------------------------------------
// Shared helpers (exposed to command modules).
// ----------------------------------------------------------------------------

/// Read a single line from stdin, trimmed. Used to prompt for mnemonics and
/// passphrases interactively without depending on a TTY crate.
///
/// Returns an empty string on EOF so callers can treat "no passphrase" as the
/// empty-string case without extra branches.
pub(crate) fn read_stdin_line(prompt: &str) -> Result<String> {
    let mut stderr = io::stderr().lock();
    write!(stderr, "{prompt}").context("stderr write")?;
    stderr.flush().context("stderr flush")?;
    drop(stderr);

    let mut buf = String::new();
    let n = io::stdin()
        .read_line(&mut buf)
        .context("read line from stdin")?;
    if n == 0 {
        return Ok(String::new());
    }
    Ok(buf.trim().to_string())
}

/// Read the entire contents of `path`, or stdin when `path == "-"`.
pub(crate) fn read_blob(path: &PathBuf) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("read blob from stdin")?;
        return Ok(buf);
    }
    fs::read(path).with_context(|| format!("read blob file {}", path.display()))
}

/// Resolve a mnemonic either from the CLI flag or by prompting on stderr.
///
/// CLI flag path logs a warning — shell history and process listings leak
/// arguments to other users on the same box.
pub(crate) fn resolve_mnemonic(flag: Option<&str>) -> Result<String> {
    if let Some(m) = flag {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: --mnemonic on the command line leaks into shell history and `ps -aux`"
        );
        return Ok(m.to_string());
    }
    let line = read_stdin_line("mnemonic (12 words FR, one line): ")?;
    if line.is_empty() {
        bail!("no mnemonic provided");
    }
    Ok(line)
}

/// Resolve an optional passphrase from flag or stderr prompt. Returns the
/// empty string when the user hits enter with no passphrase.
pub(crate) fn resolve_passphrase(flag: Option<&str>, prompt_if_absent: bool) -> Result<String> {
    if let Some(p) = flag {
        return Ok(p.to_string());
    }
    if !prompt_if_absent {
        return Ok(String::new());
    }
    read_stdin_line("passphrase (press enter if none): ")
        .map(|s| if s.is_empty() { String::new() } else { s })
        .map_err(|e| anyhow!("read passphrase: {e}"))
}
