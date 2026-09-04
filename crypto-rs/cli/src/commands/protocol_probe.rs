//! `frappuccino-cli protocol-probe` — live-probe a V2 relay endpoint.
//!
//! Uses the same pinned TLS stack as the mobile client (SPKI pin embedded in
//! `frappuccino-crypto-stream`). Hits `/auth/challenge` and prints the returned
//! `nonce` + `timestamp` — useful to confirm the server is reachable and speaks
//! the post-S9-pre-audit challenge shape.
//!
//! (The `--pk` `/auth/v2/status` probe was removed with that route — R-SRV-1,
//! 2026-06-27 — and the client plumbing in the BT-05 dead-code sweep, 2026-06-30.)

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_stream::StreamServerClient;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Relay URL (typically `https://136.244.101.236:8443`).
    pub url: String,

    /// Emit one-line JSON.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let client = StreamServerClient::new(&args.url)
        .context("build StreamServerClient (TLS pin / reqwest config)")?;

    let challenge = client.challenge().context("POST /auth/challenge")?;

    if args.json {
        let obj = serde_json::json!({
            "url": args.url,
            "challenge": {
                "nonce": hex::encode(challenge.nonce),
                "timestamp": challenge.timestamp,
            },
        });
        println!("{obj}");
    } else {
        println!("url              {}", args.url);
        println!("challenge.nonce  {}", hex::encode(challenge.nonce));
        println!("challenge.ts     {}", challenge.timestamp);
    }
    Ok(())
}
