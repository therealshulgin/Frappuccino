//! Subcommand implementations. One module per `clap` subcommand — each
//! module owns its `Args` struct and its `run(&Args)` entry point.

pub mod decrypt;
pub mod fetch_archive;
pub mod identity;
pub mod parity_test;
pub mod protocol_probe;
pub mod verify_provenance;
