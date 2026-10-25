//! The report device state file, owned by Rust, and the process-wide lock
//! every transition runs under.
//!
//! The file (`filesDir/report_state.bin` on Android, its path chosen by
//! Kotlin) holds the serialized `core::report::ReportDeviceState`, the index
//! and chain link of the NEXT report plus the directory seed, sealed with the
//! PIN-session key under `report::CTX_STATE_AAD`. Its plaintext never crosses
//! the FFI and never reaches the JVM.
//!
//! Every transition (creation at enrollment, opening a report, migration,
//! wipe) holds [`REPORT_STATE`] for its whole read-unseal-advance-seal-write
//! sequence, so two of them can never interleave in one process. Opening a
//! report hands its writer out only after the advanced state is durably
//! written (`.part`, `sync_all`, rename, directory flush): if that write fails
//! there is no writer. The file then holds the old state, and the next opening
//! derives the same index again; or, when only the final directory flush
//! failed, the advanced state, and that index is skipped. In both cases its key
//! was never used.
//!
//! The same lock holds a weak reference to the live writer, so the emergency
//! wipe can abort it from outside the recording service, and so a second
//! writer cannot be opened while one is live.

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use frappuccino_crypto_core::pin_store as core_pin_store;
use frappuccino_crypto_core::report::{ReportDeviceState, CTX_STATE_AAD};
use frappuccino_crypto_stream::durable::{part_path, write_durably, OnDirSyncError};

use crate::report_writer::{DirectoryEntrySigs, ReportWriter};
use crate::{with_pin_session, FfiError, StreamIdentity};

// ============================================================================
// The lock
// ============================================================================

/// What the state lock protects besides the file: the live writer.
struct StateSlot {
    /// The writer opened last. Weak: the slot never keeps a writer, and so
    /// its key, alive after Kotlin drops it.
    live_writer: Option<Weak<ReportWriter>>,
}

static REPORT_STATE: Mutex<StateSlot> = Mutex::new(StateSlot { live_writer: None });

fn state_guard() -> MutexGuard<'static, StateSlot> {
    // A panic in a previous transition leaves at worst a `.part` behind;
    // recovering keeps the wipe and the abort working.
    REPORT_STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

impl StateSlot {
    /// The live writer, if one is referenced and still open.
    ///
    /// A referenced writer that is not open is aborted here before being
    /// reported dead. That is a no-op for a closed or aborted one, but a
    /// writer whose lock a panic poisoned is not open (it accepts nothing)
    /// while it may still hold its key, and the next opening replaces this
    /// reference: after that, neither the global abort nor the wipe could
    /// reach it to wipe the key.
    fn live(&self) -> Option<Arc<ReportWriter>> {
        let writer = self.live_writer.as_ref().and_then(Weak::upgrade)?;
        if writer.is_open() {
            return Some(writer);
        }
        writer.abort();
        None
    }

    /// Abort the live writer, if any. True if one was open.
    fn abort_live(&mut self) -> bool {
        self.live_writer
            .take()
            .and_then(|weak| weak.upgrade())
            .is_some_and(|writer| writer.abort_now())
    }
}

// ============================================================================
// Sealing and file I/O
// ============================================================================

fn no_pin_session(what: &str) -> FfiError {
    FfiError::Internal {
        detail: format!("{what}: no active PIN session"),
    }
}

fn io_error(what: &str, error: &std::io::Error) -> FfiError {
    FfiError::Io {
        detail: format!("{what}: {error}"),
    }
}

/// Seal a serialized state under the PIN-session key and write it durably.
///
/// The state file is the only copy of the state. If the directory flush fails
/// after the rename, the new state is kept rather than removed: by then the
/// old one is already replaced, and removing the new one would leave no state
/// at all, so the device could not record again before a new enrollment. The
/// caller still gets the error, and hands out no writer.
fn write_state(path: &Path, state_bytes: &[u8]) -> Result<(), FfiError> {
    let sealed = match with_pin_session(|key, salt| {
        core_pin_store::seal_with_key_and_aad(key, salt, state_bytes, CTX_STATE_AAD)
    }) {
        Some(sealed) => sealed?,
        None => return Err(no_pin_session("seal report state")),
    };
    write_durably(path, OnDirSyncError::KeepDestination, |file| {
        file.write_all(&sealed)
    })
    .map_err(|e| io_error("write report state", &e))
}

/// Unseal a state read from disk.
fn unseal_state(sealed: &[u8]) -> Result<ReportDeviceState, FfiError> {
    let plaintext = match with_pin_session(|key, _salt| {
        core_pin_store::open_with_key_and_aad(key, sealed, CTX_STATE_AAD)
    }) {
        Some(plaintext) => plaintext?,
        None => return Err(no_pin_session("open report state")),
    };
    Ok(ReportDeviceState::from_bytes(&plaintext)?)
    // plaintext (Zeroizing) drops here → wiped.
}

fn read_state(path: &Path) -> Result<ReportDeviceState, FfiError> {
    let sealed = std::fs::read(path).map_err(|e| io_error("read report state", &e))?;
    unseal_state(&sealed)
}

fn utf8<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str, FfiError> {
    std::str::from_utf8(bytes).map_err(|e| FfiError::InvalidMnemonic {
        detail: format!("{what} bytes are not valid UTF-8: {e}"),
    })
}

// ============================================================================
// Transitions (FFI)
// ============================================================================

/// FFI — enrollment: derive the report state at index 0 from the phrase and
/// write it, sealed, to `state_path`. The intermediate `report_master` is
/// wiped before this returns and is never stored. Needs the PIN session
/// (`pin_session_populate` first).
///
/// Enrollment is a fresh start: an existing file at `state_path` is replaced.
///
/// # Errors
/// [`FfiError::InvalidMnemonic`] for bytes that are not UTF-8 or an invalid
/// phrase; [`FfiError::Internal`] without a PIN session; [`FfiError::Io`].
pub fn pin_session_create_report_state(
    mnemonic: &[u8],
    passphrase: &[u8],
    state_path: &str,
) -> Result<(), FfiError> {
    let mnemonic = utf8(mnemonic, "mnemonic")?;
    let passphrase = utf8(passphrase, "passphrase")?;
    let _slot = state_guard();
    let state = ReportDeviceState::from_mnemonic(mnemonic, passphrase)?;
    write_state(Path::new(state_path), &state.to_bytes())
}

/// FFI — start a recording: open the next report from the state at
/// `state_path` and return its writer. The state is advanced and durably
/// written before the writer is returned; on any error there is no writer.
/// The file is then as it was, except after a failed flush of the directory
/// once the advanced state had replaced it: the advanced state is kept and
/// the index is skipped. `author` is the public identity the writer encrypts
/// every object to.
///
/// The directory entry of the new report is signed in this same call (the
/// directory key lives in the state); the writer writes it with
/// `seal_directory_entry`.
///
/// # Errors
/// [`FfiError::WriterBusy`] while another writer is live in this process;
/// [`FfiError::Internal`] without a PIN session; [`FfiError::Io`] (a missing
/// state file included); [`FfiError::WrongPin`] if the file does not open
/// under the session key; [`FfiError::InvalidBlob`] for a malformed state;
/// [`FfiError::ReportRefused`] once the index space is exhausted.
#[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
pub fn pin_session_open_report(
    state_path: &str,
    author: Arc<StreamIdentity>,
) -> Result<Arc<ReportWriter>, FfiError> {
    let path = Path::new(state_path);
    let mut slot = state_guard();
    if slot.live().is_some() {
        return Err(FfiError::WriterBusy);
    }
    let mut state = read_state(path)?;
    let opening = state.open_report()?;
    let core_writer = opening.release_after_persist(|advanced| write_state(path, advanced))?;
    let directory = DirectoryEntrySigs::sign(&state, core_writer.directory_entry_name());
    // The identity is public key material; the writer keeps its own copy.
    let writer = Arc::new(ReportWriter::new(
        core_writer,
        directory,
        author.inner.clone(),
    ));
    slot.live_writer = Some(Arc::downgrade(&writer));
    Ok(writer)
    // `state` drops here: its chain link and directory seed are wiped.
}

/// FFI — migration: create the report state at index `k` from the legacy
/// `report_master`, unsealed in-crate from `master_sealed` with the PIN-session
/// key (the master never crosses the FFI), and return the state's next index.
///
/// Idempotent, because a migration that stopped half-way resumes at the next
/// unlock: if a state already exists at `state_path` it is left untouched
/// (recordings may have advanced it) and its next index is returned. It is
/// refused only if it is BEHIND `k`, which would reuse legacy indices.
///
/// # Errors
/// [`FfiError::ReportRefused`] for `k` above the migration bound or a state on
/// disk behind `k`; [`FfiError::Internal`] without a PIN session;
/// [`FfiError::WrongPin`] / [`FfiError::InvalidBlob`] for a master or state
/// that does not open; [`FfiError::Io`].
pub fn pin_session_migrate_report_state(
    master_sealed: &[u8],
    k: u32,
    state_path: &str,
) -> Result<u32, FfiError> {
    let path = Path::new(state_path);
    let _slot = state_guard();
    match std::fs::read(path) {
        Ok(sealed) => {
            let existing = unseal_state(&sealed)?;
            if existing.next_index() < k {
                return Err(FfiError::ReportRefused {
                    detail: format!(
                        "the report state on disk is at index {}, behind the migration point {k}",
                        existing.next_index()
                    ),
                });
            }
            return Ok(existing.next_index());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("read report state", &error)),
    }
    let master =
        match with_pin_session(|key, _salt| core_pin_store::open_with_key(key, master_sealed)) {
            Some(master) => master?,
            None => return Err(no_pin_session("open report master")),
        };
    let master: &[u8; 32] = master
        .as_slice()
        .try_into()
        .map_err(|_| FfiError::InvalidBlob {
            detail: format!("report_master must be 32 bytes, got {}", master.len()),
        })?;
    let state = ReportDeviceState::migrate_from_master(master, k)?;
    write_state(path, &state.to_bytes())?;
    Ok(state.next_index())
    // the unsealed master (Zeroizing) drops here → wiped.
}

/// FFI — emergency wipe: abort the live writer, if any, then securely delete
/// the state file and any `.part` a crash left next to it. Holds the state
/// lock, so it cannot interleave with an opening. Idempotent.
///
/// Both files are always attempted, the state file first: a failure on the
/// leftover `.part` never keeps the state on disk. A file whose overwrite
/// fails is still unlinked when the filesystem allows it, so its name and its
/// sealed content stop being reachable through the filesystem, even though
/// its blocks were not overwritten.
///
/// # Errors
/// [`FfiError::Io`] if either file could not be overwritten, whether or not
/// it was then unlinked. The first such error is returned once both files
/// have been attempted.
pub fn report_state_wipe(state_path: &str) -> Result<(), FfiError> {
    let path = Path::new(state_path);
    let mut slot = state_guard();
    slot.abort_live();
    let state = delete_or_unlink(path);
    let part = part_path(path).map_or(Ok(()), |part| delete_or_unlink(&part));
    state.and(part)
}

/// Securely delete `path`. If that fails, remove its name anyway, as the
/// other wipes of the app do, and still report the failure: the overwrite
/// did not complete. `remove_file` never removes a directory, so a directory
/// standing at `path` is left in place and reported.
fn delete_or_unlink(path: &Path) -> Result<(), FfiError> {
    let Err(error) = frappuccino_crypto_stream::secure_delete_file(path) else {
        return Ok(());
    };
    // Already gone (`NotFound`) or not removable: either way the error that
    // matters is the overwrite's, returned below.
    let _ = std::fs::remove_file(path);
    Err(error.into())
}

/// FFI — abort the live writer from anywhere in the process (emergency wipe):
/// its key is wiped and it seals nothing more, without a closure. Waits for an
/// opening in progress, then aborts the writer it produced. Returns whether a
/// writer was open.
pub fn report_writer_abort_live() -> bool {
    state_guard().abort_live()
}

/// FFI — whether a writer is live (opened, neither closed nor aborted).
#[must_use]
pub fn report_writer_is_live() -> bool {
    state_guard().live().is_some()
}

/// Run `f` with the state at `path` opened read-only, under the state lock,
/// for the directory key. The state is not advanced and not rewritten.
pub(crate) fn with_directory_key<R>(
    path: &Path,
    f: impl FnOnce(&ReportDeviceState) -> Result<R, FfiError>,
) -> Result<R, FfiError> {
    let _slot = state_guard();
    let state = read_state(path)?;
    f(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{author, globals, install_session, scratch_dir, MN_FIXED};
    use crate::{pin_session_clear_internal, pin_session_store};
    use frappuccino_crypto_core::report::{ReportKeyring as CoreKeyring, ReportRescue};

    fn create(dir: &Path) -> String {
        let path = dir.join("report_state.bin");
        pin_session_create_report_state(MN_FIXED.as_bytes(), b"", path.to_str().unwrap()).unwrap();
        path.to_str().unwrap().to_owned()
    }

    #[test]
    fn opening_advances_the_state_on_disk_before_the_writer_exists() {
        let _g = globals();
        let dir = scratch_dir("state_open");
        install_session();
        let path = create(&dir);
        let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();

        let first = pin_session_open_report(&path, author()).unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(
            first.report_id_hex(),
            rescue.chain(0).unwrap().report_id_hex()
        );
        assert!(report_writer_is_live());
        // One writer at a time.
        assert!(matches!(
            pin_session_open_report(&path, author()),
            Err(FfiError::WriterBusy)
        ));
        first.abort();
        assert!(!report_writer_is_live());

        let second = pin_session_open_report(&path, author()).unwrap();
        assert_eq!(second.index(), 1, "the state on disk had advanced");
        assert_eq!(
            second.report_id_hex(),
            rescue.chain(1).unwrap().report_id_hex()
        );
        // A writer Kotlin dropped does not block the next one.
        drop(second);
        assert!(!report_writer_is_live());
        let third = pin_session_open_report(&path, author()).unwrap();
        assert_eq!(third.index(), 2);
        assert!(report_writer_abort_live());
        assert!(!report_writer_abort_live());
        assert!(!third.is_open());
        // The file on disk is sealed: no chain link in clear.
        let raw = std::fs::read(&path).unwrap();
        assert_ne!(raw.first(), Some(&0x02));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_persist_yields_no_writer_and_keeps_the_index() {
        let _g = globals();
        let dir = scratch_dir("state_persist_fail");
        install_session();
        let path = create(&dir);
        // The directory of the state becomes unwritable for the .part: put a
        // directory where the .part file must be created.
        let part = part_path(Path::new(&path)).unwrap();
        std::fs::create_dir_all(&part).unwrap();
        assert!(matches!(
            pin_session_open_report(&path, author()),
            Err(FfiError::Io { .. })
        ));
        assert!(!report_writer_is_live());
        std::fs::remove_dir_all(&part).unwrap();
        let writer = pin_session_open_report(&path, author()).unwrap();
        assert_eq!(writer.index(), 0, "the failed opening consumed nothing");
        writer.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The directory flush fails after the advanced state replaced the file:
    /// no writer, and the state is still there (advanced), so the device can
    /// go on recording. A directory in mode 0o300 lets a non-root user create,
    /// rename and read files in it, but not open it for the flush.
    #[cfg(unix)]
    #[test]
    fn a_failed_directory_flush_yields_no_writer_and_keeps_a_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let _g = globals();
        let dir = scratch_dir("state_dirsync_fail");
        install_session();
        let path = create(&dir);
        let set_mode = |mode| {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode(0o300);
        if std::fs::File::open(&dir).is_ok() {
            set_mode(0o700);
            eprintln!("skip: the directory still opens (running as root?)");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let outcome = pin_session_open_report(&path, author());
        set_mode(0o700);
        assert!(matches!(outcome, Err(FfiError::Io { .. })), "{outcome:?}");
        assert!(!report_writer_is_live());
        assert!(
            Path::new(&path).exists(),
            "the only state must not be deleted"
        );
        let writer = pin_session_open_report(&path, author()).unwrap();
        assert_eq!(writer.index(), 1, "index 0 is skipped, never reused");
        writer.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_poisoned_writer_is_wiped_before_another_one_replaces_it() {
        let _g = globals();
        let dir = scratch_dir("state_poisoned");
        install_session();
        let path = create(&dir);
        let first = pin_session_open_report(&path, author()).unwrap();
        first.poison_for_test();
        assert!(!first.is_open(), "a poisoned writer accepts nothing");
        assert!(first.holds_key_for_test(), "but its key is still inside");
        // The next opening goes ahead, and the global reference moves to the
        // new writer: the poisoned one must not keep its key past that.
        let second = pin_session_open_report(&path, author()).unwrap();
        assert!(!first.holds_key_for_test());
        assert_eq!(second.index(), 1);
        assert!(report_writer_abort_live());
        assert!(!second.holds_key_for_test());

        // The same through the liveness query alone.
        let third = pin_session_open_report(&path, author()).unwrap();
        third.poison_for_test();
        assert!(!report_writer_is_live());
        assert!(!third.holds_key_for_test());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_state_needs_the_session_and_its_own_key() {
        let _g = globals();
        let dir = scratch_dir("state_session");
        install_session();
        let path = create(&dir);
        pin_session_clear_internal();
        assert!(matches!(
            pin_session_open_report(&path, author()),
            Err(FfiError::Internal { .. })
        ));
        assert!(matches!(
            pin_session_create_report_state(MN_FIXED.as_bytes(), b"", &path),
            Err(FfiError::Internal { .. })
        ));
        // Another session key does not open it.
        pin_session_store(&[0x01u8; 32], &[0x02u8; 16]).unwrap();
        assert!(matches!(
            pin_session_open_report(&path, author()),
            Err(FfiError::WrongPin)
        ));
        install_session();
        // Missing and malformed files.
        let absent = dir.join("absent.bin");
        assert!(matches!(
            pin_session_open_report(absent.to_str().unwrap(), author()),
            Err(FfiError::Io { .. })
        ));
        std::fs::write(&path, b"garbage").unwrap();
        assert!(matches!(
            pin_session_open_report(&path, author()),
            Err(FfiError::InvalidBlob { .. })
        ));
        assert!(matches!(
            pin_session_create_report_state(b"\xff\xfe", b"", &path),
            Err(FfiError::InvalidMnemonic { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_starts_the_chain_at_k_and_is_idempotent() {
        let _g = globals();
        let dir = scratch_dir("state_migrate");
        install_session();
        let master: [u8; 32] = CoreKeyring::from_mnemonic(MN_FIXED, "")
            .unwrap()
            .with_master_bytes(|b| b.try_into().unwrap());
        let sealed = with_pin_session(|key, salt| {
            core_pin_store::seal_with_key(key, salt, &master).unwrap()
        })
        .unwrap();
        let path = dir.join("report_state.bin");
        let path = path.to_str().unwrap();
        assert!(matches!(
            pin_session_migrate_report_state(&sealed, 1_000_001, path),
            Err(FfiError::ReportRefused { .. })
        ));
        assert!(!Path::new(path).exists());
        assert_eq!(
            pin_session_migrate_report_state(&sealed, 3, path).unwrap(),
            3
        );

        let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
        let writer = pin_session_open_report(path, author()).unwrap();
        assert_eq!(writer.index(), 3);
        assert_eq!(
            writer.report_id_hex(),
            rescue.chain(3).unwrap().report_id_hex()
        );
        writer.abort();
        // A resumed migration keeps the advanced state.
        assert_eq!(
            pin_session_migrate_report_state(&sealed, 3, path).unwrap(),
            4
        );
        // A migration point beyond the state on disk is refused, not applied.
        assert!(matches!(
            pin_session_migrate_report_state(&sealed, 9, path),
            Err(FfiError::ReportRefused { .. })
        ));
        assert_eq!(pin_session_open_report(path, author()).unwrap().index(), 4);
        report_writer_abort_live();
        // A master that does not open.
        let other = dir.join("other.bin");
        assert!(matches!(
            pin_session_migrate_report_state(b"not sealed", 0, other.to_str().unwrap()),
            Err(FfiError::InvalidBlob { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_wipe_aborts_the_writer_and_deletes_the_state() {
        let _g = globals();
        let dir = scratch_dir("state_wipe");
        install_session();
        let path = create(&dir);
        let writer = pin_session_open_report(&path, author()).unwrap();
        let part = part_path(Path::new(&path)).unwrap();
        std::fs::write(&part, b"stale").unwrap();
        report_state_wipe(&path).unwrap();
        assert!(!writer.is_open());
        assert!(!Path::new(&path).exists());
        assert!(!part.exists());
        report_state_wipe(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `.part` that cannot be deleted (here a directory standing at its
    /// path) is reported, and does not keep the state file on disk.
    #[test]
    fn a_failure_on_the_part_still_deletes_the_state() {
        let _g = globals();
        let dir = scratch_dir("state_wipe_part_fails");
        install_session();
        let path = create(&dir);
        let part = part_path(Path::new(&path)).unwrap();
        std::fs::create_dir_all(&part).unwrap();
        let outcome = report_state_wipe(&path);
        assert!(matches!(outcome, Err(FfiError::Io { .. })), "{outcome:?}");
        assert!(!Path::new(&path).exists(), "the state survived the wipe");
        assert!(part.is_dir(), "a directory is never removed by the wipe");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The state file cannot be opened for writing, so it cannot be
    /// overwritten: the wipe reports it and still unlinks it. A read-only
    /// file in a writable directory gives exactly that to a non-root user.
    #[cfg(unix)]
    #[test]
    fn a_state_that_cannot_be_overwritten_is_still_unlinked() {
        use std::os::unix::fs::PermissionsExt as _;
        let _g = globals();
        let dir = scratch_dir("state_wipe_readonly");
        install_session();
        let path = create(&dir);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        if std::fs::OpenOptions::new().write(true).open(&path).is_ok() {
            eprintln!("skip: a read-only file still opens for writing (running as root?)");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let outcome = report_state_wipe(&path);
        assert!(matches!(outcome, Err(FfiError::Io { .. })), "{outcome:?}");
        assert!(!Path::new(&path).exists(), "the state survived the wipe");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
