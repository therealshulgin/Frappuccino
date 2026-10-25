//! Path-safety guard for relay-supplied blob filenames (M-1 / WP-C).
//!
//! The archive listing (`GET /…/{report_id}/blobs`) returns filenames the
//! RELAY controls. On a rescue device those names are joined onto a local
//! output directory and written to disk; a compromised/coerced relay must not
//! be able to path-traverse out of that directory (`../../…`, absolute paths,
//! separators). This is the single SHARED guard used by every client — the CLI
//! (`fetch-archive`), the FFI download entry points, and (via the FFI predicate
//! `archive_blob_filename_is_safe`) the Android rescue. The relay also rejects
//! `.`/`..` at upload (`server/app/routes/upload.py`), so this is sink-side
//! defence in depth, not the only guard.

/// True iff `name` is a single, safe path component — no separator, not
/// `.`/`..`, not absolute, not empty — so joining it onto an output dir cannot
/// escape it. Uses the platform's path semantics (on the rescue device, Linux:
/// `/` is the only separator), which is exactly the sink we are protecting.
#[must_use]
pub fn is_safe_blob_filename(name: &str) -> bool {
    let mut comps = std::path::Path::new(name).components();
    matches!(
        (comps.next(), comps.next()),
        (Some(std::path::Component::Normal(c)), None) if c.to_str() == Some(name)
    )
}

/// Longest object name the relay accepts.
const MAX_RELAY_NAME_BYTES: usize = 128;

/// True iff `byte` belongs to the alphabet of relay object names,
/// `[A-Za-z0-9._-]`. Every such byte is ASCII, so a run of them is valid UTF-8
/// and spells one character per byte.
#[must_use]
pub(crate) fn is_relay_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// True iff `name` is an object name the relay accepts: 1 to 128 characters
/// from `[A-Za-z0-9._-]`, not `.`, and no `..` anywhere. Mirrors
/// `server/app/paths.py::validate_filename`, so a client never builds a URL
/// or an envelope for a name the relay would refuse, and never sends a
/// relay-supplied name back in a URL without checking it. Every such name is
/// also a safe path component ([`is_safe_blob_filename`]).
///
/// The rule is checked on the bytes ([`is_relay_object_name_bytes`]). The
/// alphabet is ASCII, so this is the same rule as on characters.
#[must_use]
pub fn is_relay_object_name(name: &str) -> bool {
    is_relay_object_name_bytes(name.as_bytes())
}

/// [`is_relay_object_name`] on raw bytes. It uses plain loops and no string
/// search, which the Kani harness over the envelope decoder relies on.
#[must_use]
pub(crate) fn is_relay_object_name_bytes(name: &[u8]) -> bool {
    (1..=MAX_RELAY_NAME_BYTES).contains(&name.len())
        && name.iter().all(|&byte| is_relay_name_byte(byte))
        && name != b"."
        && !name.windows(2).any(|pair| pair == b"..")
}

#[cfg(test)]
mod tests {
    use super::{is_relay_object_name, is_safe_blob_filename};

    #[test]
    fn relay_object_names_mirror_the_relay_rule() {
        for good in [
            "000001.strm",
            "manifest",
            "a6c2f8e53532333e878cce6644f0a419",
            "sid_000001.strm",
            "a-b_c.d",
            &"a".repeat(128),
        ] {
            assert!(is_relay_object_name(good), "{good:?}");
            assert!(is_safe_blob_filename(good), "{good:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a..b",
            "a/b",
            "a\\b",
            "a b",
            "é",
            "a?b",
            "%2e%2e",
            &"a".repeat(129),
        ] {
            assert!(!is_relay_object_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn accepts_real_blob_names_rejects_traversal() {
        // Real blob names the relay serves (chunk ids, directory index, manifest,
        // provenance proof).
        assert!(is_safe_blob_filename(
            "2115607e561b5560d82b30c04d7f0bd7_000001.strm"
        ));
        assert!(is_safe_blob_filename("0000000000"));
        assert!(is_safe_blob_filename("manifest.json"));
        assert!(is_safe_blob_filename("a1b2c3.ots"));
        // Traversal / separators / empties are refused (portable cases: `/` is a
        // separator and `.`/`..` are special on every platform).
        for bad in ["..", ".", "../etc/passwd", "a/b", "/abs", ""] {
            assert!(!is_safe_blob_filename(bad), "should reject {bad:?}");
        }
    }
}
