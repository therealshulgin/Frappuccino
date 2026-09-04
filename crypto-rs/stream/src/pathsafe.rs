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

#[cfg(test)]
mod tests {
    use super::is_safe_blob_filename;

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
