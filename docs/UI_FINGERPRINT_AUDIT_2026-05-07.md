# UI fingerprint label audit — 2026-05-07

Phase 4.2.4 of [`ROADMAP.md`](../ROADMAP.md). Closes the Blue Team
counter-audit caveat on `AUDIT_SCOPE_RUST §6.1` (STRM blob authorship not
signed): the deferral is only defensible if the UI never presents
`author_ed25519_pk` as an authenticated author label. This note records the
audit of every place the fingerprint or `author_ed25519_pk` could surface
to the user, at HEAD `fbcab3e`.

## Search method

```bash
grep -rn "readableFingerprint\|author_ed25519\|authorEd25519" \
    mobile/src/main/ stream-crypto/src/main/ --include="*.kt"
grep -rn "fingerprint\|empreinte\|auteur\|author\|envoyé par" \
    mobile/src/main/res/layout/ --include="*.xml"
```

## Call-sites touching the fingerprint

| File:line | Surface | Label / context | Verdict |
|---|---|---|---|
| `ArchiveModeActivity.kt:98` | TextView `archiveFingerprint` shown after BIP-39 unlock | XML has no preceding label, just a `<!-- Fingerprint -->` comment. The fingerprint sits below a status TextView ("✓ Phrase correspond à l'identité de ce device.") | OK — context makes it clear this is the **derived** identity from the typed phrase, not an attribution claim. |
| `StreamActivity.kt:99,177` | TextView `fingerprintText` (bottom of the idle screen) | XML comment says: *"Confidence signal for the user: 'this device is the one that enrolled the identity you see on paper'."* — 12sp monospace, deliberately understated. | OK — idle-only decoration, never shown next to a content blob. |
| `StreamSettingsActivity.kt:68` | TextView `settingsFingerprint` | Preceded by an `OsintSubtitle` "— IDENTITÉ —". Section is the user's own identity, not someone else's. | OK — factual labelling, no attribution. |
| `OnBoardSetPinFragment.kt:163` | `Timber.d` log only | Not user-visible. | OK |
| `ArchiveIdentity.kt`, `StreamIdentity.kt`, `StreamUploadManager.kt` | non-UI | Wrappers / enrollment logic. | OK |

## Layout XML refs to fingerprint terms

`activity_stream.xml` is the only layout that uses the word "fingerprint"
verbatim, and only in HTML comments — no on-screen string says
"author", "envoyé par", or anything similar.

## Author public key — explicit search

`grep -rn "authorEd25519\|author_ed25519" mobile/src/main/`: zero hits.
The `BlobMetadata.authorEd25519Pk` field exposed by the FFI is never
displayed in the current UI. (Archive retrieval — Phase 4.4 — will
introduce a stream listing screen that *could* show it; the followup TODO
below notes the design constraint.)

## Conclusion

**The §6.1 deferral holds at HEAD.** No UI element today implies that the
displayed fingerprint or any `author_ed25519_pk` value is an authenticated
attribution. The fingerprint is shown in three contexts, all framed as the
user's *own* identity — never as someone else's authorship claim.

## Followup constraints for Phase 4.4 (archive retrieval)

When the report-list screen lands as part of archive retrieval, the
`author_ed25519_pk` value MUST be either:

1. **Hidden entirely** — the user already typed the phrase, so showing
   the same identity twice (fingerprint + author) adds nothing.
2. **Or labelled defensively** — e.g. "fingerprint de l'auteur déclaré
   (non signé)" — explicit that the value is unsigned and forgeable by
   anyone holding the recipient's public key.

The reviewer at audit time should confirm one of those two patterns is in
place before greenlighting the archive retrieval surface.

## Screenshots

To be captured by therealshulgin on Seeker (SM02E406037868) at the next
session — file under `docs/screenshots/2026-05-07-fingerprint-*.png`.
Captures expected:
- `archive-mode-fingerprint.png` — post-unlock screen
- `stream-idle-fingerprint.png` — main screen idle state
- `settings-fingerprint.png` — Settings → Identity section
