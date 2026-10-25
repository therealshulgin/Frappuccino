#!/usr/bin/env bash
# check-doc-currency.sh — doc-currency anti-regression oracle.
#
# Two families of checks, both on documents that describe the CURRENT system.
#
# 1. STRM wire. Fails if a canon or authoritative doc still describes the
#    current STRM wire as "V2-with-author". The pre-publication F-C1 / WP-A
#    removal made V3 the current format, with NO `author_ed25519_pk` at rest
#    (the motto: "a seizure exposes nothing"). Source of truth:
#    crypto-rs/stream/src/header.rs. Added after the 2026-06-30 cross-audit
#    (BT-06) found GUIDE_AUDITEUR / ROADMAP / AUDIT_SCOPE still describing the
#    old V2 wire while the code shipped V3.
#
# 2. Frozen reports. Since the report rework (one-way key chain, signing at
#    production, signed closure 0x09, verified rescue), several earlier claims
#    are false, and they were written in many places at once: the device's
#    leftover signing capacity was "bounded, server-detectable, revocable" (no
#    revocation route exists, no channel tells the witness, the capacity has no
#    time limit), "no forging of past sessions" held without qualification (it
#    holds for CLOSED reports only), and several retired FFI entry points and
#    classes were still named as current. This family fails on those phrases,
#    and on a paragraph naming a retired entry point without saying it is
#    retired.
#
# Keep the signatures narrow. Legacy prose is legitimate — a doc may say the
# author key was removed in V3, or that `strm_encrypt_file` was retired — and
# widening a pattern to catch more makes the oracle ring on correct docs, after
# which someone turns it off for good. Dated documents (ROADMAP history,
# design reviews, dated plans, RELAY_BLIND_REPORTS's v3 body) are out of scope
# of family 2 on purpose: they record what was true when they were written.
#
# Usage:
#   bash scripts/check-doc-currency.sh            # exit 0 = OK, 1 = stale doc
#   bash scripts/check-doc-currency.sh selftest   # negative controls: each
#                                                 # injected stale claim must FAIL
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- family 1: the STRM wire -------------------------------------------------

# The three canons, plus the authoritative scope/invariants doc
# (AUDIT_SCOPE_RUST) and the presentation doc (POSITIONNEMENT).
CANONS=(
  "ROADMAP.md"
  "AUDIT_SCOPE_RUST.md"
  "docs/GUIDE_AUDITEUR.md"
  "docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md"
  "docs/POSITIONNEMENT.md"
)

# Signatures that assert the CURRENT format is V2-with-author. These must never
# appear in a canon. They are deliberately tight so legitimate "author removed
# in V3" / "legacy V1/V2 carried author" lines do NOT match.
BAD='VERSION_CURRENT[[:space:]]*=[[:space:]]*(VERSION_)?V?2([^0-9]|$)|VERSION_CURRENT[[:space:]]*=[[:space:]]*0x02|magic\+version\+author|STRM[[:space:]]+v2[[:space:]]*\(magic\+version\+author'

# --- family 2: frozen reports ------------------------------------------------

# Documents that describe the current system (README, canons except the dated
# ROADMAP, the residual register, the published site and its writeup drafts).
CURRENT_FIXED=(
  "README.md"
  "AUDIT_SCOPE_RUST.md"
  "docs/GUIDE_AUDITEUR.md"
  "docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md"
  "docs/POSITIONNEMENT.md"
  "docs/ACCEPTED_RESIDUALS_2026-06-28.md"
)
CURRENT_GLOBS=(
  "site/content"
  "docs/writeups"
)

# Phrases the rework made false. Matched case-insensitively.
STALE_CLAIMS='server-detectable|revocation cuts it off|bounded future signing|bounded[[:space:]]+\*\*future\*\*|bornée, détectable|détectable,? (et )?révocable|forger des signatures pour des sessions antérieures|no forging of past sessions|(huit|eight) (contextes|tags|signature domains)'

# Entry points and classes that no longer exist. A paragraph may name one only
# if it also says it is gone (RETIRED_MARKER, matched on the lowercased text).
RETIRED='strm_encrypt_file|upload_put_report_chunk|upload_put_directory_entry|archive_list_blobs|archive_download_and_decrypt|archive_download_raw|ChunkUploadQueueDurabilityTest|StreamChunkEncryptor|DirectoryEntryWorker|ProvenanceUploadWorker|sweepStaleChunks'
RETIRED_MARKER='retir|removed|supprim|n.existent plus|no longer|replaced|remplac'

# Print "line: first line of the paragraph" for each paragraph of $1 that
# names a retired entry point without a retirement marker.
retired_without_marker() {
  awk -v names="$RETIRED" -v marker="$RETIRED_MARKER" '
    function flush() {
      if (buf != "" && buf ~ names && tolower(buf) !~ marker) print start ": " first
      buf = ""
    }
    /^[ \t\r]*$/ { flush(); next }
    { if (buf == "") { start = NR; first = $0 } ; buf = buf "\n" $0 }
    END { flush() }
  ' "$1"
}

current_docs() {  # $1 = root; prints the relative paths of family-2 docs
  local root="$1" f d
  for f in "${CURRENT_FIXED[@]}"; do
    printf '%s\n' "$f"
  done
  for d in "${CURRENT_GLOBS[@]}"; do
    [ -d "$root/$d" ] || continue
    for f in "$root/$d"/*.md; do
      [ -f "$f" ] && printf '%s\n' "${f#"$root"/}"
    done
  done
}

# --- the scan ----------------------------------------------------------------

scan() {  # $1 = root; prints findings; returns 0 when clean
  local root="$1" fail=0 f path hits

  for f in "${CANONS[@]}"; do
    path="$root/$f"
    if [ ! -f "$path" ]; then
      echo "DOC-CURRENCY WARN: canon not found: $f"
      continue
    fi
    if grep -nEi "$BAD" "$path" >/dev/null 2>&1; then
      echo "DOC-CURRENCY FAIL: $f describes the current STRM wire as V2-with-author:"
      grep -nEi "$BAD" "$path" | sed 's/^/    /'
      fail=1
    fi
  done

  # Positive control: the authoritative wire doc must still mention V3
  # somewhere, so this guard cannot silently pass on a doc that dropped it.
  if ! grep -qE 'V3|VERSION_V3|0x03' "$root/AUDIT_SCOPE_RUST.md"; then
    echo "DOC-CURRENCY FAIL: AUDIT_SCOPE_RUST.md no longer mentions the V3 wire."
    fail=1
  fi

  while IFS= read -r f; do
    path="$root/$f"
    [ -f "$path" ] || { echo "DOC-CURRENCY WARN: not found: $f"; continue; }
    if grep -nEi "$STALE_CLAIMS" "$path" >/dev/null 2>&1; then
      echo "DOC-CURRENCY FAIL: $f repeats a claim the report rework made false:"
      grep -nEi "$STALE_CLAIMS" "$path" | sed 's/^/    /'
      fail=1
    fi
    hits="$(retired_without_marker "$path")"
    if [ -n "$hits" ]; then
      echo "DOC-CURRENCY FAIL: $f names a retired entry point as if it were current:"
      printf '%s\n' "$hits" | sed 's/^/    /'
      fail=1
    fi
  done < <(current_docs "$root")

  # Positive controls: the current docs must still carry the closure domain and
  # the residual register its limits, so a rewrite cannot silently drop them.
  for f in "AUDIT_SCOPE_RUST.md" "docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md" "docs/GUIDE_AUDITEUR.md"; do
    if ! grep -q '0x09' "$root/$f"; then
      echo "DOC-CURRENCY FAIL: $f no longer mentions the closure domain 0x09."
      fail=1
    fi
  done
  for r in R1 R1b R2 R3 R3b R4 R5 R6 R7; do
    if ! grep -qF "**$r**" "$root/docs/ACCEPTED_RESIDUALS_2026-06-28.md"; then
      echo "DOC-CURRENCY FAIL: ACCEPTED_RESIDUALS no longer lists residual $r."
      fail=1
    fi
  done

  return "$fail"
}

# --- selftest: negative controls ---------------------------------------------
#
# A copy of the real documents must pass; each injected stale claim must make
# the scan fail; a retired name WITH its marker must pass. Without this, a
# pattern that silently stopped matching would leave the oracle green forever.

selftest() {
  local tmp f bad=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  while IFS= read -r f; do
    mkdir -p "$tmp/$(dirname "$f")"
    cp "$ROOT/$f" "$tmp/$f"
  done < <( { printf '%s\n' "${CANONS[@]}"; current_docs "$ROOT"; } | sort -u)

  expect() {  # $1 = expected rc (0|1), $2 = label
    local rc=0
    scan "$tmp" >/dev/null 2>&1 || rc=1
    if [ "$rc" -ne "$1" ]; then
      echo "SELFTEST FAIL: $2 (expected rc=$1, got $rc)"
      bad=1
    else
      echo "selftest ok: $2"
    fi
  }

  inject() {  # $1 = file, $2 = appended text, $3 = expected rc, $4 = label;
              # runs one expectation, then restores the file
    local file="$1" text="$2" want="$3" label="$4"
    cp "$tmp/$file" "$tmp/$file.orig"
    printf '\n%s\n' "$text" >> "$tmp/$file"
    expect "$want" "$label"
    mv "$tmp/$file.orig" "$tmp/$file"
  }

  expect 0 "the current documents pass"
  inject ROADMAP.md "STRM: VERSION_CURRENT = 0x02 (magic+version+author)." 1 "family 1: V2-with-author"
  inject README.md "An adversary gets a bounded, server-detectable window of future signatures." 1 "server-detectable"
  inject README.md "Revocation cuts it off." 1 "revocation cuts it off"
  inject site/content/_index.md "At worst bounded future signing capacity." 1 "bounded future signing"
  inject docs/POSITIONNEMENT.md "Une capacité bornée, détectable, révocable." 1 "bornée, détectable, révocable"
  inject docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md "Ni forger des signatures pour des sessions antérieures." 1 "forger ... antérieures"
  inject README.md "Not one byte of past content, no forging of past sessions." 1 "no forging of past sessions"
  inject docs/GUIDE_AUDITEUR.md "Le jeu compte huit contextes." 1 "huit contextes"
  inject docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md "Le chunk passe par \`strm_encrypt_file\`." 1 "retired name without marker"
  inject docs/GUIDE_AUDITEUR.md "Durabilité : \`ChunkUploadQueueDurabilityTest\`." 1 "retired test name without marker"
  inject AUDIT_SCOPE_RUST.md "\`upload_put_report_chunk\` was retired with signing at upload." 0 "retired name with its marker passes"

  cp "$tmp/AUDIT_SCOPE_RUST.md" "$tmp/AUDIT_SCOPE_RUST.md.orig"
  sed 's/0x09/0x0?/g' "$tmp/AUDIT_SCOPE_RUST.md.orig" > "$tmp/AUDIT_SCOPE_RUST.md"
  expect 1 "positive control: 0x09 dropped from AUDIT_SCOPE"
  mv "$tmp/AUDIT_SCOPE_RUST.md.orig" "$tmp/AUDIT_SCOPE_RUST.md"

  cp "$tmp/docs/ACCEPTED_RESIDUALS_2026-06-28.md" "$tmp/r.orig"
  sed 's/\*\*R7\*\*/R7/g' "$tmp/r.orig" > "$tmp/docs/ACCEPTED_RESIDUALS_2026-06-28.md"
  expect 1 "positive control: residual R7 dropped from the register"
  mv "$tmp/r.orig" "$tmp/docs/ACCEPTED_RESIDUALS_2026-06-28.md"

  expect 0 "restored documents pass again"
  return "$bad"
}

if [ "${1:-}" = "selftest" ]; then
  if selftest; then
    echo "doc-currency selftest OK."
    exit 0
  fi
  echo "doc-currency selftest FAILED."
  exit 1
fi

if scan "$ROOT"; then
  echo "doc-currency OK: no current doc describes the STRM wire as V2-with-author, repeats a claim the report rework made false, or names a retired entry point as current."
  exit 0
fi
exit 1
