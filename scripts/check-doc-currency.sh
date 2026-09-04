#!/usr/bin/env bash
# check-doc-currency.sh — doc-currency anti-regression oracle.
#
# Fails if a canon or authoritative doc still describes the CURRENT STRM wire as
# "V2-with-author". The pre-publication F-C1 / WP-A removal made V3 the
# current format, with NO `author_ed25519_pk` at rest (the motto: "a seizure
# exposes nothing"). Source of truth: crypto-rs/stream/src/header.rs.
#
# Keep the signatures below narrow. Legacy prose is legitimate — a doc may say
# the author key was removed in V3, or that V1/V2 carried one — and widening the
# pattern to catch more makes the oracle ring on correct docs, after which
# someone turns it off for good.
#
# It was added after the 2026-06-30 cross-audit (BT-06) found GUIDE_AUDITEUR /
# ROADMAP / AUDIT_SCOPE still describing the old V2 wire while the code shipped
# V3.
#
# Usage: bash scripts/check-doc-currency.sh   (exit 0 = OK, 1 = stale doc)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

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

fail=0
for f in "${CANONS[@]}"; do
  path="$ROOT/$f"
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

# Positive control: the authoritative wire doc must still mention V3 somewhere,
# so this guard cannot silently pass on a doc that dropped the V3 description.
if ! grep -qE 'V3|VERSION_V3|0x03' "$ROOT/AUDIT_SCOPE_RUST.md"; then
  echo "DOC-CURRENCY FAIL: AUDIT_SCOPE_RUST.md no longer mentions the V3 wire."
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "doc-currency OK: no canon describes the current STRM wire as V2-with-author."
fi
exit "$fail"
