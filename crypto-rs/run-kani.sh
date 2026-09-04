#!/usr/bin/env bash
#
# run-kani.sh — run the Kani bounded-model-checking proof harnesses
# (ROADMAP 8.4 item ③). See docs/KANI_PROOFS.md for what is proven.
#
# Kani needs Linux or macOS — there is no Windows build. On Windows, run this
# from WSL (Ubuntu). One-time prereqs inside the Linux/WSL env:
#
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#   . "$HOME/.cargo/env"
#   cargo install --locked kani-verifier
#   cargo kani setup
#
# The repo pins Rust 1.88 via rust-toolchain.toml, which would override Kani's
# own bundled toolchain and break the run. So we verify against a throwaway
# copy of the workspace with that file removed — the real tree is untouched.
# (Running over /mnt/c from WSL also keeps Linux build artifacts out of the
# Windows `target/`.)
#
# Usage:
#   ./run-kani.sh                 # every harness, and assert how many there are
#   ./run-kani.sh --harness NAME  # one harness (the count check is skipped)
#   ./run-kani.sh selftest        # check the summary parser, no Kani needed
#
# The core crate's only Kani harness (the provenance manifest parser's no-panic
# proof) was retired with the manifest itself (lean "hash + Bitcoin" model,
# 2026-06-25); the remaining proofs live in the stream crate.
#
# WHY THIS SCRIPT COUNTS INSTEAD OF JUST RUNNING
#
# `cargo kani` exits non-zero when a proof FAILS, so a broken proof was already
# caught. What it cannot tell you is that a proof STOPPED EXISTING: delete a
# harness, rename it, drop its `#[kani::proof]`, or cfg it out of the build, and
# the run is still green — with less proven. The suite would quietly shrink and
# every report would keep saying "Kani: verified".
#
# That is the same defect this repo fixed in run-tamarin.sh on 2026-08-28, one
# file over, and it is the reason both runners now assert a count rather than
# trusting an exit code. A proof suite that cannot notice its own proofs leaving
# is a suite whose green means "nothing objected", not "everything held".
set -euo pipefail

# Every harness in crypto-rs/stream/src/kani_proofs.rs must be verified. Bump
# this deliberately when adding or removing one, in the same commit, so the
# change is visible in review rather than absorbed silently.
EXPECTED_HARNESSES=5

die() { echo "[run-kani] FAIL: $*" >&2; exit 1; }

# --- summary parsing --------------------------------------------------------
# Kani ends a full run with:
#
#   Manual Harness Summary:
#   Complete - 5 successfully verified harnesses, 0 failures, 5 total.
#
# These three helpers are the only place that shape is interpreted, so
# `selftest` can exercise them on a machine where Kani is not installed.

summary_line() {   # $1 = file holding raw kani output
  grep -E "successfully verified harnesses" "$1" | tail -1 | tr -d '\r'
}

summary_field() {  # $1 = file, $2 = one of verified|failures|total
  local line; line="$(summary_line "$1")"
  [ -n "$line" ] || return 1
  case "$2" in
    verified) sed -E 's/.*- ([0-9]+) successfully verified.*/\1/' <<< "$line" ;;
    failures) sed -E 's/.*verified harnesses, ([0-9]+) failures.*/\1/' <<< "$line" ;;
    total)    sed -E 's/.*failures, ([0-9]+) total.*/\1/'          <<< "$line" ;;
    *)        return 1 ;;
  esac
}

# --- selftest ---------------------------------------------------------------
# A parser that silently stops parsing would make every assertion below vacuous,
# so it is checked too, including on Windows where Kani cannot run at all.
if [ "${1:-}" = "selftest" ]; then
  T="$(mktemp)"
  cat > "$T" <<'FIXTURE'
Checking harness check_parse_header_never_panics...
VERIFICATION:- SUCCESSFUL

Manual Harness Summary:
Complete - 5 successfully verified harnesses, 0 failures, 5 total.
FIXTURE
  fails=0
  check() {  # $1 = what, $2 = got, $3 = want
    if [ "$2" = "$3" ]; then echo "  ok    $1 -> $2"
    else echo "  ECHEC $1 -> got '$2', want '$3'"; fails=$((fails + 1)); fi
  }
  check "verified" "$(summary_field "$T" verified)" "5"
  check "failures" "$(summary_field "$T" failures)" "0"
  check "total"    "$(summary_field "$T" total)"    "5"

  # A run that lost a harness: the counts agree with each other and are still
  # wrong. This is exactly the case the exit code cannot see, so the parser has
  # to read the number rather than the coherence.
  cat > "$T" <<'FIXTURE'
Manual Harness Summary:
Complete - 4 successfully verified harnesses, 0 failures, 4 total.
FIXTURE
  check "harnais manquant, verified" "$(summary_field "$T" verified)" "4"
  check "harnais manquant, total"    "$(summary_field "$T" total)"    "4"

  # A failing run.
  cat > "$T" <<'FIXTURE'
Manual Harness Summary:
Complete - 4 successfully verified harnesses, 1 failures, 5 total.
FIXTURE
  check "echec, verified" "$(summary_field "$T" verified)" "4"
  check "echec, failures" "$(summary_field "$T" failures)" "1"

  # No summary at all (Kani died before finishing): must report nothing rather
  # than invent a number.
  : > "$T"
  check "sans resume" "$(summary_field "$T" verified || echo '')" ""

  rm -f "$T"
  [ "$fails" -eq 0 ] || die "$fails selftest assertion(s) failed"
  echo "[run-kani] selftest OK"
  exit 0
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # crypto-rs (workspace root)
WORK="$(mktemp -d)/crypto-rs"
mkdir -p "$WORK"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude target --exclude .git --exclude 'mutants.out*' "$SRC/" "$WORK/"
else
  cp -r "$SRC/." "$WORK/"
fi
rm -f "$WORK/rust-toolchain.toml"

cd "$WORK"
echo "Running Kani from $WORK (rust-toolchain.toml removed so Kani uses its bundled toolchain)..."

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

# Output and exit code are kept separately: piping into `tee` alone would hand
# us tee's status and hide a Kani crash. `--no-default-features` drops the
# `protocol` feature (reqwest + rustls + tokio), which Kani cannot tractably
# model and which the parser proofs do not need.
code=0
cargo kani -p frappuccino-crypto-stream --no-default-features "$@" 2>&1 | tee "$OUT" || code="${PIPESTATUS[0]}"
[ "$code" -eq 0 ] || die "cargo kani exited $code"

verified="$(summary_field "$OUT" verified || true)"
failures="$(summary_field "$OUT" failures || true)"
total="$(summary_field "$OUT" total || true)"
[ -n "$verified" ] || die "no harness summary in the output — Kani did not finish a run"

[ "$failures" -eq 0 ] || die "$failures harness(es) failed"
[ "$verified" -eq "$total" ] || die "$verified verified but $total ran"

# `--harness` runs one on purpose, so the count would be wrong by design.
if [ "$#" -eq 0 ]; then
  [ "$verified" -eq "$EXPECTED_HARNESSES" ] || die \
    "expected $EXPECTED_HARNESSES harnesses, got $verified (one was added, removed, renamed or cfg'd out: update EXPECTED_HARNESSES deliberately)"
  echo "[run-kani] OK: $verified/$EXPECTED_HARNESSES harnesses verified, 0 failures"
else
  echo "[run-kani] OK: $verified verified, 0 failures (count check skipped for $*)"
fi
