#!/usr/bin/env bash
#
# Reproducible runner for the Tamarin symbolic (Dolev-Yao) proof of the V2
# ephemeral-ratchet enrollment / rotation / auth protocol.
#
# Tamarin requires Linux or macOS (it shells out to Maude, a Haskell + Maude
# toolchain) -- on Windows run this from WSL. Self-contained: on first run it
# downloads the tamarin-prover and Maude binaries into .tools/ (gitignored),
# then proves RatchetProtocol.spthy. GraphViz (`dot`) is NOT needed for batch
# proving and is intentionally not installed.
#
# Usage:
#   ./run-tamarin.sh             # prove every lemma (the baseline result)
#   ./run-tamarin.sh negative    # additionally run the negative controls
#   ./run-tamarin.sh selftest    # check the verdict parser, no Tamarin needed
#
# Baseline (tamarin 1.12.0, Maude 3.5.1): 10 lemmas verified, ~4-6 s. The
# archive-scope flow was retired, so `archive_auth_origin` and the long-term-key
# NC3 control are gone: the long-term key now signs only enrollment, leaving no
# cross-context surface for NC3 to demonstrate.
#
# WHY THIS SCRIPT ASSERTS INSTEAD OF PRINTING
#
# `tamarin-prover` exits 0 even when a lemma comes back `falsified`, and it exits
# 0 when it gives up with `analysis incomplete`. A runner that only pipes the
# summary to the terminal therefore reports success for a broken proof. Worse,
# the negative controls used to end in `|| true` with a pattern that accepted
# `verified` -- the one verdict that must never appear there. A control that
# cannot fail proves nothing, which is exactly the claim this suite exists to
# support, so every verdict below is now asserted and the script exits non-zero
# the moment one does not hold.
set -euo pipefail

TAMARIN_VERSION="1.12.0"
MAUDE_VERSION="3.5.1"

# The main model must come back with exactly this many verified lemmas. A lemma
# that silently disappears from the .spthy would otherwise still give a green
# run: fewer proofs, same exit code.
EXPECTED_VERIFIED=10

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$SCRIPT_DIR/.tools"
SPTHY="$SCRIPT_DIR/RatchetProtocol.spthy"

# --- verdict parsing --------------------------------------------------------
# Tamarin's summary block lists one line per lemma:
#   lemma_name (all-traces): verified (23 steps)
#   lemma_name (all-traces): falsified - found trace (10 steps)
#   lemma_name (all-traces): analysis incomplete (1 steps)
# These two helpers are the only place that shape is interpreted, so `selftest`
# can exercise them without Tamarin installed.

summary_block() {   # $1 = file holding raw tamarin output
  sed -n '/summary of summaries/,/^====/p' "$1"
}

verdict_for() {     # $1 = file, $2 = lemma name -> prints the verdict, or nothing
  summary_block "$1" \
    | grep -E "^[[:space:]]*$2[[:space:]]*\(" \
    | head -1 \
    | sed -E 's/.*\)[[:space:]]*:[[:space:]]*//; s/[[:space:]]*\(.*//; s/[[:space:]]*-.*//' \
    | tr -d '\r'
}

count_verdict() {   # $1 = file, $2 = verdict word -> prints how many lemmas got it
  summary_block "$1" | grep -cE "\)[[:space:]]*:[[:space:]]*$2" || true
}

die() { echo "[run-tamarin] FAIL: $*" >&2; exit 1; }

# --- selftest ---------------------------------------------------------------
# A parser that cannot misread is worth asserting too: if a later edit loosens
# `verdict_for`, this catches it on any machine, including the ones where
# Tamarin does not run.
if [ "${1:-}" = "selftest" ]; then
  T="$(mktemp)"
  cat > "$T" <<'FIXTURE'
summary of summaries:

analyzed: RatchetProtocol.spthy

  ltk_secrecy (all-traces): verified (12 steps)
  auth_slot_origin (all-traces): falsified - found trace (7 steps)
  rotation_authentic (all-traces): analysis incomplete (1 steps)

==============================================================================
FIXTURE
  fails=0
  check() {  # $1 = what, $2 = got, $3 = want
    if [ "$2" = "$3" ]; then
      echo "  ok    $1 -> $2"
    else
      echo "  ECHEC $1 -> got '$2', want '$3'"; fails=$((fails + 1))
    fi
  }
  check "verdict_for verified"   "$(verdict_for "$T" ltk_secrecy)"        "verified"
  check "verdict_for falsified"  "$(verdict_for "$T" auth_slot_origin)"   "falsified"
  check "verdict_for incomplete" "$(verdict_for "$T" rotation_authentic)" "analysis incomplete"
  check "verdict_for absent"     "$(verdict_for "$T" no_such_lemma)"      ""
  check "count verified"         "$(count_verdict "$T" verified)"         "1"
  check "count falsified"        "$(count_verdict "$T" falsified)"        "1"
  rm -f "$T"
  [ "$fails" -eq 0 ] || die "$fails selftest assertion(s) failed"
  echo "[run-tamarin] selftest OK"
  exit 0
fi

mkdir -p "$TOOLS"

# --- Maude (the unification backend tamarin shells out to) ------------------
MAUDE_DIR="$TOOLS/maude-$MAUDE_VERSION"
if [ ! -x "$MAUDE_DIR/maude" ]; then
  echo "[run-tamarin] downloading Maude $MAUDE_VERSION ..."
  curl -fsSL --retry 8 -o "$TOOLS/maude.zip" \
    "https://github.com/maude-lang/Maude/releases/download/Maude${MAUDE_VERSION}/Maude-${MAUDE_VERSION}-linux-x86_64.zip"
  mkdir -p "$MAUDE_DIR"
  python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
    "$TOOLS/maude.zip" "$MAUDE_DIR"
  chmod +x "$MAUDE_DIR/maude"
fi

# --- tamarin-prover ---------------------------------------------------------
TAMARIN_BIN="$TOOLS/tamarin-prover"
if [ ! -x "$TAMARIN_BIN" ]; then
  echo "[run-tamarin] downloading tamarin-prover $TAMARIN_VERSION ..."
  curl -fsSL --retry 8 -o "$TOOLS/tamarin.tar.gz" \
    "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VERSION}/tamarin-prover-${TAMARIN_VERSION}-linux64-ubuntu.tar.gz"
  tar -xzf "$TOOLS/tamarin.tar.gz" -C "$TOOLS"
  chmod +x "$TAMARIN_BIN"
fi

export PATH="$MAUDE_DIR:$TOOLS:$PATH"
export MAUDE_LIB="$MAUDE_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Runs tamarin and keeps BOTH the output and the exit code. The pipeline used to
# swallow one or the other; here a tool crash is a failure, not a silent pass.
prove() {           # $1 = output file, remaining args = tamarin args
  local out="$1"; shift
  local code=0
  tamarin-prover "$@" +RTS -N -RTS > "$out" 2>&1 || code=$?
  return "$code"
}

echo "[run-tamarin] $(tamarin-prover --version 2>/dev/null | grep -i tamarin | head -1)"
echo "[run-tamarin] maude $(maude --version 2>/dev/null | head -1)"
echo "[run-tamarin] proving $(basename "$SPTHY") ..."

MAIN="$WORK/main.txt"
prove "$MAIN" --prove "$SPTHY" || die "tamarin-prover exited non-zero on the main model"
summary_block "$MAIN"

got_verified="$(count_verdict "$MAIN" verified)"
got_falsified="$(count_verdict "$MAIN" falsified)"
got_incomplete="$(count_verdict "$MAIN" 'analysis incomplete')"

[ "$got_falsified" -eq 0 ] || die "$got_falsified lemma(s) falsified on the main model"
[ "$got_incomplete" -eq 0 ] || die "$got_incomplete lemma(s) came back incomplete"
[ "$got_verified" -eq "$EXPECTED_VERIFIED" ] \
  || die "expected $EXPECTED_VERIFIED verified lemmas, got $got_verified (a lemma was added, removed or renamed: update EXPECTED_VERIFIED deliberately)"
echo "[run-tamarin] main model OK: $got_verified/$EXPECTED_VERIFIED verified, 0 falsified, 0 incomplete"

if [ "${1:-}" = "negative" ]; then
  echo ""
  echo "[run-tamarin] === negative controls (each MUST falsify) ==="

  # Each control breaks the model on purpose. The lemma it targets has to come
  # back `falsified`: `verified` would mean the lemma never depended on what we
  # just removed, and any other verdict means we learned nothing.
  negative_control() {   # $1 = label, $2 = lemma, $3 = sed program
    local label="$1" lemma="$2" edit="$3"
    local mutated="$WORK/$lemma.spthy" out="$WORK/$lemma.txt" code=0
    echo "[run-tamarin] $label"
    cp "$SPTHY" "$mutated"
    sed -i "$edit" "$mutated"
    cmp -s "$SPTHY" "$mutated" \
      && die "$label: the mutation changed nothing (the .spthy moved under the sed program)"
    prove "$out" --prove="$lemma" "$mutated" || code=$?
    [ "$code" -eq 0 ] || die "$label: tamarin-prover exited $code"
    local verdict; verdict="$(verdict_for "$out" "$lemma")"
    case "$verdict" in
      falsified) echo "[run-tamarin] $lemma: falsified, as required" ;;
      "")        die "$label: no verdict for $lemma (tamarin printed no summary line)" ;;
      *)         die "$label: $lemma came back '$verdict', expected 'falsified'" ;;
    esac
  }

  negative_control "NC1: drop the Ed25519 auth-signature check in Server_Verify" \
    auth_slot_origin "/verify(sig, <.auth., n>, epk)/d"

  negative_control "NC2: collapse the auth/rotate (ephemeral) domain tags" \
    rotation_authentic "s/\x27rotate\x27/\x27auth\x27/g"

  echo "[run-tamarin] negative controls OK: both falsified"
fi
