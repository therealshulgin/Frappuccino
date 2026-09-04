#!/usr/bin/env bash
#
# assert_zeroize_not_dse.sh — executable oracle for ROADMAP 8.4.2 part 2.
#
# Proves, at the LLVM-IR level, that EphemeralRatchet's secret-zeroization
# (`zeroize_secrets`, shared by `wipe()` and `Drop::drop`, wiping
# `private_keys[50][64]` + `next_chain_key`) is NOT dead-store-eliminated by
# the compiler. This is the regression tripwire for the one zeroization
# guarantee that cargo-mutants cannot cover: the `drop -> ()` mutant is
# unkillable in safe Rust (a Drop body is unobservable without reading freed
# memory = UB), so a deterministic compiler-IR check is the only oracle.
#
# It re-emits the core crate's LLVM IR at two optimization levels and asserts a
# profile-robust invariant on the body of `zeroize_secrets`:
#
#   the wipe is performed via zeroize::Zeroize  <=>  the body contains either
#     (a) inlined `store volatile` instructions (aggressive-opt form), OR
#     (b) a `call` to a `zeroize::Zeroize::zeroize` monomorphization (size-opt
#         form: the wipe stays out-of-line as real calls).
#
# A regression that swaps `.zeroize()` for `= [0; N]` / `.fill(0)` lowers to a
# non-volatile memset / plain stores with NEITHER signature, so the invariant
# fails and the guard exits non-zero.
#
# Two levels are checked because the shipping APK profile is `opt-level = "s"`
# (size) — where the wipe is OUT-OF-LINE calls and `store volatile` is absent
# from the core crate's per-crate IR (it lives in the leaf write_volatile in
# another codegen unit). A naive `grep 'store volatile'` would FALSE-FAIL on the
# very profile that ships. opt-level=2 is the methodology's DSE-aggressive
# diagnostic, where the wipe inlines and the volatile stores must survive.
#
# Stable toolchain only (no nightly): `--emit=llvm-ir` is stable. Run from
# anywhere. Exit 0 = PASS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"     # crypto-rs (cargo workspace root)
PKG="frappuccino-crypto-core"
SYM="zeroize_secrets"

emit_ll() {  # $1=opt-level  $2=dest .ll
  local opt="$1" dest="$2" td ll
  td="$(mktemp -d)"
  CARGO_TARGET_DIR="$td" cargo rustc -p "$PKG" --lib \
    --manifest-path "$WS_DIR/Cargo.toml" \
    -- --emit=llvm-ir -C opt-level="$opt" >/dev/null 2>&1
  ll="$(find "$td" -name 'frappuccino_crypto_core-*.ll' | head -1)"
  [ -n "$ll" ] || { echo "emit failed (opt=$opt): no .ll produced" >&2; rm -rf "$td"; return 1; }
  cp "$ll" "$dest"
  rm -rf "$td"
}

fn_body() {  # extract the zeroize_secrets function body from a .ll on stdin file $1
  awk '/define.*'"$SYM"'/{f=1} f{print} f&&/^}/{f=0}' "$1"
}

check_level() {  # $1=opt-level  $2=human-label
  local opt="$1" label="$2" ll body def vol zcall memset
  ll="$(mktemp -u).ll"
  emit_ll "$opt" "$ll"
  def="$(grep -c "define.*$SYM" "$ll" || true)"
  body="$(fn_body "$ll")"
  vol="$(printf '%s\n' "$body" | grep -c 'store volatile' || true)"
  # call instructions (have an @symbol) to a zeroize::Zeroize monomorphization;
  # the '@' filter excludes the human-readable `; call <.. as Zeroize>` comments
  zcall="$(printf '%s\n' "$body" | grep -E '\bcall\b' | grep -F '@' | grep -c 'Zeroize' || true)"
  memset="$(printf '%s\n' "$body" | grep -c 'llvm.memset' || true)"
  rm -f "$ll"

  printf '  [%s] opt-level=%s  defined=%s  store-volatile=%s  zeroize-calls=%s  non-volatile-memset=%s\n' \
    "$label" "$opt" "$def" "$vol" "$zcall" "$memset"

  local ok=1
  if [ "$def" -lt 1 ]; then
    echo "    FAIL: zeroize_secrets was not emitted (inlined away?) — review manually" >&2; ok=0
  fi
  if [ $(( vol + zcall )) -lt 1 ]; then
    echo "    FAIL: wipe is neither inlined-volatile nor a zeroize::Zeroize call — possible DSE/regression" >&2; ok=0
  fi
  if [ "$memset" -gt 0 ]; then
    echo "    WARN: an llvm.memset appears in the secret-wipe body — verify it is volatile (review)" >&2
  fi
  return $(( ok == 1 ? 0 : 1 ))
}

echo "zeroize-not-DSE oracle — EphemeralRatchet::$SYM (private_keys + next_chain_key)"
rc=0
check_level s  "shipping/size" || rc=1
check_level 2  "DSE-aggressive" || rc=1

if [ "$rc" -eq 0 ]; then
  echo "PASS: ratchet secret wipe preserved at both opt-level=s and opt-level=2 (no dead-store elimination)"
else
  echo "AUDIT GUARD FAILED — the ratchet secret-zeroization may have regressed" >&2
fi
exit "$rc"
