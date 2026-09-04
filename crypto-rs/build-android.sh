#!/usr/bin/env bash
#
# build-android.sh — compile frappuccino-crypto-ffi for Android ABIs and
# generate Kotlin UniFFI bindings.
#
# Prerequisites:
#   - rustup toolchain 1.80.0 with Android targets (installed via rust-toolchain.toml)
#   - cargo-ndk (cargo install cargo-ndk)
#   - Android NDK r26+ (set ANDROID_NDK_HOME)
#
# Output:
#   target/<android-target>/release/libuniffi_frappuccino.so   (per ABI)
#   copied to ../mobile/src/main/jniLibs/<abi>/libuniffi_frappuccino.so
#   plus uniffi.frappuccino.* Kotlin bindings under ../mobile/build/generated/source/uniffi/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ANDROID_NDK_HOME must point to the NDK root. If unset, try common Windows paths.
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    if [[ -d "$HOME/AppData/Local/Android/Sdk/ndk" ]]; then
        # Pick the latest NDK present.
        LATEST_NDK="$(ls -v "$HOME/AppData/Local/Android/Sdk/ndk" 2>/dev/null | tail -n1)"
        if [[ -n "$LATEST_NDK" ]]; then
            export ANDROID_NDK_HOME="$HOME/AppData/Local/Android/Sdk/ndk/$LATEST_NDK"
            echo "Auto-detected ANDROID_NDK_HOME=$ANDROID_NDK_HOME"
        fi
    fi
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]] || [[ ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "ERROR: ANDROID_NDK_HOME not set or invalid." >&2
    echo "Install NDK r26+ via Android Studio SDK Manager, then export:" >&2
    echo "  export ANDROID_NDK_HOME=\$HOME/AppData/Local/Android/Sdk/ndk/<version>" >&2
    exit 1
fi

# STRICT_PROVENANCE=1 refuses to build unless the tree matches HEAD exactly.
# The release workflow sets it; a developer build does not, and nothing about a
# developer build changes.
#
# It exists because the manifest emitted at the bottom of this script is only
# worth anything if a third party can go back to the source it names. The first
# public manifest recorded `git_describe=a6b81c3-dirty` for a commit that was in
# no public history at all, which is the state an external review (2026-08-28,
# finding F-04) called out: a binary attested against source nobody can fetch is
# not attested. The check runs here, before the fifteen minutes of compiling, so
# a release build that cannot be honest fails immediately.
#
# Untracked files count. `git describe --dirty` ignores them, but a file that
# exists here and in no clone is a build input the auditor does not have.
#
# The `-- :/` pathspec is load-bearing. `git ls-files` is scoped to the CURRENT
# DIRECTORY, and this script runs from crypto-rs/, so without it the check saw
# only its own subtree: measured 2026-09-04, 0 untracked files from crypto-rs/
# against 22 at the repository root. A release build would have passed while the
# tree carried inputs no clone has. `:/` means "from the repository root", which
# is what the sentence above always claimed. (`diff-index` above needs no such
# fix: it covers the whole repository regardless of cwd, verified separately.)
if [[ "${STRICT_PROVENANCE:-0}" != "0" ]]; then
    if ! git -C "$SCRIPT_DIR" rev-parse HEAD > /dev/null 2>&1; then
        echo "ERROR: STRICT_PROVENANCE is set but this is not a git checkout," >&2
        echo "so the manifest could not name a commit to attest against." >&2
        exit 1
    fi
    if ! git -C "$SCRIPT_DIR" diff-index --quiet HEAD --; then
        echo "ERROR: STRICT_PROVENANCE is set and there are uncommitted changes." >&2
        echo "The manifest would record a -dirty tree that no one else can check out:" >&2
        git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no >&2
        exit 1
    fi
    untracked="$(git -C "$SCRIPT_DIR" ls-files --others --exclude-standard -- :/)"
    if [[ -n "$untracked" ]]; then
        echo "ERROR: STRICT_PROVENANCE is set and the tree holds untracked files." >&2
        echo "They are inputs a clone of this commit would not have:" >&2
        echo "$untracked" >&2
        exit 1
    fi
    echo "STRICT_PROVENANCE: tree is clean at $(git -C "$SCRIPT_DIR" rev-parse HEAD)"
fi

# Which ABIs to build. Override with TARGETS env var for subset builds
# (e.g. `TARGETS=arm64-v8a ./build-android.sh` during dev).
TARGETS="${TARGETS:-arm64-v8a armeabi-v7a x86_64}"

echo "Building frappuccino-crypto-ffi for: $TARGETS"
# Phase 3a (transport plan §10.9 / m4) — `--features quic` compiles the HTTP/3
# upload transport (quinn + h3 + BBR) into the shipped `.so`. Override with
# FEATURES="" for a DirectTls-only build (e.g. to measure the size delta).
FEATURES="${FEATURES-quic}"
FEATURE_ARGS=""
if [[ -n "$FEATURES" ]]; then
    FEATURE_ARGS="--features $FEATURES"
fi
echo "Cargo features: ${FEATURES:-<none>}"
# shellcheck disable=SC2086
cargo ndk $(for t in $TARGETS; do echo -n "-t $t "; done) \
    --platform 21 \
    build --release -p frappuccino-crypto-ffi $FEATURE_ARGS

# The shipped .so decodes STRM V3 only. `legacy-strm` belongs to the CLI, and the
# `-p frappuccino-crypto-ffi` above is what keeps it out: Cargo unifies features
# across a shared build graph, so a workspace-wide build would hand the FFI a
# stream crate that still parses V1/V2 and this script would package it without a
# word. Rather than trust the invocation, check the artefact. The marker is a
# `#[used]` static that exists in the binary only under the feature (see
# `stream/src/lib.rs::LEGACY_STRM_MARKER`); the Gradle gate re-checks it before
# packaging, so a hand-built .so does not slip past either.
LEGACY_MARKER="FRAPPUCCINO_LEGACY_STRM_COMPILED_IN"

JNI_DIR="../mobile/src/main/jniLibs"
mkdir -p "$JNI_DIR"
for abi in $TARGETS; do
    case "$abi" in
        arm64-v8a)   src="target/aarch64-linux-android/release" ;;
        armeabi-v7a) src="target/armv7-linux-androideabi/release" ;;
        x86)         src="target/i686-linux-android/release" ;;
        x86_64)      src="target/x86_64-linux-android/release" ;;
        *) echo "Unknown ABI: $abi" >&2; exit 1 ;;
    esac
    mkdir -p "$JNI_DIR/$abi"
    if grep -qa "$LEGACY_MARKER" "$src/libuniffi_frappuccino.so"; then
        echo "ERROR: the $abi .so carries the legacy STRM decoder (V1/V2)." >&2
        echo "The shipped library must decode V3 only. This happens when the FFI is" >&2
        echo "built in a graph that also contains the CLI, which enables" >&2
        echo "\`legacy-strm\`: Cargo unifies the feature into the stream crate for" >&2
        echo "every consumer. Build the FFI on its own (-p frappuccino-crypto-ffi)." >&2
        exit 1
    fi
    cp "$src/libuniffi_frappuccino.so" "$JNI_DIR/$abi/"
    echo "  -> $JNI_DIR/$abi/libuniffi_frappuccino.so"
done

# Generate Kotlin bindings. UniFFI 0.28 library mode reads symbols from the
# compiled .so so the generated Kotlin matches the exact exported API.
# Use the host build for library extraction (since we're on Windows cross-compile,
# we instead generate from the UDL directly which is language-agnostic).
#
# S8c.1 : bindings land in stream-crypto/ so they're accessible to the crypto
# coordination layer. `mobile` picks them up transitively as a project dep.
# The .so stays in mobile/src/main/jniLibs/ (APK-level embedding, loaded at
# runtime via System.loadLibrary).
BINDINGS_OUT="../stream-crypto/build/generated/source/uniffi/debug/java"
mkdir -p "$BINDINGS_OUT"
cargo run --bin uniffi-bindgen --quiet -- \
    generate ffi/src/frappuccino.udl \
    --language kotlin \
    --out-dir "$BINDINGS_OUT"
echo "Kotlin bindings generated at $BINDINGS_OUT"

# WP-E4 (audit 2026-06-28) — emit the .so provenance manifest. Binds the shipped
# jniLibs binaries to this commit + toolchain + their SHA-256 so the mobile gate
# `checkSoProvenance` can reject a hand-built / stale / swapped .so, and a
# third-party verifier can confirm "this .so == this commit". Regenerated on every
# build; the file is intentionally NOT hand-edited.
emit_provenance() {
    local manifest="$SCRIPT_DIR/PROVENANCE.txt"
    local pin sof abi
    pin="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$SCRIPT_DIR/rust-toolchain.toml" 2>/dev/null | head -1)"
    {
        echo "# Frappuccino — crypto .so provenance manifest (WP-E4, audit 2026-06-28)"
        echo "#"
        echo "# Regenerated by crypto-rs/build-android.sh on every build (do NOT hand-edit), and"
        echo "# deliberately NOT tracked in git: it describes binaries that are not tracked either,"
        echo "# so a committed copy could only ever describe whichever machine last built. That is"
        echo "# exactly how the first public manifest came to name a private -dirty commit."
        echo "#"
        echo "# The mobile gate checkSoProvenance (mobile/build.gradle) recomputes each shipped"
        echo "# jniLibs .so SHA-256 and FAILS the build unless it matches the sha256:<abi> lines"
        echo "# below — closing the hand-built / stale / swapped-.so gap."
        echo "#"
        echo "# WHAT A THIRD PARTY CAN CHECK, and it is worth being exact about the limits."
        echo "# The release workflow (.github/workflows/release.yml) builds from a clean public"
        echo "# commit with strict_provenance=1 and publishes this file next to the .so it"
        echo "# describes. Given a signed APK, unzip lib/<abi>/libuniffi_frappuccino.so and compare"
        echo "# its SHA-256 to the matching line here: APK signing does not alter entry contents,"
        echo "# so the digests hold across signing. That links a distributed APK to a public commit."
        echo "#"
        echo "# It does NOT establish bit-for-bit reproducibility. This script pins neither"
        echo "# SOURCE_DATE_EPOCH nor --remap-path-prefix, and absolute source paths differ between"
        echo "# machines, so rebuilding the same commit elsewhere yields different digests. The"
        echo "# claim is 'this binary came out of that run of that commit', not 'anyone can"
        echo "# recreate these bytes'. strict_provenance=0 below means a developer build: the"
        echo "# commit it names may be private, rewritten, or dirty."
        echo ""
        echo "git_commit=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "git_describe=$(git -C "$SCRIPT_DIR" describe --always --dirty 2>/dev/null || echo unknown)"
        echo "strict_provenance=${STRICT_PROVENANCE:-0}"
        echo "build_context=build-android.sh"
        echo "rustc=$(rustc --version 2>/dev/null || echo unknown)"
        echo "rust_toolchain_pin=${pin:-unknown}"
        echo "cargo_ndk=$(cargo ndk --version 2>/dev/null | head -1 || echo unknown)"
        echo "ndk=$(basename "${ANDROID_NDK_HOME:-unknown}")"
        echo "features=${FEATURES:-<none>}"
        echo "cargo_lock_sha256=$(sha256sum "$SCRIPT_DIR/Cargo.lock" 2>/dev/null | awk '{print $1}')"
        echo ""
        echo "# Per-ABI SHA-256 of mobile/src/main/jniLibs/<abi>/libuniffi_frappuccino.so"
        for abi in $TARGETS; do
            sof="$JNI_DIR/$abi/libuniffi_frappuccino.so"
            if [[ -f "$sof" ]]; then
                echo "sha256:$abi=$(sha256sum "$sof" | awk '{print $1}')"
            fi
        done
    } > "$manifest"
    echo "Provenance manifest written to $manifest"
}
emit_provenance

echo "BUILD OK"
