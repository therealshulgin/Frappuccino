#!/usr/bin/env bash
#
# Like libuniffi_frappuccino.so, the produced .so is NOT git-tracked
# (mobile/src/main/jniLibs/ is gitignored); this source + script are the
# tracked, reproducible artifacts, so after a clean clone libtcpcc.so is simply
# absent and this script is what puts it back. Do not commit one. Kotlin loads
# it fail-safe, so a missing .so degrades to "cc unknown / bbr not applied",
# never a crash — that degradation is deliberate, do not harden it into a
# startup check or a fatal error.
#
# The ABI list at the bottom must stay aligned with the ABIs the APK packages:
# the script builds libtcpcc.so for each of them into
# mobile/src/main/jniLibs/<abi>/. An ABI added to the packaging but not here
# fails nothing; it just leaves the devices of that ABI in the silent degraded
# mode above.
#
# See tcpcc.c for the why (Phase 0a transport stopgap, docs/TRANSPORT_PLAN.md).
#
# Run after editing tcpcc.c:
#   bash mobile/src/main/cpp/build-tcpcc.sh
#
# Prereqs: ANDROID_NDK_HOME (or NDK auto-located under the SDK) + the NDK
# clang toolchain. API level overridable via API=NN.
set -euo pipefail

CPP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNI_DIR="$(cd "$CPP_DIR/../jniLibs" 2>/dev/null && pwd || echo "$CPP_DIR/../jniLibs")"
API="${API:-21}"

# Locate the NDK: explicit env first, else the highest-versioned SDK ndk/*.
NDK="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
if [ -z "$NDK" ]; then
  SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}}"
  NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[ -n "$NDK" ] && [ -d "$NDK" ] || { echo "ERROR: NDK not found (set ANDROID_NDK_HOME)"; exit 1; }

# Host tag + clang suffix (.cmd on Windows).
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64; EXT=.cmd ;;
  Darwin)               HOST=darwin-x86_64;  EXT= ;;
  *)                    HOST=linux-x86_64;   EXT= ;;
esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST/bin"

build_one() {
  abi="$1"; triple="$2"
  cc="$BIN/${triple}${API}-clang${EXT}"
  out="$JNI_DIR/$abi/libtcpcc.so"
  mkdir -p "$JNI_DIR/$abi"
  echo "[$abi] $(basename "$cc") -> $out"
  "$cc" -O2 -fPIC -shared -Wall -Wextra -o "$out" "$CPP_DIR/tcpcc.c"
}

build_one arm64-v8a   aarch64-linux-android
build_one armeabi-v7a armv7a-linux-androideabi
build_one x86_64      x86_64-linux-android

echo "libtcpcc.so built for all ABIs (API $API)."
