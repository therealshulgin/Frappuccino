#!/usr/bin/env bash
# check-diag-dex.sh -- is the diagnostics upload compiled into an APK?
#
# A pre-release test build (version name ending in -testN) carries the code
# that sends logs to the test relay; any other version must not carry a line of
# it (mobile/build.gradle switches the source set on the version name). This
# looks for the endpoint path in the APK's dex files and checks the answer
# against what the caller expects.
#
# Usage:
#   bash scripts/check-diag-dex.sh <apk> present   # a test build
#   bash scripts/check-diag-dex.sh <apk> absent    # any other version
#
# Fails closed: a missing APK, an APK without any classes*.dex, or a grep that
# errors is a failure, never a pass. Without that, "absent" would be reported
# for an APK that was never looked at.
set -euo pipefail

NEEDLE='/diag/v1/logs'
apk="${1:-}"
want="${2:-}"

case "$want" in
  present|absent) ;;
  *) echo "usage: $0 <apk> present|absent" >&2; exit 2 ;;
esac

if [ -z "$apk" ] || [ ! -f "$apk" ]; then
  echo "FAIL: no APK at '${apk}'"
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! unzip -q -o "$apk" 'classes*.dex' -d "$work"; then
  echo "FAIL: could not extract classes*.dex from $apk"
  exit 1
fi
shopt -s nullglob
dexes=("$work"/classes*.dex)
shopt -u nullglob
if [ "${#dexes[@]}" -eq 0 ]; then
  echo "FAIL: $apk holds no classes*.dex"
  exit 1
fi

# grep: 0 = found, 1 = not found, anything else = could not look.
set +e
grep -qaF -- "$NEEDLE" "${dexes[@]}"
rc=$?
set -e
case "$rc" in
  0) found=present ;;
  1) found=absent ;;
  *) echo "FAIL: grep could not read the dex files of $apk (exit $rc)"; exit 1 ;;
esac

echo "$apk: ${#dexes[@]} dex file(s), '$NEEDLE' $found"
if [ "$found" != "$want" ]; then
  echo "FAIL: expected the diagnostics endpoint to be $want"
  exit 1
fi
echo "ok: $want, as expected"
