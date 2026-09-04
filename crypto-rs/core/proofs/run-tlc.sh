#!/usr/bin/env bash
#
# run-tlc.sh — model-check the EphemeralRatchet FSM with TLA+/TLC
# (ROADMAP 8.4 item 4). See docs/TLA_RATCHET.md for what is proven.
#
# TLC is pure Java, so this runs anywhere with a JRE — Windows, Linux, macOS;
# no WSL needed (unlike Kani/Tamarin). Requires `java` on PATH (JDK/JRE 11+).
#
# Downloads tla2tools.jar (the TLC model checker) into .tools/ on first run.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$DIR/.tools/tla2tools.jar"

if [ ! -f "$JAR" ]; then
  mkdir -p "$DIR/.tools"
  echo "downloading tla2tools.jar (TLC model checker)..."
  curl -sSL --fail --retry 5 --retry-delay 3 -o "$JAR" \
    https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
fi

cd "$DIR"
exec java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
  -config EphemeralRatchet.cfg EphemeralRatchet.tla
