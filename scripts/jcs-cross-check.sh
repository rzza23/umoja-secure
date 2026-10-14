#!/usr/bin/env bash
#
# Cross-check the TS and Kotlin JCS canonicalizers.
#
# Both sides read the same three corpora and emit
# {id}\t{base64(canonical)} lines, sorted by id. This script runs both
# and diffs the output.
#
# Exit: 0 on match, 1 on divergence or on any error.
#
# Task: TASK-P1-026
# Closes: KI-012

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS_OUT="backend/build/jcs-cross-check/ts.tsv"
KOTLIN_OUT="android/app/build/jcs-cross-check/kotlin.tsv"

mkdir -p "$(dirname "$TS_OUT")"

echo "==> TS canonicalizer"
(cd backend && npx tsx src/crypto/jcs-dump.ts) > "$TS_OUT"

echo "==> Kotlin canonicalizer"
if ! (cd android && ./gradlew :app:testDebugUnitTest \
        --tests "com.umoja.secure.crypto.JcsCrossCheckTest" \
        --rerun-tasks -q); then
  echo "ERROR: Kotlin test run failed"
  exit 1
fi

if [ ! -f "$KOTLIN_OUT" ]; then
  echo "ERROR: expected Kotlin output at $KOTLIN_OUT, not found"
  exit 1
fi

echo "==> diff"
if ! diff -u <(sort "$TS_OUT") <(sort "$KOTLIN_OUT"); then
  echo ""
  echo "DIVERGENCE: TS and Kotlin JCS outputs differ."
  echo "  TS:     $TS_OUT"
  echo "  Kotlin: $KOTLIN_OUT"
  exit 1
fi

LINES=$(wc -l < "$TS_OUT" | tr -d ' ')
echo ""
echo "PASS: $LINES inputs, byte-identical output from both implementations."
