#!/usr/bin/env bash
# mayhem/test.sh — runs the known-answer selftest build.sh produced (mayhem/selftest/kdc_selftest.cpp):
# NetworkPacket parse/serialize values, DeviceInfo identity validation and name filtering, and an mdns.h
# PTR record decoded to its expected name. Counts PASS/FAIL lines; a neutered binary prints none.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem/build-test/kdc_selftest"
EXPECTED=22
if [ ! -x "$BIN" ]; then
  echo "missing $BIN — run mayhem/build.sh first" >&2
  emit_ctrf "kdc-selftest" 0 "$EXPECTED"
  exit 1
fi
out="$(LC_ALL=C.UTF-8 QT_QPA_PLATFORM=offscreen "$BIN" 2>&1)"; rc=$?
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out" || true)
failed=$(grep -c '^FAIL ' <<<"$out" || true)
# Cases that never reported (binary died or was neutered) count as failures.
missing=$(( EXPECTED - passed - failed ))
[ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1
emit_ctrf "kdc-selftest" "$passed" "$failed"
