#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Two oracles, both pre-built by mayhem/build.sh with normal flags (no sanitizers):
#  1. upstream_tests: facil.io's own tests/default.c driver (mustache, fiobj, http helpers, RESP; its
#     fio_test() step is stubbed out in build.sh because it is not container-stable).
#     It aborts on any failed FIO_ASSERT. We require exit 0 AND the exact list of "=== <section>"
#     banners, so a binary that exits early (or a patch that skips sections) fails.
#  2. kat: known-answer probe (mayhem/kat.c). Its output is diffed line by line against the golden
#     values below (JSON, mustache, base64, SHA, URL parse, query parse, HTTP/1, RESP, WebSocket).
for b in upstream_tests kat; do
  [ -x "/mayhem/$b" ] || { echo "missing /mayhem/$b — build.sh should have produced it" >&2; emit_ctrf "facil.io" 0 1; exit 1; }
done

GOLDEN_SECTIONS=$(cat <<'EOS'
=== Testing Mustache parser (mustache_parser.h)
=== FIOBJ Tests ===
=== Testing Strings
=== Testing Numbers
=== Testing Floats
=== Testing Array
=== Testing Hash
=== Testing Primitives
=== Testing fioj_each2
=== Testing fioj_iseq with nested items
=== testing fiobj_data
=== Testing JSON parser (simple test)
=== Testing JSON formatting (simple test)
=== Testing JSON parsing (UTF-8 and special cases)
=== FIOBJ Done ===
=== Testing HTTP helpers
EOS
)
GOLDEN_KAT=$(cat <<'EOS'
json consumed 44
json out {"a":[1,2.5,"x\ny"],"b":null,"c":{"d":true}}
json bad consumed 5
mustache Hi World! <1><2> <b> &lt;b&gt;.
base64 Zm9vYmFy
base64 decoded fooba
sha1 a9993e364706816aba3e25717850c26c9cd0d89d
sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
url http|user|pw|host.io|8080|/p/a|q=1&r=2|t
atol 31
ltoa -1234567
query {"a":1,"b":"x y","c":2.5}
decode_url 7 a b+c d
time 29 Sun, 06 Nov 1994 08:49:37 GMT
http1 consumed 69/69 M=POST;P=/a/b;Q=x=1;V=HTTP/1.1;HN=host;HV=Example.COM;HN=content-length;HV=5;B=hello;REQ=;
resp array 3
resp string 3
resp chunk foo
resp number -42
resp null
resp message
resp resend 0
ws wrap 81026869
ws msg hi first=1 last=1 text=1
ws left 0
ws client len 12
ws msg masked first=1 last=1 text=0
ws left 0
ws ping ok
EOS
)

passed=0; failed=0

ut_out=$(timeout 600 /mayhem/upstream_tests 2>&1); ut_rc=$?
if [ "$ut_rc" -eq 0 ]; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL upstream_tests exit code $ut_rc" >&2; fi

got_sections=$(printf '%s\n' "$ut_out" | grep '^=== ')
while IFS= read -r want; do
  if printf '%s\n' "$got_sections" | grep -qxF -- "$want"; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL missing section: $want" >&2; fi
done <<< "$GOLDEN_SECTIONS"
if [ "$(printf '%s\n' "$got_sections" | wc -l)" -ne "$(printf '%s\n' "$GOLDEN_SECTIONS" | wc -l)" ]; then
  failed=$((failed+1)); echo "FAIL unexpected number of upstream test sections" >&2
fi

kat_out=$(timeout 60 /mayhem/kat 2>/dev/null)
while IFS= read -r want; do
  if printf '%s\n' "$kat_out" | grep -qxF -- "$want"; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL kat: expected line: $want" >&2; fi
done <<< "$GOLDEN_KAT"
if [ "$(printf '%s\n' "$kat_out" | wc -l)" -ne "$(printf '%s\n' "$GOLDEN_KAT" | wc -l)" ]; then
  failed=$((failed+1)); echo "FAIL kat printed an unexpected number of lines" >&2
fi

emit_ctrf "facil.io-tests+kat" "$passed" "$failed"
