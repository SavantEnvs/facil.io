#!/usr/bin/env bash
#
# mayhem/build.sh — build facil.io's fuzz harnesses (sanitized), standalone reproducers, and the
# upstream test suite + KAT probe (normal flags, for mayhem/test.sh).
#
# facil.io is a plain-C library with no configure step: every library .c file is compiled straight
# from the tree (the same file set the upstream makefile builds, minus the optional OpenSSL TLS
# backend and the Redis engine). Build output goes under tmp/, which upstream's .gitignore covers.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIBDIR=lib/facil
INCLUDES="-I$SRC -I$SRC/$LIBDIR -I$SRC/$LIBDIR/fiobj -I$SRC/$LIBDIR/http -I$SRC/$LIBDIR/http/parsers -I$SRC/$LIBDIR/redis -I$SRC/$LIBDIR/cli -I$SRC/$LIBDIR/tls"
LIB_SOURCES="
  $LIBDIR/fio.c
  $LIBDIR/fiobj/fio_siphash.c
  $LIBDIR/fiobj/fiobject.c
  $LIBDIR/fiobj/fiobj_ary.c
  $LIBDIR/fiobj/fiobj_data.c
  $LIBDIR/fiobj/fiobj_hash.c
  $LIBDIR/fiobj/fiobj_json.c
  $LIBDIR/fiobj/fiobj_mustache.c
  $LIBDIR/fiobj/fiobj_numbers.c
  $LIBDIR/fiobj/fiobj_str.c
  $LIBDIR/http/http.c
  $LIBDIR/http/http1.c
  $LIBDIR/http/http_internal.c
  $LIBDIR/http/websockets.c
  $LIBDIR/tls/fio_tls_missing.c
  $LIBDIR/cli/fio_cli.c
  $LIBDIR/redis/redis_engine.c
"

# build_lib <outdir> <flags...>: compile every library source into <outdir>/libfacil.a
build_lib() {
  local out="$1"; shift
  rm -rf "$out"; mkdir -p "$out"
  local objs=() src
  for src in $LIB_SOURCES; do
    local obj="$out/$(echo "$src" | tr '/' '_').o"
    "$CC" "$@" $INCLUDES -c "$src" -o "$obj" &
    objs+=("$obj")
    while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
  done
  wait
  rm -f "$out/libfacil.a"
  ar rcs "$out/libfacil.a" "${objs[@]}"
}

# 1) The library with sanitizers + SanCov. FIO_FORCE_MALLOC routes fio_malloc to libc malloc so ASan
#    sees every heap access (facil.io's own arena allocator would hide overflows inside its blocks).
#    -fno-sanitize=pointer-overflow,null,object-size,alignment: facil.io relies on NULL-pointer idioms that halt
#    every target on its first input under -fno-sanitize-recover: `&ptr->member` on a NULL base (the
#    FIO_LS_EMBD_OBJ container-of in fio_lib_init at process startup; fiobj_str_buf ->
#    fio_str_capa_assert) and `s->ordered + s->pos` on a NULL, empty set (fio.h set destructor).
#    clang reports these through the null / object-size type-check handlers, and fio_json_parser.h
#    does plain uint64_t loads/stores at unaligned addresses (benign on x86, but it halts json and
#    mustache within seconds). So exactly those four UBSan checks are relaxed; ASan still traps a
#    real NULL dereference and the rest of UBSan stays on and halting.
FUZZ_OUT=tmp/mayhem-fuzz
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow,null,object-size,alignment -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -DFIO_FORCE_MALLOC=1"
build_lib "$FUZZ_OUT" $FUZZ_FLAGS

# 2) Harnesses: a libFuzzer binary and a run-once standalone reproducer for each.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_OUT/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$FUZZ_OUT/lsan_off.o"

HARNESSES="fuzz_json fuzz_mustache fuzz_http1 fuzz_websocket fuzz_resp fuzz_http_request fuzz_fio_util fuzz_fiobj"
build_harness() {
  local h="$1"
  $CC $FUZZ_FLAGS $INCLUDES $LIB_FUZZING_ENGINE \
      "mayhem/$h.c" "$FUZZ_OUT/lsan_off.o" "$FUZZ_OUT/libfacil.a" -lpthread -lm -o "/mayhem/$h"
  $CC $FUZZ_FLAGS -DMAYHEM_STRICT_INVARIANTS $INCLUDES \
      "mayhem/$h.c" "$FUZZ_OUT/standalone_main.o" "$FUZZ_OUT/lsan_off.o" "$FUZZ_OUT/libfacil.a" \
      -lpthread -lm -o "/mayhem/$h-standalone"
}
for h in $HARNESSES; do
  build_harness "$h" &
  while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
wait

# 3) The test side, with the project's normal flags (no sanitizers): upstream's own test driver
#    (tests/default.c, DEBUG build: fio, fiobj, mustache, http and RESP self-tests) and the
#    known-answer probe that test.sh diffs against golden output.
#    tests/default.c's main() starts with fio_test(), which is not usable as an oracle in a container:
#    fio_malloc_test() writes through memory whose mapping depends on the kernel's mmap layout
#    (SIGSEGV in fio_memcpy) and fio_socket_test() is a loopback accept race ("accept error: EAGAIN").
#    So the driver is compiled with fio_test renamed to a no-op stub (driver plumbing only; no library
#    source is touched) and the fio.h utilities are covered by the known-answer probe instead.
TEST_OUT=tmp/mayhem-test
build_lib "$TEST_OUT" -O2 -DDEBUG=1 $COVERAGE_FLAGS
$CC -O2 -DDEBUG=1 $COVERAGE_FLAGS $INCLUDES -Dfio_test=mayhem_skip_fio_test tests/default.c mayhem/test_stub.c \
    "$TEST_OUT/libfacil.a" -lpthread -lm -o /mayhem/upstream_tests
$CC -O2 -DDEBUG=1 $COVERAGE_FLAGS $INCLUDES mayhem/kat.c mayhem/kat_resp.c "$TEST_OUT/libfacil.a" \
    -lpthread -lm -o /mayhem/kat
