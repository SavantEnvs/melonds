#!/usr/bin/env bash
#
# mayhem/build.sh — build melonDS's bundled libslirp fuzz harnesses (src/net/libslirp/fuzzing) and its test oracle.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

SL="$SRC/src/net/libslirp"
FZ="$SL/fuzzing"
DOMAIN='-DG_LOG_DOMAIN="Slirp"'

# 1) libslirp (the vendored copy melonDS ships, with its glib shim) — twice, both with
#    sanitizers + DWARF 3, minus UBSan's `alignment` check: slirp overlays struct qlink / tcpiphdr on
#    the mbuf data at 4-byte offsets by design (tcp_input.c:263), which trips it on EVERY TCP packet
#    and would make all tcp* targets die on their seeds. Benign on x86. One build with libFuzzer coverage instrumentation (fuzz binaries) and one
#    without (the -standalone reproducers, which have no libFuzzer runtime to satisfy the coverage hooks).
build_slirp() {  # <build-dir> <extra flags>
  cmake -S "$SL" -B "$1" -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fno-sanitize=alignment $2" >/dev/null
  cmake --build "$1" -j"$MAYHEM_JOBS"
}
build_slirp "$SRC/build/slirp-fuzz" "-fsanitize=fuzzer-no-link"
build_slirp "$SRC/build/slirp-plain" ""

# 2) Harnesses. Every target in mayhem/targets.txt is "<binary> <harness source>"; several binaries
#    (tftp/dhcp/udp-d, ...) share a source and differ only in seeds, so each source is built once.
#    The harness TUs get the same -fno-sanitize=alignment (they walk pcap records through unaligned
#    struct pointers); every other UBSan check stays on and halting.
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/build/lsan_off.o"
COMMON="-include $SRC/mayhem/glib_compat.h -I$SL/glib -I$SL/src -I$SRC/build/slirp-fuzz $DOMAIN"
HFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fno-sanitize=alignment"
declare -A built
while read -r name src; do
  [ -n "$name" ] || continue
  if [ -z "${built[$src]:-}" ]; then
    "$CC" $HFLAGS -DCUSTOM_MUTATOR $COMMON $LIB_FUZZING_ENGINE \
        "$FZ/$src" "$FZ/helper.c" "$SRC/build/lsan_off.o" "$SRC/build/slirp-fuzz/libslirp.a" \
        -o "$SRC/$name"
    "$CC" $HFLAGS $COMMON "$STANDALONE_FUZZ_MAIN" \
        "$FZ/$src" "$FZ/helper.c" "$SRC/build/lsan_off.o" "$SRC/build/slirp-plain/libslirp.a" \
        -o "$SRC/$name-standalone"
    built[$src]="$name"
  else
    cp -f "$SRC/${built[$src]}" "$SRC/$name"
    cp -f "$SRC/${built[$src]}-standalone" "$SRC/$name-standalone"
  fi
done < "$SRC/mayhem/targets.txt"

# 3) Test oracle with the project's NORMAL flags: a known-answer selftest (public API) plus
#    libslirp's own ncsitest (assert-based).
mkdir -p "$SRC/build-tests"
cmake -S "$SL" -B "$SRC/build-tests/slirp" -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$SRC/build-tests/slirp" -j"$MAYHEM_JOBS"
"$CC" -O1 $COVERAGE_FLAGS -I"$SL/src" -I"$SRC/build-tests/slirp" "$SRC/mayhem/slirp_selftest.c" \
    "$SRC/build-tests/slirp/libslirp.a" -o "$SRC/build-tests/slirp_selftest"
"$CC" -O1 $COVERAGE_FLAGS -I"$SL/glib" -I"$SL/src" -I"$SRC/build-tests/slirp" -DBUILDING_LIBSLIRP \
    '-DG_LOG_DOMAIN="Slirp"' "$SL/test/ncsitest.c" \
    "$SRC/build-tests/slirp/libslirp.a" -o "$SRC/build-tests/ncsitest"
