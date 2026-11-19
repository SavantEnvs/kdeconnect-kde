#!/usr/bin/env bash
# mayhem/build.sh — builds KDE Connect's core library (core/) with the fuzz flags, the fuzz
# harnesses + standalone reproducers, and (with normal flags) the known-answer selftest that
# mayhem/test.sh runs. See mayhem/CMakeLists.txt for why core/ is built from a harness-side
# CMake file instead of upstream's top-level one (Qt >= 6.9 + the full GUI stack).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export CC CXX
cd "$SRC"

# Standalone run-once driver, compiled as C so its LLVMFuzzerTestOneInput reference is unmangled.
mkdir -p mayhem/build-fuzz
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/standalone_main.o

# 1) core/ + the Qt harness, instrumented (SanCov on the library too, so the fuzzer sees its edges).
cmake -S mayhem -B mayhem/build-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=None \
  -DKDC_FUZZ=ON \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
  -DKDC_FUZZ_LINK="$LIB_FUZZING_ENGINE" \
  -DKDC_STANDALONE_OBJ="$SRC/mayhem/build-fuzz/standalone_main.o"
cmake --build mayhem/build-fuzz -j"$MAYHEM_JOBS"
cp mayhem/build-fuzz/fuzz_networkpacket mayhem/build-fuzz/fuzz_networkpacket-standalone "$SRC/"

# 2) mdns.h (header-only; KDE's copy is C++). No Qt needed.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC" \
  mayhem/harnesses/fuzz_mdns.cpp mayhem/lsan_off.cc -o "$SRC/fuzz_mdns"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC" mayhem/harnesses/fuzz_mdns.cpp mayhem/lsan_off.cc \
  mayhem/build-fuzz/standalone_main.o -o "$SRC/fuzz_mdns-standalone"

# 3) Known-answer selftest with the project's normal flags (run by mayhem/test.sh).
cmake -S mayhem -B mayhem/build-test -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DKDC_FUZZ=OFF \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build mayhem/build-test -j"$MAYHEM_JOBS"
