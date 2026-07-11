#!/usr/bin/env bash
#
# radare2/mayhem/build.sh -- build radare2's libr as a sanitized static library and link the
# OSS-Fuzz `ia_fuzz` harness (vendored from github.com/radareorg/radare2-fuzz, air-gapped under
# mayhem/vendor/) against it, both as a libFuzzer target and a standalone reproducer. Also builds
# a small behavioral KAT oracle (mayhem/harnesses/kat_asm.c) for mayhem/test.sh.
#
# The fuzzed surface is radare2's instruction analyzer (ia_fuzz -> `ia`/`oba` on a malloc:// buffer
# of the fuzz bytes) -- this is the ENTIRE real OSS-Fuzz build for radare2: projects/radare2/build.sh
# does `sys/static.sh` (build a static libr) then clones radare2-fuzz and `make`s every `targets/*.cc`
# against it. At the vendored radare2-fuzz commit there is exactly ONE target (ia_fuzz.cc) -- verified
# against the full upstream git history (see mayhem/vendor/radare2-fuzz/VENDORED.md) -- so this ships
# 100% of the harnesses that recipe produces.
#
# We build libr directly (skip sys/static.sh's STATIC_BINS-only-if-set CLI-tools pass and its final
# smoke test) because radare2-fuzz's own Makefile only ever needs $RADARE2_STATIC_BUILD/usr/lib/libr.a
# + headers -- never the CLI binaries -- and building those under a from-scratch clang+ASan static
# link hits an UNRELATED toolchain bug (see the two Makefile patches below) with no payoff for us.
#
# Build contract from org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/STANDALONE_FUZZ_MAIN).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX DEBUG_FLAGS

# radare2's own plugin-registration ABI casts function pointers to a generic signature
# (r_asm_plugin_add et al take a `void *`-shaped struct pointer internally) -- this is an
# intentional C plugin idiom, but UBSan's -fsanitize=function flags it as undefined behavior on
# EVERY r_core_new() call, aborting before a single fuzz iteration runs (verified: with UBSan on,
# ia_fuzz crashes on iteration 0, every run, regardless of input). OSS-Fuzz's own
# projects/radare2/project.yaml ships `sanitizers: [address]` ONLY for exactly this project, for
# exactly this reason -- so we match upstream's own accepted practice: keep whatever ASan-related
# component(s) $SANITIZER_FLAGS carries, drop only the UBSan component, for the flags we actually
# compile radare2 + the harnesses with. The container's advertised $SANITIZER_FLAGS env is left
# untouched (still ASan+UBSan, per the org build contract / static gate).
R2_SANITIZER_FLAGS=""
for tok in ${SANITIZER_FLAGS}; do
  case "$tok" in
    -fsanitize=*)
      list="$(printf '%s' "${tok#-fsanitize=}" | tr ',' '\n' | grep -v '^undefined$' | paste -sd, - || true)"
      [ -n "$list" ] && R2_SANITIZER_FLAGS="${R2_SANITIZER_FLAGS} -fsanitize=$list"
      ;;
    *) R2_SANITIZER_FLAGS="${R2_SANITIZER_FLAGS} $tok" ;;
  esac
done
R2_SANITIZER_FLAGS="${R2_SANITIZER_FLAGS# }"

# SanitizerCoverage instrumentation for the fuzzed radare2 code itself. libr.a was previously built
# with ONLY $R2_SANITIZER_FLAGS (ASan, no -fsanitize=fuzzer[-no-link]) -- so libFuzzer/Mayhem saw
# ZERO coverage edges inside radare2; the only instrumented code was the tiny ia_fuzz.cc harness TU
# (compiled+linked with $LIB_FUZZING_ENGINE=-fsanitize=fuzzer, which implies coverage). We add
# `-fsanitize=fuzzer-no-link` (coverage instrumentation only, no libFuzzer main/runtime, no conflict
# with the final link's $LIB_FUZZING_ENGINE) to libr.a's own CFLAGS/CXXFLAGS below, and also to the
# harness TU's compile flags alongside $R2_SANITIZER_FLAGS for consistency.
R2_COV_FLAGS="-fsanitize=fuzzer-no-link"

export USERCC="$CC" HOST_CC="$CC" NOLTO=1
export AR=llvm-ar

cd "$SRC"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 0) Two idempotent source patches (applied every run; no-ops once already applied) ───────────
python3 - "$SRC/libr/Makefile" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")

# (a) Skip building libr.so: linking libr's merged libr.o (ASan-instrumented) into a shared object
#     makes clang's driver pull the STATIC ASan runtime into the .so, colliding with symbols already
#     baked into libr.o (".preinit_array section is not allowed in DSO" / duplicate-symbol errors).
#     We never need libr.so (only libr.a, to link the fuzz harness), so just don't build it.
# NOTE: matched by EXACT line (not substring) -- "\t$(MAKE) libr.${EXT_SO}" is also a PREFIX of the
# unrelated recursive rule "\t$(MAKE) libr.${EXT_SO} WITH_LIBR=1" a few lines down.
old_a = "\t$(MAKE) libr.${EXT_SO}"
new_a = "\t@true # mayhem: skip libr.so (ASan-static-runtime clash when linked into a DSO; only libr.a is needed for the fuzz harness)"
n_a = sum(1 for l in lines if l == old_a)
if n_a:
    assert n_a == 1, n_a
    lines = [new_a if l == old_a else l for l in lines]

# (b) libr.o is built via `clang -r -nostdlib --whole-archive ...` (a RELOCATABLE partial link, just
#     combining every component .a into one .o). clang's driver adds the sanitizer runtime to ANY
#     link-shaped invocation whenever -fsanitize=... is present in $(CFLAGS) -- including `-r` mode --
#     so libr.o ends up with a full baked-in copy of the ASan runtime. Then linking OUR harness
#     against libr.a (which also wants the runtime) collides with that baked-in copy ("multiple
#     definition of `__asan_check_load_add_16_RBX'", etc). `-fno-sanitize-link-runtime` suppresses
#     runtime linking for JUST this partial-link recipe (each .o was already compiled+instrumented
#     per-file beforehand; we only want to stop RE-linking the runtime at this aggregation step).
old_b = "\t$(CC) -r -nostdlib $(CFLAGS) $(WHOLEFLAG) -o libr.o $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}"
new_b = "\t$(CC) -r -nostdlib -fno-sanitize-link-runtime $(CFLAGS) $(WHOLEFLAG) -o libr.o $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}"
n_b = sum(1 for l in lines if l == old_b)
if n_b:
    assert n_b == 1, n_b
    lines = [new_b if l == old_b else l for l in lines]

open(p, 'w').write("\n".join(lines))
print("mayhem: libr/Makefile patches applied (idempotent)")
PYEOF

# ── 1) Configure + build libr.a (sanitized + SanCov-instrumented), skipping libr.so and the CLI
#       tools (binr) ────────────────────────────────────────────────────────────────────────────
export CFLAGS="${R2_SANITIZER_FLAGS} ${R2_COV_FLAGS} ${DEBUG_FLAGS}"
export CXXFLAGS="${CFLAGS}"

./configure-plugins
./configure --prefix=/usr --without-gpl --with-libr --quiet

make -j"${MAYHEM_JOBS}" plugins.cfg libr/include/r_version.h
make -j"${MAYHEM_JOBS}" -C shlr sdbs
make -j"${MAYHEM_JOBS}" -C shlr/zip
make -j"${MAYHEM_JOBS}" -C libr/util
make -j"${MAYHEM_JOBS}" -C libr/socket
make -j"${MAYHEM_JOBS}" -C shlr
make -j"${MAYHEM_JOBS}" -C libr

LIBR_A="$SRC/libr/libr.a"
[ -f "$LIBR_A" ] || { echo "ERROR: $LIBR_A not produced" >&2; exit 1; }
echo "built radare2 libr.a: $(du -h "$LIBR_A" | cut -f1)"

# ── 2) Assemble a $RADARE2_STATIC_BUILD dist dir (mirrors OSS-Fuzz's r2-static/usr layout) ──────
RADARE2_STATIC_BUILD="$BUILD/r2static-dist"
rm -rf "$RADARE2_STATIC_BUILD"
mkdir -p "$RADARE2_STATIC_BUILD/usr/lib" "$RADARE2_STATIC_BUILD/usr/include/libr/sdb"
cp "$LIBR_A" "$RADARE2_STATIC_BUILD/usr/lib/libr.a"
cp -r "$SRC/libr/include/." "$RADARE2_STATIC_BUILD/usr/include/libr/"
cp -r "$SRC/subprojects/sdb/include/sdb/." "$RADARE2_STATIC_BUILD/usr/include/libr/sdb/"
export RADARE2_STATIC_BUILD

# ── 3) Build the vendored radare2-fuzz harness (mayhem/vendor/radare2-fuzz/targets/ia_fuzz.cc) ──
# The vendored Makefile builds EVERY targets/*.cc (there is exactly one: ia_fuzz.cc) against
# $RADARE2_STATIC_BUILD/usr/lib/libr.a -- we replicate its exact compile+link recipe ourselves
# (rather than shelling out to `make`) so it links directly against our merged libr.a.
# -fuse-ld=lld: the default bfd `ld` takes 5-10+ MINUTES to link against our single giant
# merged-object libr.a; lld does the identical link in ~1-2s.
R2FUZZ_TARGETS="$SRC/mayhem/vendor/radare2-fuzz/targets"

$CXX -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${R2_COV_FLAGS} ${DEBUG_FLAGS} \
    -I "${RADARE2_STATIC_BUILD}/usr/include/libr" -I "${RADARE2_STATIC_BUILD}/usr/include/libr/sdb" \
    "$R2FUZZ_TARGETS/ia_fuzz.cc" \
    "${RADARE2_STATIC_BUILD}/usr/lib/libr.a" -lpthread -lutil -ldl -lm \
    "$LIB_FUZZING_ENGINE" \
    -o /mayhem/ia_fuzz

# ── 4) Standalone reproducer (no libFuzzer runtime), same harness source ────────────────────────
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
$CC ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"
$CXX -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} \
    -I "${RADARE2_STATIC_BUILD}/usr/include/libr" -I "${RADARE2_STATIC_BUILD}/usr/include/libr/sdb" \
    "$R2FUZZ_TARGETS/ia_fuzz.cc" "$BUILD/standalone_main.o" \
    "${RADARE2_STATIC_BUILD}/usr/lib/libr.a" -lpthread -lutil -ldl -lm \
    -o /mayhem/ia_fuzz-standalone

# ── 5) Behavioral KAT oracle for mayhem/test.sh (mayhem/harnesses/kat_asm.c) ─────────────────────
# NOTE: `-x c` only applies to kat_asm.c -- `-x none` resets language detection back to
# extension-based BEFORE libr.a, or clang tries to parse the archive as C source text.
$CXX -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} \
    -I "${RADARE2_STATIC_BUILD}/usr/include/libr" -I "${RADARE2_STATIC_BUILD}/usr/include/libr/sdb" \
    -x c "$SRC/mayhem/harnesses/kat_asm.c" -x none \
    "${RADARE2_STATIC_BUILD}/usr/lib/libr.a" -lpthread -lutil -ldl -lm \
    -o /mayhem/kat_asm

echo ""
echo "build.sh complete:"
ls -lh /mayhem/ia_fuzz /mayhem/ia_fuzz-standalone /mayhem/kat_asm
