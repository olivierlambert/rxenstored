#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Runs one fuzz target of fuzz/ for SECONDS, then adds the run to the
# totals of $FUZZ_DIR/STATUS.txt.
#
#   scripts/fuzz.sh TARGET SECONDS [MAX_LEN]   (0 seconds: build only)
#   scripts/fuzz.sh --status                   rewrite STATUS.txt from the totals
#   scripts/fuzz.sh --list                     the targets
#
# MAX_LEN: the longest input libFuzzer makes (default per target, below);
# a run with a MAX_LEN given keeps its own corpus, corpus/TARGET-MAX_LEN.
#
# Environment (all optional):
#   FUZZ_DIR        where everything a run writes goes (default
#                   <checkout>/target/fuzz): build directories, corpus/T
#                   (grows; fuzz/seeds/T is read too, never written),
#                   artifacts/T (crash-*, timeout-*, oom-*: inputs that
#                   failed), logs/, totals/ and STATUS.txt
#   FUZZ_TOOLCHAIN  the rustup toolchain (default nightly)
#   RSS_MB          memory limit per process, MiB (default 1024)
#   NICE            niceness (default 10)
#
# Needs a nightly toolchain and cargo-fuzz (fuzz/README.md). libFuzzer
# stops at the first failing input; the script saves it and starts again
# until SECONDS have passed. An input that takes more than 10 s is a
# timeout. An input of the corpus that fails as soon as it is loaded is
# moved to artifacts/T/failing-corpus/, so that the run can go on.
#
# To reproduce a failing input:  $FUZZ_DIR/target-*/x86_64-unknown-linux-gnu/release/T FILE
# (core_requests prints its actions with FUZZ_TRACE=1); to minimise one:
#   cd fuzz && cargo +nightly fuzz tmin T FILE

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FUZZ_DIR=${FUZZ_DIR:-$ROOT/target/fuzz}
FUZZ_TOOLCHAIN=${FUZZ_TOOLCHAIN:-nightly}
RSS_MB=${RSS_MB:-1024}
NICE=${NICE:-10}
export PATH="$HOME/.cargo/bin:$PATH"

TARGETS="core_requests core_requests_native core_vs_model ring wire_decode config options native_config native_options log_format"

# The sanitizer of a target: AddressSanitizer for the one over unsafe code.
sanitizer() {
    case "$1" in
        ring) echo address ;;
        *) echo none ;;
    esac
}

dict() {
    case "$1" in
        core_requests | core_requests_native | core_vs_model) echo "$ROOT/fuzz/dict/core.dict" ;;
        wire_decode | ring) echo "$ROOT/fuzz/dict/wire.dict" ;;
        config | options) echo "$ROOT/fuzz/dict/config.dict" ;;
        native_config | native_options) echo "$ROOT/fuzz/dict/native.dict" ;;
    esac
}

# The default longest input. core_requests (and core_requests_native): 4 KiB keeps an input to a few
# milliseconds; the recorded VM start of its seeds (up to 34 KiB) is
# replayed whole by a run with MAX_LEN 65536.
max_len() {
    case "$1" in
        core_vs_model) echo 16384 ;;
        *) echo 4096 ;;
    esac
}

# The seeds of a target: core_requests_native takes core_requests's (the
# same inputs, the core in the native profile).
seeds() {
    case "$1" in
        core_requests_native) echo "$ROOT/fuzz/seeds/core_requests" ;;
        *) echo "$ROOT/fuzz/seeds/$1" ;;
    esac
}

target_dir() {
    echo "$FUZZ_DIR/target-$(sanitizer "$1")"
}

# STATUS.txt from totals/NAME (one line per run: start end seconds execs
# cov ft) and the artifacts.
status() {
    local out="$FUZZ_DIR/STATUS.txt.new" t f
    {
        echo "fuzzing status, written $(date -u '+%Y-%m-%d %H:%M:%S UTC') by scripts/fuzz.sh"
        echo "FUZZ_DIR=$FUZZ_DIR"
        cat "$FUZZ_DIR"/night*.plan 2>/dev/null || true
        echo
        echo "Running now:"
        for f in "$FUZZ_DIR"/running/*; do
            if [ -e "$f" ]; then echo "  $(cat "$f")"; fi
        done
        echo
        printf '%-22s %6s %9s %14s %8s %7s %7s %8s %8s\n' target runs cpu_s execs exec/s cov ft corpus failing
        for f in "$FUZZ_DIR"/totals/*; do
            [ -s "$f" ] || continue
            t=${f##*/}
            local runs secs execs cov ft rate=- corpus failing
            read -r runs secs execs cov ft < <(awk '{r++; s+=$3; e+=$4; c=$5; f=$6} END {print r, s, e, c, f}' "$f")
            if [ "$secs" -gt 0 ]; then rate=$((execs / secs)); fi
            corpus=$(find "$FUZZ_DIR/corpus/$t" -type f 2>/dev/null | wc -l)
            failing=$(find "$FUZZ_DIR/artifacts/${t%%-*}" -maxdepth 1 -type f \( -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' -o -name 'leak-*' \) 2>/dev/null | wc -l)
            printf '%-22s %6s %9s %14s %8s %7s %7s %8s %8s\n' "$t" "$runs" "$secs" "$execs" "$rate" "$cov" "$ft" "$corpus" "$failing"
        done
        echo
        echo "cpu_s: seconds of one process (an upper bound on its CPU time on a loaded machine);"
        echo "cov/ft: libFuzzer's coverage (edges) and features at the end of the last run;"
        echo "failing: inputs saved in $FUZZ_DIR/artifacts/TARGET (crash-*, timeout-*, oom-*)."
    } >"$out"
    mv "$out" "$FUZZ_DIR/STATUS.txt"
}

case "${1:-}" in
    --status)
        mkdir -p "$FUZZ_DIR/totals" "$FUZZ_DIR/running"
        exec 9>"$FUZZ_DIR/status.lock"
        flock 9
        status
        exit 0
        ;;
    --list)
        echo "$TARGETS"
        exit 0
        ;;
esac

[ $# -eq 2 ] || [ $# -eq 3 ] || { sed -n '5,33p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
T=$1
SECS=$2
case " $TARGETS " in *" $T "*) ;; *) echo "fuzz.sh: unknown target $T ($TARGETS)" >&2; exit 2 ;; esac
if [ $# -eq 3 ]; then
    LEN=$3
    NAME=$T-$LEN
else
    LEN=$(max_len "$T")
    NAME=$T
fi

mkdir -p "$FUZZ_DIR"/{corpus/"$NAME",artifacts/"$T"/failing-corpus,logs,totals,running}
TD=$(target_dir "$T")
BIN="$TD/x86_64-unknown-linux-gnu/release/$T"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# The pid too: two slots of fuzz-night.sh may start the same target at once.
LOG="$FUZZ_DIR/logs/$NAME-$STAMP-$$.log"

# Build (a no-op if nothing changed). If the build fails, an existing binary runs.
if ! (cd "$ROOT/fuzz" && CARGO_TARGET_DIR="$TD" nice -n "$NICE" cargo "+$FUZZ_TOOLCHAIN" fuzz build -a -s "$(sanitizer "$T")" "$T") >"$LOG.build" 2>&1; then
    echo "fuzz.sh: build of $T failed (see $LOG.build)" >&2
    [ -x "$BIN" ] || exit 1
fi
[ "$SECS" -gt 0 ] || { rm -f "$LOG" "$LOG.build"; exit 0; }

ARGS=(
    -rss_limit_mb="$RSS_MB" -malloc_limit_mb="$RSS_MB" -timeout=10
    -max_len="$LEN"
    -artifact_prefix="$FUZZ_DIR/artifacts/$T/"
    -print_final_stats=1
)
D=$(dict "$T")
if [ -n "$D" ] && [ -f "$D" ]; then ARGS+=(-dict="$D"); fi
SEEDS=()
if [ -d "$(seeds "$T")" ]; then SEEDS=("$(seeds "$T")"); fi

echo "$NAME: started $(date -u '+%H:%M:%S') for ${SECS}s (pid $$, log $LOG)" >"$FUZZ_DIR/running/$$"
"$0" --status || true
START=$(date +%s)
DEADLINE=$((START + SECS))
EXECS=0 COV=- FT=- LAST_FAILED=
: >"$LOG"
# One libFuzzer process at a time; after a failing input, another, until
# the deadline.
while :; do
    LEFT=$((DEADLINE - $(date +%s)))
    [ "$LEFT" -ge 10 ] || break
    PART="$LOG.part"
    # The ASan build needs no leak checking (a fuzz input that leaks is not
    # what is looked for) and must not hide its own aborts.
    ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:symbolize=1} \
        timeout --kill-after=60 $((LEFT + 300)) nice -n "$NICE" "$BIN" "${ARGS[@]}" -max_total_time="$LEFT" \
        "$FUZZ_DIR/corpus/$NAME" "${SEEDS[@]}" >"$PART" 2>&1 || true
    cat "$PART" >>"$LOG"
    N=$(sed -nE 's/^stat::number_of_executed_units: *([0-9]+).*/\1/p' "$PART" | tail -1)
    EXECS=$((EXECS + ${N:-0}))
    L=$(grep -E '^#[0-9]+[[:space:]].* cov: ' "$PART" | tail -1 || true)
    C=$(echo "$L" | sed -nE 's/.* cov: ([0-9]+).*/\1/p')
    F=$(echo "$L" | sed -nE 's/.* ft: ([0-9]+).*/\1/p')
    [ -n "$C" ] && COV=$C
    [ -n "$F" ] && FT=$F
    # Stopped on a failing input: libFuzzer names it by the SHA-1 of its
    # bytes, as it names the files of a corpus.
    FAILED=$(sed -nE 's/.*Test unit written to .*\/(crash|timeout|oom|leak)-([0-9a-f]{40}).*/\2/p' "$PART" | tail -1)
    rm -f "$PART"
    [ -n "$FAILED" ] || break
    if [ "$FAILED" = "$LAST_FAILED" ]; then
        if [ -f "$FUZZ_DIR/corpus/$NAME/$FAILED" ]; then
            mv "$FUZZ_DIR/corpus/$NAME/$FAILED" "$FUZZ_DIR/artifacts/$T/failing-corpus/"
        else
            echo "fuzz.sh: $T fails again on input $FAILED, which is not in its corpus (a seed?): run stopped" >&2
            break
        fi
    fi
    LAST_FAILED=$FAILED
done
END=$(date +%s)
rm -f "$FUZZ_DIR/running/$$"
echo "$START $END $((END - START)) $EXECS $COV $FT" >>"$FUZZ_DIR/totals/$NAME"
"$0" --status || true
echo "$NAME: $EXECS executions in $((END - START))s, cov $COV, ft $FT; log $LOG"
