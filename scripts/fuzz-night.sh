#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# A long fuzzing session: two or four slots (processes at a time), each
# rotating through the targets of fuzz/ until HOURS have passed, by
# scripts/fuzz.sh. Shares of the time, by priority: core_requests 45 %
# (of which a sixth with inputs up to 64 KiB, which replay the recorded VM
# start of its seeds whole; with two slots 45 % of it, with four half of
# it, core_requests_native, the core in the native profile), core_vs_model
# 30 % (both profiles, by the first byte of each input), ring 12.5 %, the six
# parsers 12.5 % (wire_decode, config, options, native_config,
# native_options, log_format, about 2 % each). The slots start together.
# With two slots no target runs in both at once; with four, core_requests
# and core_vs_model at times run twice at once on the same corpus (as
# libFuzzer's own parallel jobs do: each process picks up what the other
# adds), the others never.
#
#   scripts/fuzz-night.sh [HOURS] [SLOTS]      (default 7 hours, 2 slots;
#                                              SLOTS: 2 or 4, one per CPU)
#
# Environment: FUZZ_DIR, FUZZ_TOOLCHAIN, RSS_MB, NICE as for scripts/fuzz.sh;
# FUZZ_ROOT, the checkout to fuzz when this script runs from a copy.
#
# To leave it running after the shell that started it goes:
#   setsid nohup scripts/fuzz-night.sh 7 >/dev/null 2>&1 &
# State: $FUZZ_DIR/STATUS.txt (see scripts/fuzz.sh), logs in $FUZZ_DIR/logs.
# To stop it: `pkill -f fuzz-night.sh; pkill -f scripts/fuzz.sh`, then the
# fuzzing processes (STATUS.txt names them).

set -uo pipefail

ROOT=${FUZZ_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
FUZZ_DIR=${FUZZ_DIR:-$ROOT/target/fuzz}
export FUZZ_DIR
HOURS=${1:-7}
SLOTS=${2:-2}
case $SLOTS in
    2 | "A B") SLOTS="A B" ;;
    4 | "A B C D") SLOTS="A B C D" ;;
    *) echo "fuzz-night.sh: SLOTS is 2 or 4" >&2; exit 2 ;;
esac
mkdir -p "$FUZZ_DIR/logs"

START=$(date +%s)
DEADLINE=$(awk -v s="$START" -v h="$HOURS" 'BEGIN {printf "%d", s + h * 3600}')
PLAN="$FUZZ_DIR/night-${SLOTS// /}.plan"
{
    echo "Session: started $(date -u -d "@$START" '+%Y-%m-%d %H:%M:%S UTC'), ends by $(date -u -d "@$DEADLINE" '+%Y-%m-%d %H:%M:%S UTC') ($HOURS h), slots: $SLOTS"
    echo "Driver: scripts/fuzz-night.sh (pid $$); per run: scripts/fuzz.sh"
} >"$PLAN"

# One cycle of 120 minutes per slot: TARGET:MINUTES[:MAX_LEN].
#
# Two slots, 240 minutes: core_requests 108 (45 %, 18 of them with 64 KiB
# inputs, 45 core_requests_native), core_vs_model 72 (30 %), ring 30
# (12.5 %), the parsers 5 each.
# In B's order, started with A, no target runs in both slots at once.
CYCLE2_A="core_requests:45 core_requests:9:65536 core_vs_model:36 ring:15 wire_decode:5 config:5 native_config:5"
CYCLE2_B="ring:15 core_vs_model:36 options:5 log_format:5 native_options:5 core_requests_native:45 core_requests:9:65536"
# Four slots, 480 minutes: core_requests 216 (45 %, 36 with 64 KiB
# inputs, 60 core_requests_native), core_vs_model 144 (30 %), ring 60
# (12.5 %), the parsers 10 each. A runs core_requests (its second hour
# core_requests_native) and B core_vs_model all the time; C and D
# add a second core_requests (minutes 60 to 120), a second core_vs_model
# (96 to 120), the 64 KiB inputs (0 to 36, C only), ring (C 36 to 60, D
# 60 to 96) and the parsers (D, 0 to 60).
CYCLE4_A="core_requests:60 core_requests_native:60"
CYCLE4_B="core_vs_model:60 core_vs_model:60"
CYCLE4_C="core_requests:36:65536 ring:24 core_requests:60"
CYCLE4_D="wire_decode:10 config:10 options:10 native_config:10 native_options:10 log_format:10 ring:36 core_vs_model:24"

slot() {
    local name=$1 cycle=$2 entry t m len now left secs
    while :; do
        for entry in $cycle; do
            IFS=: read -r t m len <<<"$entry"
            now=$(date +%s)
            left=$((DEADLINE - now))
            [ "$left" -lt 60 ] && return 0
            secs=$((m * 60))
            [ "$secs" -gt "$left" ] && secs=$left
            echo "[$(date -u '+%H:%M:%S')] slot $name: $t ${len:+(max_len $len) }for ${secs}s"
            "$ROOT/scripts/fuzz.sh" "$t" "$secs" ${len:+"$len"} ||
                echo "[$(date -u '+%H:%M:%S')] slot $name: $t failed"
        done
    done
}

# Build everything first, one at a time, so that the slots do not build at once.
for t in $("$ROOT/scripts/fuzz.sh" --list); do
    "$ROOT/scripts/fuzz.sh" "$t" 0 || echo "build of $t failed"
done
pids=()
n=$(echo $SLOTS | wc -w)
for s in $SLOTS; do
    cycle=CYCLE${n}_$s
    slot "$s" "${!cycle}" >>"$FUZZ_DIR/logs/session-slot-$s.log" 2>&1 &
    pids+=($!)
done
wait "${pids[@]}"
echo "Session: ended $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >>"$PLAN"
"$ROOT/scripts/fuzz.sh" --status
