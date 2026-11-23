#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Kani gate: the proof harnesses of the ring (crates/xs-sys/src/ring_proofs.rs),
# checked by Kani, a bounded model checker: each harness is proved for
# every value of its arbitrary inputs, not for samples.
#
#   scripts/kani.sh [HARNESS...]     default: all of them, in the order below
#
# Harnesses (every page byte is arbitrary when a harness starts).
#
# At RING_SIZE (1,024), the code the daemon runs, buffers short of the ring:
#   read                  Page::read, any indices, either queue, any buffer
#                         of 0 to 32 bytes: the result, the count, the
#                         indices, every page byte.
#   read_bytes            the same, buffers of 0 to 8 bytes: the bytes read.
#   write                 Page::write, buffers of 0 to 8 bytes: the result,
#                         the count, the indices, every page byte.
#   guest_to_server,      a write then a read through GuestRing and Ring on
#   server_to_guest       one page, from any valid state of the queue.
#   read_once, write_once each index word accessed once, the stored one
#                         once more; -Z stubbing (Page::word replaced by a
#                         copy that counts its calls).
#   reconnect             Ring::reconnect: both queues 0xff, the indices 0,
#                         connection CONNECTED, every other byte unchanged.
#                         Not in the default run: it does not fit in
#                         7 GB of memory (out of memory after 9 min);
#                         `scripts/kani.sh reconnect` runs it.
#   page_new              Page::new refuses a short or misaligned mapping;
#                         -Z c-ffi (a refused mapping's drop calls munmap,
#                         then a foreign function without a body).
# Every queue size from 4 to 1,024:
#   layout                Field::offset, the queues, the mask.
#   word_and_queue        Page::word and Page::queue, any word, queue, index.
# At small queue sizes N (Page<4>, <8>, <16>, <32>: the same source,
# monomorphised with another constant), buffers of 0 to 2N + 1 bytes, so
# longer than the free space, than what is queued, than the ring:
#   smallN_read, smallN_read_bytes, smallN_write, smallN_read_once,
#   smallN_write_once, smallN_reconnect
#                         as above, at N;
#   smallN_round_trip_requests, smallN_round_trip_replies
#                         a write then a read, as above, two Page<N> views;
#   small4_wwrr, small4_wrwr
#                         write, write, read, read (write, read, write,
#                         read), any lengths, against a model of the queue.
#   Run: all seven at N = 4 and 8 (round trips per queue) and the two
#   sequences; at 16 read, read_bytes (per queue), the _once pair and
#   reconnect; at 32 read, the _once pair and reconnect. The others do
#   not fit in 7 GB of memory.
# A proof at N = 16 is about Page<16>: that it carries to Page<1024> is an
# argument (same source, the size only in the queue lengths, the mask,
# the offsets and the bounds), not a proof. What is proved of Page<1024>
# is what the harnesses at RING_SIZE prove, with their buffer bounds.
# Kani's own checks are on in every harness: out-of-bounds and misaligned
# accesses, arithmetic overflow, panics, the standard library's safety
# preconditions; and each loop is proved to stop within its unwind bound.
#
# Not covered: concurrency (Kani runs one thread, an atomic access is a
# plain one, a fence is nothing: a guest writing during an operation is
# Miri's part, scripts/miri.sh); the real mapping (the page is a heap
# allocation); at RING_SIZE, Ring::reconnect, and buffers longer than 32
# bytes for read, 8 for the bytes read, write and the round trips; more
# than two operations except the two sequences at N = 4; that each queue
# byte is read once (only the index words are counted); the daemon's use
# of the ring; every function not named above.
#
# Pass: every harness reports VERIFICATION:- SUCCESSFUL and every cover
# property of it is satisfied (the paths the proof is about exist). The
# last line says which. Logs: target/kani/*.log.
#
# Needs: cargo install --locked kani-verifier && cargo kani setup
# (Kani 0.68.0, CBMC 6.11.0 were used); 5 GB of free memory for the
# largest harnesses (guest_to_server, the small round trips, the two
# sequences: 4.2 to 4.8 GB at their peak, compile included); about 100 min
# for all of them on 4 cores with 7 GB (99 min on 2026-11-22), 64 of it in
# write and the two round trips at RING_SIZE, 29 in the small harnesses.
# Environment: KANI_TIMEOUT, seconds per harness (default 3600);
# KANI_MEM_MAX, the memory limit of a harness (default: what is available
# when it starts, less 768 MB).
#
# Memory: each harness runs under scripts/cage.sh, in its own cgroup with
# a hard limit. CBMC can grow by gigabytes in seconds; without the limit
# the kernel's global OOM kill can stop the whole terminal session. With
# it, CBMC alone is killed and the harness is reported as FAIL (out of
# memory). Each summary line gives the peak memory of the harness's
# cgroup. Run a harness outside this script the same way:
#   scripts/cage.sh cargo kani -p xs-sys --harness ring::proofs::NAME --exact

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

ALL=(layout word_and_queue page_new read_once write_once read read_bytes write guest_to_server server_to_guest
    small4_reconnect small4_read_once small4_write_once small4_read small4_read_bytes small4_write
    small4_round_trip_requests small4_round_trip_replies small4_wwrr small4_wrwr
    small8_reconnect small8_read_once small8_write_once small8_read small8_read_bytes small8_write
    small8_round_trip_requests small8_round_trip_replies
    small16_reconnect small16_read_once small16_write_once small16_read small16_read_bytes_requests
    small16_read_bytes_replies
    small32_reconnect small32_read_once small32_write_once small32_read)
if [ $# -gt 0 ]; then HARNESSES=("$@"); else HARNESSES=("${ALL[@]}"); fi
for h in "${HARNESSES[@]}"; do
    case " ${ALL[*]} reconnect " in
        *" $h "*) ;;
        *) echo "kani.sh: no harness $h (see the header)" >&2; exit 2 ;;
    esac
done
cargo kani --version >/dev/null 2>&1 || {
    echo "kani.sh: Kani is missing: cargo install --locked kani-verifier && cargo kani setup" >&2
    exit 2
}

OUT=target/kani
mkdir -p "$OUT"
status=0
summary=()
for h in "${HARNESSES[@]}"; do
    case "$h" in
        page_new) flags=(-Z c-ffi) ;;
        *_once) flags=(-Z stubbing) ;;
        *) flags=() ;;
    esac
    echo "== $h"
    start=$(date +%s)
    set +e
    # In the cage: the harness, then the peak memory of the cage's cgroup
    # (the compile, then CBMC), when the cage is a systemd scope.
    # shellcheck disable=SC2016 # expanded by the inner shell
    scripts/cage.sh ${KANI_MEM_MAX:+-m "$KANI_MEM_MAX"} bash -c '
        timeout "$0" nice cargo kani -p xs-sys --harness "ring::proofs::$1" --exact "${@:2}"
        rc=$?
        cg=$(cut -d: -f3 /proc/self/cgroup)
        case "$cg" in
            */run-*.scope) echo "kani.sh: peak memory $(($(cat "/sys/fs/cgroup$cg/memory.peak") / 1048576)) MB" ;;
        esac
        exit $rc' "${KANI_TIMEOUT:-3600}" "$h" "${flags[@]}" >"$OUT/$h.log" 2>&1
    rc=$?
    set -e
    elapsed=$(($(date +%s) - start))
    result=$(grep -o 'VERIFICATION:- [A-Z]*' "$OUT/$h.log" | tail -n 1 | cut -c 16-)
    covers=$(grep -o '[0-9]* of [0-9]* cover properties satisfied' "$OUT/$h.log" | tail -n 1 || true)
    verdict=pass
    if [ $rc -ne 0 ] || [ "$result" != SUCCESSFUL ]; then
        verdict=FAIL
    elif [ -n "$covers" ] && [ "$(echo "$covers" | awk '{print $1}')" != "$(echo "$covers" | awk '{print $3}')" ]; then
        verdict="FAIL (a cover property is not satisfied)"
    fi
    [ $rc -eq 124 ] && verdict="FAIL (timeout)"
    if [ "$verdict" = FAIL ] && { grep -q 'appears to have run out of memory' "$OUT/$h.log" ||
        { [ -z "$result" ] && grep -qiE 'sigkill|signal: 9|signal 9|killed' "$OUT/$h.log"; }; }; then
        verdict="FAIL (out of memory: killed at the limit of scripts/cage.sh)"
    fi
    peak=$(grep -o 'peak memory [0-9]* MB' "$OUT/$h.log" | tail -n 1 || true)
    summary+=("  $h: $verdict, ${result:-no result}${covers:+, $covers}, exit $rc, $((elapsed / 60)) min $((elapsed % 60)) s${peak:+, $peak}")
    echo "${summary[-1]}"
    if [ "$verdict" != pass ]; then
        grep -E -B1 -A3 'Status: FAILURE|Status: UNSATISFIABLE|^error' "$OUT/$h.log" | head -n 40 || true
        status=1
    fi
done

echo
echo "== kani summary (logs in $OUT/)"
printf '%s\n' "${summary[@]}"
if [ $status -eq 0 ]; then
    echo "== kani: pass"
else
    echo "== kani: FAIL"
fi
exit $status
