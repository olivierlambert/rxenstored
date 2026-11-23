#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Run a command that may use a lot of memory (cbmc under Kani, rustc on a
# large crate, a mutant's runaway test) in its own cgroup with a hard
# memory limit, so that it is the only thing that dies when it grows.
#
#   scripts/cage.sh [-m SIZE] COMMAND [ARG...]
#
#   -m SIZE   the limit, as systemd writes it (4G, 2500M). Default:
#             $CAGE_MEM_MAX, else the memory available now less 768 MB.
#
# Why: on a machine with little memory and no free swap, the kernel's
# global OOM killer kills the largest process; that process is in the
# terminal's systemd scope (tmux-spawn-*.scope, OOMPolicy=stop), and
# systemd then stops the whole scope: the shell, the editor and whatever
# started the run go down with it (seen with rustc under cargo-mutants
# and with cbmc at 6 GB). A loop that polls `ps` and kills above a
# threshold is not a guard: cbmc grows by gigabytes between two polls.
#
# How: `systemd-run --user --scope` moves the command out of the
# terminal's scope into one of its own, with
#   MemoryMax        the limit; the kernel kills inside this cgroup only;
#   MemorySwapMax=0  no swap, so the limit is the whole of it;
#   OOMPolicy=continue  the rest of the command survives the kill (cargo
#                    reports the failure) instead of the scope stopping;
# and oom_score_adj 900, so that if the machine runs out anyway (another
# process grew), the kernel picks the caged command first.
#
# Exit status: the command's. A process killed by the limit dies of
# SIGKILL (137 from a shell).

set -euo pipefail

mem=${CAGE_MEM_MAX:-}
if [ "${1:-}" = -m ]; then
    mem=${2:?cage.sh: -m needs a size}
    shift 2
fi
[ $# -gt 0 ] || { echo "usage: cage.sh [-m SIZE] COMMAND [ARG...]" >&2; exit 2; }

if [ -z "$mem" ]; then
    avail_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    mem_mb=$((avail_kb / 1024 - 768))
    if [ "$mem_mb" -lt 512 ]; then
        echo "cage.sh: only $((avail_kb / 1024)) MB available: not starting $1" >&2
        exit 2
    fi
    mem=${mem_mb}M
fi

echo 900 >/proc/self/oom_score_adj 2>/dev/null || true

if systemd-run --user --scope --quiet -p MemoryMax=64M true 2>/dev/null; then
    exec systemd-run --user --scope --quiet \
        -p "MemoryMax=$mem" -p MemorySwapMax=0 -p OOMPolicy=continue -- "$@"
fi

# No systemd user manager (a container, CI): limit the address space
# instead. Coarser (virtual, per process), but it still stops a runaway.
echo "cage.sh: no systemd user scope: falling back to ulimit -v" >&2
case "$mem" in
    *G) kb=$((${mem%G} * 1024 * 1024)) ;;
    *M) kb=$((${mem%M} * 1024)) ;;
    *K) kb=${mem%K} ;;
    *) kb=$((mem / 1024)) ;;
esac
ulimit -v "$kb"
exec "$@"
