#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Sanitizer gate.
#
#   scripts/sanitize.sh SANITIZER [CRATE...]
#
# SANITIZER: address (AddressSanitizer, with its leak checker), thread
# (ThreadSanitizer), memory (MemorySanitizer, with origins) or leak
# (LeakSanitizer alone). CRATE: default xs-sys xs-daemon xs-sim xs-core
# xs-wire. Runs every test target of each crate (unit tests, integration
# tests; not the doc tests) built with the sanitizer, the standard library
# rebuilt with it too (-Zbuild-std), for x86_64-unknown-linux-gnu. The
# daemon binary the integration tests of xs-daemon start
# (CARGO_BIN_EXE_rxenstored) is part of the same build, so it is
# instrumented as well; a report of any process (a test or a daemon it
# started) goes to a file, target/sanitize/SANITIZER/report.PID, so a
# report from a daemon whose exit no test checks is not lost.
#
# Pass: every test passes and no report file exists. The last line says
# which. Logs: target/sanitize/SANITIZER/CRATE.log.
#
# Needs: the nightly toolchain with rust-src (rustup toolchain install
# nightly --component rust-src). Environment: SANITIZE_TARGET_DIR (default
# target/sanitize/SANITIZER/build), the build directory, about 1.5 GB per
# sanitizer; XS_MODEL_SEEDS and XS_MODEL_STEPS for a shorter xs-core model
# test (crates/xs-core/tests/model.rs), unset by default.
#
# Not covered: what the tests do not run (the real Xen devices,
# privcmd/evtchn/gntdev ioctls on a host, crates/xs-sys/examples/xen_probe.rs);
# libc and the kernel are not instrumented (MemorySanitizer relies on its
# libc interceptors, ThreadSanitizer sees no ordering through the kernel,
# e.g. a write to an eventfd that wakes an epoll wait in another thread:
# the code under test hands no memory over that way); xs-bench is not run.
# Skipped tests, with their reasons, are listed below (SKIP) and printed.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

usage() {
    sed -n '5,37p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

[ $# -ge 1 ] || usage
SAN=$1
shift
case "$SAN" in
    address | thread | memory | leak) ;;
    *) usage ;;
esac
if [ $# -gt 0 ]; then CRATES=("$@"); else CRATES=(xs-sys xs-daemon xs-sim xs-core xs-wire); fi
for c in "${CRATES[@]}"; do
    [ -d "crates/$c" ] || { echo "sanitize.sh: no crate $c" >&2; exit 2; }
done
[ -d "$(rustc +nightly --print sysroot 2>/dev/null)/lib/rustlib/src/rust/library" ] || {
    echo "sanitize.sh: nightly with rust-src is missing: rustup toolchain install nightly --component rust-src" >&2
    exit 2
}

# Tests that cannot be meaningful under a sanitizer: CRATE:SANITIZER:TEST:reason.
SKIP=(
    "xs-daemon:leak:a_failed_fork_is_reported:the daemon runs under prlimit --nproc=1, so LeakSanitizer alone cannot fork its checker at the exit and ends the process with its own exit code (23), which the test checks (under AddressSanitizer the same test passes, without a leak check)"
)

OUT=target/sanitize/$SAN
mkdir -p "$OUT"
rm -f "$OUT"/report.*
TARGET=x86_64-unknown-linux-gnu
export CARGO_TARGET_DIR=${SANITIZE_TARGET_DIR:-$OUT/build}
flags="-Zsanitizer=$SAN -Cdebuginfo=1"
[ "$SAN" = memory ] && flags="$flags -Zsanitizer-memory-track-origins"
export RUSTFLAGS="$flags"
export RUSTDOCFLAGS="$flags"
report=$PWD/$OUT/report
export ASAN_OPTIONS="log_path=$report:detect_leaks=1:abort_on_error=0:symbolize=1"
export TSAN_OPTIONS="log_path=$report:halt_on_error=0:second_deadlock_stack=1"
export MSAN_OPTIONS="log_path=$report"
export LSAN_OPTIONS="log_path=$report"

status=0
summary=()
for c in "${CRATES[@]}"; do
    skips=()
    for s in "${SKIP[@]}"; do
        IFS=: read -r sc ss st sr <<<"$s"
        if [ "$sc" = "$c" ] && { [ "$ss" = '*' ] || [ "$ss" = "$SAN" ]; }; then
            skips+=(--skip "$st")
            echo "SKIP $c $st: $sr"
        fi
    done
    features=()
    if grep -q '^gnttab = ' "crates/$c/Cargo.toml"; then features=(--features gnttab); fi
    echo "== $SAN $c"
    start=$(date +%s)
    set +e
    cargo +nightly test --no-fail-fast -Zbuild-std --target "$TARGET" -p "$c" "${features[@]}" --lib --bins --tests \
        -- "${skips[@]}" >"$OUT/$c.log" 2>&1
    rc=$?
    set -e
    elapsed=$(($(date +%s) - start))
    passed=$(grep -o '[0-9]* passed' "$OUT/$c.log" | awk '{s += $1} END {print s + 0}')
    failed=$(grep -o '[0-9]* failed' "$OUT/$c.log" | awk '{s += $1} END {print s + 0}')
    line="  $c: $passed passed, $failed failed, exit $rc, $((elapsed / 60)) min $((elapsed % 60)) s"
    echo "$line"
    summary+=("$line")
    if [ $rc -ne 0 ]; then
        grep -E '^test .* FAILED|^error|panicked at' "$OUT/$c.log" | head -n 20 || true
        status=1
    fi
done

echo
echo "== sanitize $SAN summary (logs in $OUT/)"
printf '%s\n' "${summary[@]}"
# LeakSanitizer checks a process at its exit from a forked tracer: in a
# process that may not fork (xs-daemon's a_failed_fork_is_reported starts
# the daemon under `prlimit --nproc=1`) it cannot run and says so. Such a
# report says nothing about the code: it is listed, it does not fail.
for r in "$OUT"/report.*; do
    [ -e "$r" ] || continue
    if grep -q 'TestPTrace() failed to fork' "$r" &&
        ! grep -v -E 'TestPTrace\(\) failed to fork|LeakSanitizer has encountered a fatal error|HINT: ' "$r" | grep -q .; then
        echo "   no leak check (the process could not fork): $r"
    elif ! grep -v -E '^WARNING: failed decoding unknown ioctl 0x[0-9a-f]+$' "$r" | grep -q .; then
        # MemorySanitizer cannot tell what the Xen ioctls (_IOC_NONE with a
        # size, xen/abi.rs) read or write: it says so, and checks nothing
        # for them. Not a finding; listed.
        echo "   ioctls MemorySanitizer cannot decode (not checked): $r"
    else
        echo "   REPORT: $r"
        status=1
    fi
done
if [ $status -eq 0 ]; then
    echo "== sanitize $SAN: pass"
else
    echo "== sanitize $SAN: FAIL"
fi
exit $status
