# Testing

## The tests

    cargo test --workspace

None of the tests needs Xen or root. What they cover:

- **`xs-core`**: every request type, permissions, quotas, transactions, conflict credit,
  domain lifecycle and the access-log records, from bytes in to bytes out; the XSA
  regression tests (`xsa_NNN_…`, mapped to advisories in [`SECURITY.md`](SECURITY.md)).
- **The model test** (`crates/xs-core/tests/model.rs`): 450 seeded random sequences of 400
  steps over socket and guest connections, 150 of them with tight quotas, compared at every
  step with a hand-written model of oxenstored's behaviour (replies and events; the store
  every 50 steps), with the core's own recount of every quota (`Core::audit`) after each step.
  Not in the sequences: domain introduction and death, ring reconnection, conflict credit.
  The same sequences run again in native mode, against the model switched to the native
  rules ([`DESIGN.md`](DESIGN.md)); the XSA regression tests run in both modes.
- **`xs-sys`**: the ring against a racing peer on two mappings of a memfd page, wrap-around at
  every offset, corrupt indices; the Xen ABI layouts against the Linux and Xen 4.17 headers.
- **`xs-daemon`**: the event loop in process over the simulated Xen of `xs-sim` (rings,
  domain lifecycle, reconnection, failing hypercalls, an event-channel device that
  overflows), start-up and command line, both logs, the panic hook; the recorded VM start of
  `xs-bench` replayed against the daemon, and against the core to count its memory (the test
  fails above 66,000 bytes per simulated VM; about 64,500 today).

## The gates

| Gate | Command | Passes when | Needs |
|---|---|---|---|
| Lint | `scripts/lint.sh` | clippy reports nothing on any target; the no-panic lints of `Cargo.toml` are denied in all code that is not a test, except in `xs-bench` | `rustup component add clippy` |
| no_std | `scripts/nostd.sh [TARGET]` | `xs-wire` and `xs-core` build, and pass clippy, without `std` (default `x86_64-unknown-none`) | `rustup target add x86_64-unknown-none` |
| Coverage | `scripts/coverage.sh [CRATE...]` | 100 % of lines and regions for `xs-wire` and `xs-core`, 95 % of lines for `xs-sys` and `xs-daemon`; every exclusion listed, with its reason, in [`coverage-exclusions.md`](coverage-exclusions.md) | `cargo install --locked cargo-llvm-cov`, `rustup component add llvm-tools-preview` |
| Proofs | `scripts/kani.sh [HARNESS...]` | every harness is proved and every case it is meant to cover is reachable (below) | `cargo install --locked kani-verifier`, `cargo kani setup` |
| Mutation | `scripts/mutants.sh CRATE [--max-missed N]` | no missed mutant in `xs-core` and `xs-wire` (every small change cargo-mutants makes to the code fails a test); in `xs-sys` and `xs-daemon` each missed one is accounted for below | `cargo install --locked cargo-mutants` |

Coverage shows that a line ran; a missed mutant shows that the line could be wrong with no
test noticing. Each crate is measured with its own tests only. `scripts/mutants.sh` builds in
`$TMPDIR` (point it at a disk where `/tmp` is a small tmpfs).

Figures of the last full runs: coverage 100 % of lines and regions for `xs-wire` and
`xs-core`, 98.61 % of lines for `xs-sys`, 98.12 % for `xs-daemon`. Mutation: `xs-core` 1,081
mutants, 1,007 caught, 0 missed, 7 timeouts, 67 unviable; `xs-wire` 38 mutants, 34 caught, 0
missed, 1 timeout, 3 unviable. `xs-sys`: 340 mutants, 232 caught, 15 missed, 46 timeouts, 47
unviable. Of the 15, 9 change the check of a system call's result in a way no input can show
(`read` of an eventfd returns 8 or fails, never 0) and 6 are in `daemonize`, which needs a
process with one thread and so runs only in `xs-daemon`'s tests, where 3 are caught, 2 cannot
be told apart from the code and 1 (a second fork that fails) cannot be provoked. `xs-daemon`
outside `log/format.rs`: 26 missed, of which 18 no input can tell from the code and 8 need a
timing that a test cannot arrange (the first retry of a failing device, a guest notifying
while its earlier requests are held); `log/format.rs`: 529 mutants, 524 caught, 2 unviable, 3
missed that tests added since kill. 14 mutants equivalent by arithmetic alone are excluded
in `.cargo/mutants.toml`, each with its reason. These runs predate the last changes to the
log queue and the transaction byte quota.

## Proofs of the ring

    scripts/kani.sh        # about 100 minutes on 4 cores; needs 5 GB of free memory

The code that reads and writes the page shared with a guest (`crates/xs-sys/src/ring.rs`:
`read`, `write`, the reconnection, about 100 lines) is checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker: each of the 38
harnesses of `crates/xs-sys/src/ring_proofs.rs` is proved for every value of its inputs, not
for samples. The guest is modelled as the page's contents: when a harness starts, every byte
of the page is arbitrary, so every pair of indices (2^32 x 2^32) and every content of both
queues is covered.

What is proved, for a read and for a write:

- no access outside the page, no misaligned access, no panic, no arithmetic overflow;
- indices that describe more than the queue holds are refused, with the two values read, and
  then nothing in the page changes;
- otherwise the count returned is exactly what the buffer and the queue allow; one index
  moves, by that count, modulo 2^32; no other byte of the page changes (a read changes no
  queue byte; a write changes only the bytes it reports, in its own queue);
- the bytes moved are the right ones, in order; bytes written then read come back in order,
  in both directions;
- each index is read once per operation, so a guest that changes it meanwhile cannot make
  the daemon use two different values;
- the layout behind the `unsafe` blocks: every word is inside the page, aligned, after both
  queues, and overlaps nothing.

The bounds, which are the limits of the result:

- **At the real queue size (1,024 bytes)**, the code the daemon runs: buffers of up to 32
  bytes for a read, up to 8 for the bytes moved, for a write and for a write followed by a
  read. Longer buffers do not fit in the memory of the machine used (7 GB).
- **At queue sizes of 4, 8, 16 and 32 bytes**: buffers from empty to longer than two queues,
  so longer than the free space, than what is queued and than the queue itself; the
  reconnection (both queues filled, the four indices 0, nothing else changed); at 4 bytes,
  two sequences of four operations compared with a model of the queue. Not every check fits
  at every size: the header of `scripts/kani.sh` says which run. The queue size is a
  constant of the same source code, so this is a strong argument that the result holds at
  1,024, not a proof of it.
- **Sequential only.** Kani runs one thread and treats an atomic access as a plain one: this
  proves the algorithm against any state a guest can leave between two operations, not
  against a guest writing during one. That is what the Miri runs below exercise, for the
  schedules they run.
- **Not covered**: the real mapping of a guest's page (the proofs use a heap page), the
  daemon's use of the ring, and everything outside `ring.rs`. The results rest on Kani, on
  CBMC and its SAT solver, and on Kani's model of the standard library.

A proof that cannot fail proves nothing: 28 faults were planted in `ring.rs` one at a time (a
check removed or off by one, a missing mask, a wrong offset, an index advanced wrongly, a
second read of an index, a queue left unfilled by the reconnection…). 27 make a harness
fail. The one that does not removes a memory fence, which a sequential proof cannot see.
Three of the faults cannot be seen at 1,024 bytes (two need buffers longer than those proved
there, one has no effect at that size); the harnesses at small sizes catch them. Writing the proofs found no defect in the ring.

## Not tested here

**Fuzzing** (libFuzzer, coverage-guided; `fuzz/`, run with `scripts/fuzz.sh`). Ten
targets: the core fed raw requests from several guests and domain 0 with invariants checked
after each (quotas, what each connection has queued, who may see which watch event), once per
mode; the core against the model, in both modes; the ring; the wire decoder; the
configuration file and the command line of each mode; the log formatter. Before the first
campaign, 12 bugs were planted one at a time (quota off by one, a skipped permission check, a
ring index wrap, an unescaped log byte…): each was found by a target that could see it, the
slowest in 240 s. Three campaigns of one night each, on 4-core VMs. The first
(2026-11-17): about 14 process-hours and 131 million executions; it found one bug in the
daemon, in the accounting of queued watch events, now fixed with a regression test, and one
error in the model. The second (2026-11-19): 48 process-hours and 739 million executions; no
bug in the daemon, one error in the model and one case the invariants did not allow for. The
third (2026-11-20), on the code with both modes: 48 process-hours and 808 million executions
(the core with invariants 15.6 h in compatibility mode and 6.0 h in native mode, the core
against the model 14.4 h, the ring under AddressSanitizer 6.0 h, the six others 6.0 h); no
bug in the daemon, one more case the invariants did not allow for. After that change to the
invariants, four permission checks were removed from the core one at a time: each was found
by at least one of the two core targets within 80 s (one of them only when started from the
night's corpus), and neither target found all four in 5 minutes. No
crash, hang or memory error in any night. At the end of the third, the core targets were
still reaching new code slowly; the model and ring targets had stopped. That is hours, not the weeks a fuzzing campaign should run.

**Miri** (`scripts/miri.sh`), which detects undefined behaviour in the code it runs, runs the
unit tests of `xs-wire`, the model test of `xs-core` with 2 seeds of 150 steps, 26 of the 31
unit tests of `xs-daemon` and 37 of the 73 of `xs-sys`, among them every ring test, the three
that run two threads on one page each under 8 schedules. It cannot run the others, marked in
the source with the reason (memfd, file mappings, Unix sockets, signals, process creation, the
Xen device files), nor any integration test, and has not finished `xs-core`'s own unit tests
(`xs-core` has no `unsafe`). Miri found that the ring read and wrote the page it shares with
the guest with volatile accesses, which Rust counts as non-atomic: a data race, so undefined
behaviour by the language's rules whenever the guest wrote what the daemon was reading;
harmless as compiled today. Every access to the page is now atomic.

**Sanitizers** (`scripts/sanitize.sh`): AddressSanitizer with leak detection, ThreadSanitizer
and MemorySanitizer run every test of the five crates, with the standard library and the
daemon that the integration tests start instrumented too: no report. Like the tests, they do
not reach the real Xen devices.

**Differential test** (`crates/xs-diff`, and `crates/xs-daemon/tests/differential.rs`, run
when `RXS_OXENSTORED` names an oxenstored that can start without Xen). rxenstored was run side
by side with oxenstored 4.17.6 as XCP-ng 8.3 ships it (the unmodified package binary, on a
machine without Xen, through its Unix socket): about 8,400 seeded random sequences of 150
requests each, on three connections, covering every request type a socket can send, malformed
and over-long ones included; each reply, each connection's watch events and the final store
were compared. Every difference was triaged: 3 are documented differences
([`DESIGN.md`](DESIGN.md)), 2 were bugs of rxenstored in debug and display output (fixed), 2
were behaviours of oxenstored that rxenstored then adopted (the order of the watch events one
change sends to a connection, and the events of a commit whose requests had to be run again),
9 are behaviours of oxenstored that rxenstored does not copy (reply text, transaction
numbering, malformed input, requests only dom0 may send), and 5 were artefacts of the test.
After the change, 1,200 more sequences showed no difference in watch events, their order
included. Guests were not simulated: what depends on the caller being a guest (its quotas,
permissions, watch filtering, conflict credit) was not compared side by side. Nothing was
compared with C xenstored.
Real Xen is exercised only by hand: `crates/xs-sys/examples/xen_probe.rs` checks the Xen
devices of a live dom0 without disturbing its xenstored (built with `--features gnttab`; its
header lists the commands).

`xs-bench` replays the recorded xenstore traffic of one HVM guest's start on an XCP-ng 8.3
host (names, addresses and UUIDs replaced by documentation values), once per simulated VM,
over a daemon's socket (run it without arguments for its usage). It is a model, not a host:
no real domains, the guest's requests come with dom0's rights, reads are not in the recording. Do not run it
against the daemon of a host whose guests matter.
