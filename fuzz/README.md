# Fuzzing

Coverage-guided fuzz targets for rxenstored (libFuzzer, through cargo-fuzz). This directory
is a crate of its own, outside the main workspace, with its own `Cargo.lock`: `cargo test
--workspace` and the gates do not build it. It is built with debug assertions and overflow
checks on, so the `debug_assert!`s of the code and xs-core's `impossible()` stop a run, as
any panic does. `ring` is built with AddressSanitizer.

## The targets

| Target | What it drives | What it checks |
|---|---|---|
| `core_requests` | `xs_core::Core` as a toolstack and guests that do not follow the protocol would drive it: two sockets, domain 0's ring, three guests with small quotas (domain 3 the stub domain of domain 2); requests of every type, well formed or built from arbitrary fields and bytes; INTRODUCE, RELEASE, SET_TARGET; domains dying; ring reconnection; output read or left unread; time | after every step: `Core::audit` (every fourth step and at the end); every message well formed; one reply per request; what each guest holds within its quotas (watches, transactions, the bytes its transactions keep, queued replies, events and bytes, nodes per owner, value sizes); every change, read and watch event of a guest allowed by the permission rules of the model of `crates/xs-core/tests/oracle/`; every event for a watch its connection has; the domains the core and the machine know; access-log lines |
| `core_requests_native` | as `core_requests` (the same body, `core_requests_body.rs`, inputs and seeds), with the core in the native profile | as `core_requests`, by the native profile's rules where they differ (`xs_core::Rules`: a quota of N allows N watches and transactions, quota errors are ENOSPC, a guest owns the nodes it creates) |
| `core_vs_model` | the request generator of the model test (`crates/xs-core/tests/model.rs`), each choice a byte of the input; bit 3 of the first byte runs both in the native profile | every reply and watch event, and the store, against the model of oxenstored's behaviour in `crates/xs-core/tests/oracle/`, which follows the native profile's rules in a native run |
| `ring` | `xs_sys::ring` on a page between two inaccessible pages, with a peer that writes any index and any byte between the server's calls | results and the page against what the indices say; corrupt indices refused; never more than `RING_SIZE` bytes per call |
| `wire_decode` | `xs_wire::Decoder` fed a stream cut at arbitrary points | agreement with a reference parser; re-encoding; a bounded buffer |
| `config` | `oxenstored.conf` parsing (`crates/xs-daemon/src/compat/config.rs`, `--compat=oxenstored`), then a core built with the result | no panic; same result twice; the core runs |
| `options` | oxenstored's command line (`crates/xs-daemon/src/compat/options.rs`) | no panic; same result twice |
| `native_config` | `rxenstored.conf` parsing (`crates/xs-daemon/src/native/config.rs`), then the core, conflict and log settings built from the result and a core run with them; each line also as a `-Q NAME=VALUE` argument | no panic; same result twice; errors one per refused line, in order, on exactly the lines that are refused alone or set a key again; every setting what its line says (the harness's own reading of the documented values) or the default; values within the documented bounds; the settings written back read the same; quotas reach the core as documented (0: no limit) |
| `native_options` | rxenstored's own command line (`crates/xs-daemon/src/native/options.rs`), then its `-Q` values | no panic; same result twice; the same result and the same kind of error as an independent reading of the documented getopt_long grammar |
| `log_format` | the access-log formatter (`xs_daemon::log::format`) | escaping (printable output that unescapes to the input), `truncate`, dates |

## Prerequisites

- A Rust nightly toolchain (cargo-fuzz needs `-Z` flags). Last used: rustc 1.102.0-nightly
  (65ce8611f 2026-11-18), and before it (5f4effd57 2026-11-13); other recent nightlies should
  do. The main workspace builds with stable 1.96.1.
- cargo-fuzz 0.13.2 (`cargo install --locked cargo-fuzz`).
- A C/C++ toolchain for libFuzzer (built by the `libfuzzer-sys` crate): `build-essential`.
- For the scripts: bash, coreutils (`timeout`), util-linux (`flock`), awk, sed, find;
  python3 for `fuzz/gen_seeds.py`.
- Linux x86-64 (the `ring` target maps memfd pages).

### A fresh Debian 12 or 13 machine

As a user with sudo, 4 vCPUs and 8 GB of memory being plenty (run as they are on the
Debian 13 generic cloud image, 2026-11-19: under a minute to cargo-fuzz installed, under a
minute to build every target on 4 vCPUs):

    sudo apt-get update
    sudo apt-get install -y build-essential curl git python3 pkg-config
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
    . "$HOME/.cargo/env"
    rustup toolchain install nightly --profile minimal
    cargo +nightly install --locked cargo-fuzz@0.13.2
    git clone <this repository> rxenstored && cd rxenstored
    scripts/fuzz.sh --list
    for t in $(scripts/fuzz.sh --list); do scripts/fuzz.sh "$t" 0; done     # build all
    scripts/fuzz.sh log_format 60                                          # a first short run

With `--default-toolchain none`, the nightly installed becomes rustup's default; the scripts
name it anyway (`FUZZ_TOOLCHAIN`). For a machine that cannot reach the repository, make a
bundle where it can (`git bundle create rxenstored.bundle HEAD`), copy it over, and
`git clone rxenstored.bundle rxenstored` (a detached HEAD at the commit bundled). A dated
nightly reproduces the toolchain above exactly: `rustup toolchain install nightly-2026-11-19`,
then `FUZZ_TOOLCHAIN=nightly-2026-11-19` (the channel of a date holds the compiler of the day
before: `nightly-2026-11-14` for 5f4effd57 2026-11-13).

## Running

One target for a number of seconds:

    scripts/fuzz.sh core_requests 600
    scripts/fuzz.sh core_requests 600 65536     # inputs up to 64 KiB (corpus of its own)

The script builds the target if needed, runs one libFuzzer process (niced, 1 GiB memory limit,
10 s per input), saves any input that fails and starts again until the time is up, and adds
the run to `STATUS.txt`. Everything goes under `FUZZ_DIR` (default `target/fuzz` in the
checkout): `corpus/TARGET` grows (`fuzz/seeds/TARGET` is read too, never written),
`artifacts/TARGET` holds the inputs that failed (`crash-*`, `timeout-*`, `oom-*`), `logs/`,
`totals/` and `STATUS.txt`, the sum of every run. Other settings: `FUZZ_TOOLCHAIN`
(default `nightly`), `RSS_MB` (1024), `NICE` (10).

A session of several hours, two or four processes at a time (one per CPU), rotating through
the targets by priority (core_requests 45 % of the time, about half of it core_requests_native,
core_vs_model 30 %, ring 12.5 %, the six parsers 12.5 %):

    setsid nohup scripts/fuzz-night.sh 7 >/dev/null 2>&1 &       # 7 hours, 2 processes
    setsid nohup scripts/fuzz-night.sh 12 4 >/dev/null 2>&1 &    # 12 hours, 4 processes
    cat target/fuzz/STATUS.txt

Without the scripts: `cd fuzz && cargo +nightly fuzz run core_requests` (add `-s address` for
`ring`).

## A failing input

    target/fuzz/target-none/x86_64-unknown-linux-gnu/release/core_requests FILE
    FUZZ_TRACE=1 target/fuzz/target-none/x86_64-unknown-linux-gnu/release/core_requests FILE
    cd fuzz && cargo +nightly fuzz tmin core_requests FILE     # minimise

(`ring` is in `target-address`.) `FUZZ_TRACE=1` makes `core_requests` print each action, each
request handled and each message queued; `ORACLE_TRACE=1` makes `core_vs_model` print each step
and what the model expects. `FUZZ_PROFILE=1` makes `core_requests` print, per input, the time
spent in each of its parts. Once understood, a failing input becomes a regression test in the
normal test suite, and the input a seed.

## Seeds and dictionaries

`fuzz/seeds/TARGET` is a small curated set, read at the start of every run:

- `core_requests`: inputs that start with `RXS1` replay records (connection, request type,
  transaction, payload) before the input's own actions, cheaply (the checks run from the end of
  the replay). `python3 fuzz/gen_seeds.py fuzz/seeds/core_requests` writes them: the recorded
  start and stop of an HVM guest on XCP-ng 8.3 (`crates/xs-bench/scenarios/`, where names,
  addresses and UUIDs are documentation values) mapped onto the target's connections, and
  sequences shaped like the XSA regression tests of `crates/xs-core/src/tests.rs` (named
  `xsa-NNN-…`), the transaction byte quota, CONTROL `quota` in a transaction, the events of a
  commit. The others are inputs kept as regression inputs: a node named `@/` under the root,
  the root's owner gone after a RELEASE, and commits after SET_TARGET or the RELEASE of the
  target changed the connection's rights during its transaction.
- `core_vs_model`: the first steps of the model test's seeded sequences, as choice bytes
  (`XS_FUZZ_SEEDS=DIR cargo test -p xs-core --test model -- --ignored` writes them), in each
  profile (`model-seed-*`, `model-native-seed-*`), a commit after SET_TARGET changed the
  connection's rights during its transaction, and nodes created in a transaction after the
  nodes it removed were removed outside it too (node counts held at zero), in each profile.
- `core_requests_native` reads `fuzz/seeds/core_requests`.
- The others: small sets from short runs, `oxenstored.conf` and `rxenstored.conf` files,
  command lines.

Dictionaries are in `fuzz/dict/` (paths, special watches, permissions, CONTROL commands,
limits; configuration keys of either file and options of either command line; wire header
words).

## Checking a target before a long run

A target that cannot find a bug it should find is not ready. To check one: copy the tree,
plant one bug in the copy (a quota off by one, a permission check skipped, a ring index not
checked, a byte left unescaped), build the target from the copy with its own `FUZZ_DIR`, run
it for a few minutes from the current corpus, and see that it fails, and how fast. Each target
was checked so against bugs of its kind before its first long run.
