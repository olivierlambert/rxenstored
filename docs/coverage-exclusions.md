# Coverage exclusions

Code that the coverage gate (`scripts/coverage.sh`) does not measure. Every entry is reviewed like
code: adding, changing or removing one is part of the change that needs it, and the reviewer
checks the reason. `scripts/covgate.py markers` (run by `scripts/coverage.sh`) fails if a
marker in `crates/*/src` has no entry here, if an entry has no marker, or if the file does not
match.

Markers, in a line comment:

- `// cov:excl-line ID`: the line the comment ends;
- `// cov:excl-start ID` ... `// cov:excl-stop ID`: both marker lines and every line between.

A region is excluded only if every line it spans is excluded. An exclusion is for code that
cannot run in `cargo test` (no Xen, no root), never for code that is merely untested: a reachable path gets a
test, an unreachable one is removed if the type system allows it, and only otherwise excluded
here, with the invariant that rules it out (backed by a `debug_assert!` where one fits).

## Rules

| Id | Scope | Reason |
|---|---|---|
| `test-code` | `#[cfg(test)]` items and `#[cfg(test)] mod x;` files | The tests themselves: a panic arm of a test helper is not product code |

## Markers

| Id | File | Reason |
|---|---|---|
| `xen-domctl-reply` | `crates/xs-sys/src/xen/mod.rs` | Runs only when `IOCTL_PRIVCMD_HYPERCALL` succeeds, which needs privcmd on a Xen dom0; it copies the reply out of the hypercall page, and the decoding it hands over to (`abi::getdomaininfo_reply`) is tested against the 4.17 layout |
| `xen-backend-port` | `crates/xs-sys/src/xen/mod.rs` | Runs only when `IOCTL_XENBUS_BACKEND_EVTCHN` succeeds, which needs `/dev/xen/xenbus_backend` on a Xen dom0: the mmap of dom0's store page and the hand-over. The failures before it run on `/dev/zero`, a regular file, a directory and a missing path; the choice between the device and the files is tested with a stand-in device (`dom0_ring_from`) |
| `xen-foreign-mapped` | `crates/xs-sys/src/xen/mod.rs` | Runs only when `IOCTL_PRIVCMD_MMAPBATCH_V2` maps a guest frame, which needs privcmd on a Xen dom0; the failure paths before it run on `/dev/zero` |
| `xen-grant-mapped` | `crates/xs-sys/src/xen/mod.rs` | Built only with the `gnttab` feature, off by default, so not in the measured build; with it, runs only when `IOCTL_GNTDEV_MAP_GRANT_REF` succeeds, which needs gntdev on Xen: the mmap of the grant, its release if that fails, and the hand-over to a `Mapping` whose release hook (`grant_release`) is tested on its own |
| `xen-opened` | `crates/xs-daemon/src/main.rs` | Runs only when `RealXen::open` succeeds, which needs the Xen devices of a dom0: the log of what was opened and the hand-over to the event loop. The failure before it runs in `tests/startup.rs` (`a_start_without_xen_devices_fails_clearly`); the event loop over a backend is tested with the simulated one (`tests/rings`) |
| `daemonize` | `crates/xs-sys/src/process.rs` | `fork_twice`, the forks of `daemonize`: forking is only sound in a process with a single thread, which a test harness is not (`daemonize` refuses it, tested here with the check that refuses it, `one_thread_in`); the daemon's start runs it in the tests of xs-daemon (`tests/startup.rs`), whose coverage is not credited to xs-sys. What it is made of is tested here: the readiness report (`read_report`, `Readiness`), `null_onto`, `reap` |
