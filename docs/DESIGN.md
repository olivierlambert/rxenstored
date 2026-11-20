# Design

rxenstored has two modes. By default it is a xenstored of its own: its command line, its
configuration file and the native behaviour below. With `--compat=oxenstored` it replaces
oxenstored 4.17 as XCP-ng 8.3 runs it. The compatibility contract comes first, then the
native mode, then how the daemon is built.

## The compatibility contract (`--compat=oxenstored`)

**Kept as oxenstored 4.17 has it.**

- Start-up: the stock `launch-xenstore` runs it with oxenstored's arguments after
  `--compat=oxenstored`; it reads
  `/etc/xen/oxenstored.conf` with oxenstored 4.17's grammar (every key checked, warnings as
  oxenstored gives them, errors under `--config-test`; four keys are not honoured, below),
  writes the pid file, daemonises and sends `READY=1` to systemd. SIGTERM and SIGINT stop it,
  SIGHUP reopens the logs.
- Transports: the same unix socket, dom0's ring from `/dev/xen/xenbus_backend`
  (falling back to `/proc/xen/xsd_kva` and `/proc/xen/xsd_port`, which are used as configured
  when `xenstored-kva` or `xenstored-port` name other paths; the device path has run on a
  test host, the fallback only in tests), guest rings by foreign mapping of the gfn that INTRODUCE gives, the
  RECONNECTION ring feature advertised, domain state through Xen 4.17's domctl (interface
  version 0x15).
- Semantics of every request it serves: permissions, the XSA-115 check of watch events,
  the watch events each connection gets and their order (a change fires the watches on its
  path from the root down, each path's newest watch first, and for a removal those below it
  in name order; a commit fires one change per request its transaction recorded, in order),
  `EQUOTA`, oxenstored 4.17's quotas and conflict credit, transactions re-executed at commit
  when the store changed (a different reply is `EAGAIN`), a level-triggered
  `@releaseDomain`.
- The access log: oxenstored's line formats, rotation by line count, `syslog:<facility>`.

Checked by a model test (`crates/xs-core/tests/model.rs`: replies, events and the store
compared at every step with a hand-written model of oxenstored's behaviour, on 450 seeded
random sequences) and on one host, as the README says (toolstack logs, access-log counts);
and by a differential test against the oxenstored binary over its socket
([`TESTING.md`](TESTING.md)), which does not cover what depends on the caller being a guest.

**Different on purpose**, each commented in the code:

| rxenstored | oxenstored 4.17 |
|---|---|
| A ring reconnection drops the guest's watches | keeps them in its watch index (XSA-512, fixed upstream) |
| `DIRECTORY_PART` is implemented | `ENOSYS` |
| A commit after other changes is always re-executed | merged when the paths it read and wrote did not change, re-executed otherwise |
| The periodic ring scan examines 32 rings per tick | all rings at once every 20 s |
| Logging goes through a bounded queue (65,536 lines, 8 MiB) to a log thread; when full, lines are dropped and counted | writes synchronously |
| A commit that had to be re-executed logs `commit` | logs `coalesce` or `conflict` and the replayed requests |
| The syslog program name is the binary's name | `oxenstored` |
| A log that cannot be opened does not stop the daemon | stops |
| `merge-activate`, `gc-max-overhead`, `test-eagain` and `allow-debug` are read but not honoured (no guest may use `CONTROL`); a value other than the default gets a warning at start and under `--config-test` | honoured |
| `quota-transaction-bytes` (default 3 MiB, absent from `oxenstored.conf`): beyond it, a guest's request in a transaction gets `EQUOTA`; domain 0 is exempt | no such quota |
| `--help` after `--live` or `--restart` exits non-zero, so oxenstored's live-update check refuses to hand over | n/a |

**Rules of its own**, each commented in the code, which a client written against oxenstored
4.17 could notice: `RELEASE` of domain 0 or of a reserved domid is `EINVAL`, and nothing is
touched; a `SET_TARGET` relation ends when its target dies or is released; the conflict
history records the change each commit made, so a transaction that fails is blamed on the
commits whose own change made it fail; a guest's watch path is limited to `quota-path-max`,
its ACL to 256 entries; the root node is never counted in quotas; when the event-channel
device reports lost notifications, every ring is examined.

**Kept although debatable** (compatibility mode; native differs, below), each pinned by a test:

| Behaviour | Why it is debatable | Test |
|---|---|---|
| Nodes a guest creates below a dom0-owned node it may write belong to dom0, which has no quota | a quota bypass of the XSA-419 class | `xsa_419_who_owns_and_pays_for_a_node_a_guest_creates` |
| `quota-maxwatch` and `quota-transaction` allow one more than their value | off by one, but guests and tools may count on it | `xsa_326d_…`, `xsa_326e_…` |
| A failing WRITE keeps the parents it created | leaves nodes behind | `xsa_414_what_a_failed_creation_leaves_and_counts` |
| `@releaseDomain` fires at every `VIRQ_DOM_EXC` while any domain is shut down | event storms | `a_dead_domain_loses_its_connection_nodes_and_acl_entries_and_release_domain_fires_once` |

**Not supported**: live update in either direction (`--live` and `--restart` are refused,
`CONTROL live-update` and `CONTROL xenbus` answer `ENOSYS`); the `audit` log mode; `CONTROL
stats` and `trace`. oxenstored's `-T` (trace file) is accepted and ignored, with a warning.Grant mapping of guest rings exists in `xs-sys`, behind its `gnttab` feature (off by
default); it cannot be selected from the configuration and has not run on a host.

## Native mode

Without `--compat=oxenstored`. It has run on one host, for one 40-guest benchmark (below).

- Command line (`rxenstored --help`): `-N/--no-fork`, `-F/--pid-file`, `-D/--no-domain-init`
  and `-T/--trace-file` (accepted, ignored) as both C xenstored and oxenstored have them;
  `-Q/--quota NAME=VALUE` as C xenstored; `-c/--config-file`, `--config-test`,
  `--disable-socket`, `--no-access-log`, `--socket`, `--version`. C xenstored's other flags
  are not accepted. An unknown option stops the start.
- Configuration: `/etc/xen/rxenstored.conf`, one `KEY = VALUE` per line. An unknown key, a
  key set twice or a bad value stops the start, with its line number. Quotas are
  `quota-NAME`, with C xenstored's names where the limit means the same (`nodes`, `watches`,
  `transactions`, `outstanding`, `path-max`, `node-permissions`); 0 means no limit. The
  command line wins over the file. There is no switch to turn permission or quota checks
  off.
- Default quotas, C xenstored's: 1,000 nodes, 128 watches, 10 transactions, 20 outstanding
  replies, 5 permission entries per node (its owner's included), 2,048-byte values and
  relative paths, 1,024 requests per transaction.
- The daemon log goes to `syslog:daemon`; there is no access log unless configured. The
  unix socket is created with mode 0600.

Where its behaviour differs from the compatibility mode:

- A quota refuses with `ENOSPC`.
- A quota of N allows N watches and N open transactions per connection.
- `CONTROL` from a guest is answered `EACCES`; domain 0's commands are unchanged.
- A node a guest creates is owned by that guest (the rest of its permissions are its
  parent's), counts in the guest's node quota, and is removed when the guest goes.
- A `WRITE` or `MKDIR` that fails creates nothing.
- `RM` of the root is refused with `EINVAL`.
- A request on a node that does not exist is answered `EACCES` rather than `ENOENT` when
  the caller may not access the nearest existing node above it (read access for `READ`,
  `DIRECTORY`, `DIRECTORY_PART`, `GET_PERMS`; write access for `RM`, `SET_PERMS`).

Checked by the same model test with the model switched to these rules, on the same number
of sequences, and by the XSA regression tests run in both modes.

On one XCP-ng 8.3 host (4 cores), booted with the default quotas above and the access log
switched on for comparison: the host's own guests came back with their devices, the same
40-guest benchmark as the compatibility mode ran with no failed operation and 5.06 s of
daemon CPU for the 40 starts (5.08 s in compatibility mode), and two Windows Server 2022
guests connected their PV drivers. No quota refused anything: guests held at most 185 nodes
and 14 watches, and domain 0 is not held to the quotas. The one visible difference was 20
`EACCES` replies where the compatibility mode answers `ENOENT`, to guest frontends reading
a backend node just removed during unplugs; every unplug and plug succeeded. One run; not
run with the default of no access log, nor with other toolstacks.

## How it is built

**Two threads.** One owns all xenstore state and runs the event loop; the other writes the
logs. Writes, commits and the events they cause need one global order, and per-request work
is small once it no longer depends on the number of domains, so the state is not sharded.

**Crates.** `xs-wire` (wire format) ← `xs-core` (all protocol decisions, sans-IO) ←
`xs-daemon` (event loop, configuration, logs) → `xs-sys` (system calls, all `unsafe`).
`xs-core` does no system call and reads no clock (the daemon passes it the time), so every
protocol, permission, quota and conflict decision can be tested from bytes. `xs-sim`
implements the same `XenBackend` trait as the real Xen devices, so the daemon's ring and
domain handling run end to end in `cargo test`. The only runtime dependency is `libc`.

**Event loop.** Edge-triggered epoll. The event-channel device says which ports fired, and
only those rings are read. A socket gets up to 64 requests and 64 KiB per turn, a ring 16
requests; after a ring turn its indices are read again before sleeping. A safety scan
examines 32 rings per tick, so that every ring is looked at once per `ring-scan-interval`
without a burst. The next deadline (scan tick, conflict credit, retry of a failing device)
becomes the epoll timeout.

**Store.** A persistent tree. A node is 56 bytes and lives in its parent's map; values and
names up to 22 bytes are stored inline. Children are kept in an in-tree copy-on-write B+ tree
of fan-out 16, so a write copies the few pages on its path that another version shares. Each
node has a value generation and a children generation (the latter is `DIRECTORY_PART`'s
`gencnt`).

**Transactions.** Starting one is a snapshot: the root pointer. At commit, if the store has
not changed, the transaction's root becomes the store's; otherwise every request is
re-executed on the current store and any different reply makes the commit `EAGAIN`.
oxenstored does the same when it cannot merge the transaction; where it merges (it tries to
first, `merge-activate`), rxenstored re-executes, so a few commits end differently: in the
differential test, about 1 sequence in 100. Conflict credit is oxenstored 4.17's: a guest that keeps making others' commits
fail is paused; dom0 never is.

**Watches.** A path trie, with the watches and trie nodes in two arrays and two hash tables of
indices: (parent, name) to find a child, (connection, node, token) to find a watch. They
hash with SipHash-1-3 under a key drawn at start, since clients choose the names. A change
fires the watches along its path and, for a removal, below it: cost in the path's depth and
the watches that match. A guest is held once `quota-maxwatchevents` events of its
own wait for a watcher, until the watcher reads; one guest never holds another, and domain
0's connections are never given up on for unread output. Domain 0 and sockets are never held for a guest: the
events they cause for a watcher that already has twice `quota-maxwatchevents` unsent are
dropped, and the daemon log says when such a streak of drops starts and, with its count,
when it ends.

**Quotas.** Each version of the store carries its node count per owner; a transaction
carries its changes to them; every operation updates one count per node created, removed or
given away. `Core::audit` recounts everything from the tree, and the model test calls it
after every step.

**Logs.** The core hands records to a bounded queue; the log thread formats and writes them,
waiting 2 ms after each batch so that a busy daemon wakes it a few hundred times a second.
Lines dropped because the queue was full, or lost because a destination failed, are counted
and reported in both logs.

**`unsafe`.** All of it outside the tests is in `xs-sys`, each block with a `SAFETY`
comment; the other crates of the daemon have `#![forbid(unsafe_code)]`. The ring code reads
each index once, refuses indices that claim more than the ring holds (the ring is then marked
bad and ignored until its domain dies), copies data at masked offsets and makes no Rust
reference to the shared page: its words are read and written by volatile accesses, ordered
by fences.

**No panics.** Clippy's `unwrap_used`, `expect_used`, `indexing_slicing`, `string_slice`,
`panic`, `unreachable`, `print_stdout`, `print_stderr` and the others listed in `Cargo.toml`
are denied in all code that is not a test, except in `xs-bench`, the load generator. What
lints cannot see: allocation failure and stack overflow abort the process (recursion is
bounded by the path length, with the deepest path tested on a 4 MiB stack); integer overflow
wraps in release builds, so the sites that take values from guests or the configuration were
reviewed by hand; preconditions inside the standard library were checked at each use. A panic
that happens anyway writes one line to stderr and aborts (`crates/xs-daemon/src/fatal.rs`).

**`no_std` core.** `xs-wire` and `xs-core` use `core` and `alloc` only (`scripts/nostd.sh`),
so that the core could later run in a stub domain. Nothing runs there today.

## Reading the code: upstream citations

Comments cite the Xen sources so that a behaviour can be checked against the daemon it
copies. Prefixes, all in the [Xen repository](https://xenbits.xen.org/gitweb/?p=xen.git):

| Prefix | Path |
|---|---|
| `ox/` | `tools/ocaml/xenstored/` (oxenstored) |
| `cx/` | `tools/xenstored/` (C xenstored) |
| `xb/` | `tools/ocaml/libs/xb/` (oxenstored's ring and wire library) |
| `xs_wire.h` | `xen/include/public/io/xs_wire.h` |
| `docs/misc/…` | Xen's protocol documents, `xenstore.txt` and `xenstore-ring.txt` |

Line numbers are those of Xen's master branch at commit `7e020a4dd6` (October 2026), unless
the citation names a release, such as `RELEASE-4.17.0` or "4.17", for code that differs in
the version XCP-ng 8.3 ships. Hashes next to an XSA are upstream Xen commits.
