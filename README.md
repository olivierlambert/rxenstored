# rxenstored

A xenstore daemon written in Rust, with its own command line and configuration, and a
compatibility mode in which it replaces oxenstored on XCP-ng 8.3 (Xen 4.17). Every
measurement below is of the compatibility mode; the native mode has not run on a host.

> **Status: experimental, not production-ready.** It was written with AI assistance and has
> not yet been reviewed line by line by a human. It has served guests on two hosts only
> (XCP-ng 8.3, HVM guests). Its longest run is one daemon serving one 4-core host for 7 hours,
> through a 6.5-hour soak of about 3,000 guest lifecycle operations (1,600 domains, Linux and
> Windows) with no failure attributed to it; nothing has run for days. It has been fuzzed for
> hours, not weeks, and there has been no external security review. Do not run it on a host
> whose guests matter.

## Results with 500 guests

A dual-socket AMD EPYC 7443 server with 500 Alpine Linux HVM guests, each daemon in turn as
its xenstored. *Daemon CPU*: user plus system time of the daemon process, all threads.

| Single runs | oxenstored (Xen 4.17) | oxenstored (XAPI) | C xenstored | rxenstored |
|---|---|---|---|---|
| Batch of 25 starts, from 475 to 500 guests: wall time | 124 s | 37.4 s | 73.9 s | 37.7 s |
| Same batch: daemon CPU | 124 s | 26.5 s | 68.6 s | 3.31 s |
| All 500 starts: daemon CPU | 1,076 s | 341 s | 663 s | 58.7 s |
| Reboot 25 guests: wall time, mean of 3 rounds | 177 s | 60.2 s | 106 s | 45.0 s |
| Idle with 500 guests: daemon CPU per minute | 21.1 s | 5.56 s | 5.55 s | 0.72 s |
| Daemon memory (RSS) with 500 guests | 89.2 MB, not started fresh | 87.0 MB | 61.3 MB | 31.1 MB |

oxenstored (XAPI), the newer out-of-tree oxenstored, ran on a second server of the same
model. Newer C xenstored releases were not measured. XCP-ng 8.3 ships both oxenstored and C
xenstored, and uses oxenstored by default.

![Starting 500 guests, 25 at a time](docs/img/epyc-ramp.svg)

Daemon CPU per batch of 25 starts grew by 23.2 s per 100 guests running with oxenstored (Xen
4.17), 4.6 s with oxenstored (XAPI), 12.6 s with C xenstored and 0.15 s with rxenstored (least
squares; rxenstored went from 2.35 s for the first batch to 3.31 s for the last). With
rxenstored a batch still went from 25 s at 25 guests to 38 s at 500; the daemon was on the CPU
for under 9 % of that time. oxenstored (XAPI)'s batches took as long as rxenstored's, within
2.5 s, with its daemon on the CPU for 71 % of the last one.

![With 500 guests running: operations and the daemon at rest](docs/img/epyc-500-up.svg)

With 500 guests running, rxenstored took 1.3× to 3.9× less wall time than the other three to
reboot and 1.5× to 7.1× less to replug network interfaces; to suspend and resume, 1.5× and
2.0× less than C xenstored and oxenstored (Xen 4.17), and 2.6 % more than oxenstored (XAPI).
It took 8.7× to 36× less time per node to list the store and used 7.7× to 29× less CPU at
rest.

![40 guests: four xenstore daemons](docs/img/intel-40-guests.svg)

With 40 guests, wall times were close whichever the daemon (331 to 337 s for the 40 starts,
111 to 114 s for the 12 reboots); daemon CPU was not, and oxenstored (XAPI) was close to C
xenstored. With 500 guests, oxenstored (XAPI) used about half of C xenstored's daemon CPU
(0.44× to 0.53× per phase) and the same at rest.

## How it was measured

- **Hosts**, XCP-ng 8.3, unmodified toolstack. EPYC (dom0: 16 vCPUs, 16 GiB): guests of 1
  vCPU, 256 MiB and one NIC, started 25 at a time, then 3 rounds of reboot, suspend/resume
  and NIC replug on 25. Intel, 4 cores (dom0: 4 vCPUs): 40 Debian HVM guests started 4 at a
  time, then 3 rounds of the same and of disk replug on 4.
- **Daemons**, each the host's xenstored from boot, with the host's `oxenstored.conf`:
  oxenstored (Xen 4.17) as XCP-ng 8.3 ships it (4.17.6); oxenstored (XAPI) is
  [xapi-project/oxenstored](https://github.com/xapi-project/oxenstored) `c7b810d`, built for
  Xen 4.17 with a two-line build patch; C xenstored is XCP-ng's 4.17.6, given the host's
  oxenstored quotas mapped to its options and run without its trace log (`-T`), which favours
  it; the others wrote the host's access log.
- **rxenstored** was an earlier build, before the no-panic lints, the `no_std` core (a
  synthetic before-and-after run showed no CPU difference), two fixes (access-log loss
  accounting, back-off on failed accepts) and the changes since. Of the benchmarks, only the
  40-guest one was run again on the 4-core Intel host, once on each later build: 5.15 s of
  daemon CPU for the 40 starts on the code first published, then 5.09 s, 5.02 s and 5.08 s on
  later code (the last started with `--compat=oxenstored`), against the measured build's
  5.25 s; every other phase within or just under the
  spread of the earlier runs, memory equal or lower, and no operation failed.
- **oxenstored (Xen 4.17) was not fresh**: 8.2 MB resident before the EPYC ramp after two
  trial runs (the others: 0.9 to 2.1 MB); on the Intel host, 130.7 MB and 478 more nodes
  left by earlier runs.
- **Single runs**, hours to a day apart; C xenstored on a fresh install of the same server
  model, oxenstored (XAPI) on a second server of the same model. No run shown here had a failed operation.

## How it works

Work in proportion to what is ready: epoll for the sockets and, of the guest rings, only
those whose event channel fired, each drained in batches. Watches live in a path trie: a
change costs its path's depth plus the watches that match. The store is a persistent tree: a
transaction starts with an O(1) snapshot. Quota counts are kept per owner: a check is a
lookup. A second thread writes the access log. What is still not constant is under
Limitations below; the details are in [`docs/DESIGN.md`](docs/DESIGN.md).

## What "drop-in" covers

Started with `--compat=oxenstored`, it keeps oxenstored 4.17's socket, dom0 ring and guest
ring mapping, command line, `oxenstored.conf` grammar, quotas, conflict credit, access-log
format, and its replies to every request rxenstored serves. Without that option it reads its
own command line and `/etc/xen/rxenstored.conf` (`rxenstored --help`), with C xenstored's
quota names and default quotas, and behaves as [`docs/DESIGN.md`](docs/DESIGN.md) lists
under "Native mode". For the compatibility mode, the deliberate differences, and the debatable behaviours
kept, are listed in [`docs/DESIGN.md`](docs/DESIGN.md). How it was checked: a model test
compares replies, events and the store with a hand-written model of oxenstored's behaviour on
450 seeded random sequences; on one host, over the same 40-guest run, the toolstack's logs
showed no message class that oxenstored's runs did not, and the two daemons' access logs had
the same counts by connection kind and operation within 1 % (the guests' own timed writes
differed by 3 %), apart from oxenstored's lines for replayed transactions. A differential test then ran it
side by side with the oxenstored 4.17.6 binary over its socket, about 8,400 random sequences
([`docs/TESTING.md`](docs/TESTING.md)); it does not cover what depends on the caller being a
guest.

## Trying it on a test host, and going back

    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl -p xs-daemon

Copy `target/x86_64-unknown-linux-musl/release/rxenstored` to `/usr/sbin/rxenstored` in dom0,
add these two lines to `/etc/sysconfig/xencommons` and reboot:

    XENSTORED=/usr/sbin/rxenstored
    XENSTORED_ARGS=--compat=oxenstored

The stock `launch-xenstore` starts what the first line names, with
`--pid-file /var/run/xen/xenstored.pid` and `XENSTORED_ARGS`. To go back, remove both lines
and reboot: oxenstored refuses `--compat`, so a second line left behind stops the host's
xenstore from starting. One XCP-ng 8.3 host was booted this way. The daemon and access logs go where `oxenstored.conf` says; start-up messages
go to the service's journal, which on that host ended in `/var/log/daemon.log` under
`launch-xenstore`. To replace a running rxenstored, delete the old file first: it is in use.
xenstored cannot be restarted on a running host, so each switch is a reboot, which stops the
guests, and a daemon that fails to start leaves the host without its toolstack. Have console
access first, and do not do this on a host whose guests matter.

## Build and test

    cargo build --release        # target/release/rxenstored and xs-bench
    cargo test --workspace       # none of the tests needs Xen or root

The gates and what they prove: [`docs/TESTING.md`](docs/TESTING.md). To run the daemon without
Xen, on its own socket (`--help` lists the options):

    mkdir -p /tmp/rxs && printf '%s\n' "log = /tmp/rxs/xenstored.log" "access-log = /tmp/rxs/access.log" >/tmp/rxs/conf
    target/release/rxenstored -N -D -c /tmp/rxs/conf -F /tmp/rxs/pid --socket /tmp/rxs/socket

## Security

xenstored runs in dom0 and serves every guest. Of the 33 Xen security advisories about
xenstore (XSA-38 to XSA-514), 25 have a regression test here, 7 do not apply, and XSA-419 is
handled as oxenstored 4.17 handles it. It has been fuzzed ([`docs/TESTING.md`](docs/TESTING.md)); there has been no external review. The
list, the known limits, and how to report a vulnerability: [`docs/SECURITY.md`](docs/SECURITY.md).

## Limitations

- Linux dom0 only (epoll, Linux's Xen devices); XCP-ng 8.3 and Xen 4.17 only.
- No live update to or from oxenstored (`--live`, `--restart` refused); no stub-domain mode.
- A domain's death walks the whole store; each `VIRQ_DOM_EXC` asks Xen about every domain.
- There is no per-guest memory bound and no transaction age limit: the quotas bound counts,
  not the memory a guest can make dom0 hold in total.
- In compatibility mode, where oxenstored 4.17's behaviour is debatable it is kept: [`docs/DESIGN.md`](docs/DESIGN.md).
- Not there yet: `CONTROL stats` and `trace`, the `audit` log mode, the `-T` trace file.
- Not tested: PV or PVH guests, migration between hosts, more than 500 guests, runs of days,
  Windows guests beyond a few Windows Server 2022 ones.

## Licence

Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>

GPL-2.0-only: see [`LICENSE`](LICENSE).
