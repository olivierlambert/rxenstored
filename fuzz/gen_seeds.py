#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
"""Seed inputs for core_requests (fuzz/fuzz_targets/core_requests.rs,
`replay`): the recorded VM start and stop of xs-bench (sanitised: names,
addresses and UUIDs are documentation values), mapped onto the harness's
connections, and hand-written sequences shaped like the XSA regression
tests of crates/xs-core/src/tests.rs.

    python3 fuzz/gen_seeds.py OUT_DIR

An input is b"RXS1", then records (slot, type, transaction, u16 length,
payload), then 0xff and nothing: the fuzzer appends actions after it.
Slots: 0 the toolstack's socket (xenopsd, A11 in the recording), 1 the
other sockets, 2 domain 0's ring, 3/4/5 the guests of domids 1/2/3.
"""

import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCEN = os.path.join(HERE, "..", "crates", "xs-bench", "scenarios", "xcpng83-hvm-2vbd-1vif")

DIRECTORY, READ, GET_PERMS, WATCH, UNWATCH, T_START, T_END = 1, 2, 3, 4, 5, 6, 7
INTRODUCE, RELEASE, WRITE, MKDIR, RM, SET_PERMS = 8, 9, 11, 12, 13, 14
SET_TARGET, RESET_WATCHES, DIRECTORY_PART, CONTROL = 19, 21, 22, 0
NO_DRAIN = 0x80


def rec(slot, ty, payload, tx=0):
    return struct.pack("<BBBH", slot, ty, tx, len(payload)) + payload


def z(*parts):
    return b"".join(p + b"\0" for p in parts)


def seed(records):
    return b"RXS1" + b"".join(records) + b"\xff"


def scenario(files, guest):
    """The access-log lines of `files`, domain 4 of the recording as `guest`."""
    slot_of_guest = 2 + guest
    recs = []
    open_txns = {}  # slot -> list of the recording's tids, in order of start

    def remap(s):
        return re.sub(
            r"(/local/domain/|/vif/|/vbd/|/vbd3/|/xenops/domain/|/libxl/|/domains/|/tasks/)4\b",
            lambda m: m.group(1) + str(guest),
            s,
        )

    def txsel(slot, tid):
        if tid is None:
            return 0
        lst = open_txns.setdefault(slot, [])
        if tid not in lst:
            lst.append(tid)
            recs.append(rec(slot, T_START, b"\0"))
        return lst.index(tid) + 1

    for f in files:
        for line in open(os.path.join(SCEN, f), encoding="utf-8", errors="replace"):
            m = re.match(r".*oxenstored:\s+(\S+)\s+(\S+)\s+(.*)$", line.rstrip("\n"))
            if not m:
                continue
            conn, op, data = m.groups()
            if op == "w" or conn.startswith("r("):
                continue
            c = re.match(r"([AD])(\d+)(?:\.(\d+))?$", conn)
            if not c:
                continue
            kind, num, tid = c.group(1), int(c.group(2)), c.group(3)
            if kind == "A":
                slot = 0 if num == 11 else 1
            elif num == 0:
                slot = 2
            elif num == 4:
                slot = slot_of_guest
            else:
                continue
            data = remap(data.strip()).encode()
            tx = txsel(slot, tid)
            if op == "write":
                path, _, value = data.partition(b" ")
                recs.append(rec(slot, WRITE, path + b"\0" + value, tx))
            elif op in ("mkdir", "rm"):
                recs.append(rec(slot, MKDIR if op == "mkdir" else RM, z(data), tx))
            elif op == "setperms":
                parts = data.split(b" ")
                recs.append(rec(slot, SET_PERMS, z(*parts), tx))
            elif op in ("watch", "unwatch"):
                path, _, token = data.partition(b" ")
                recs.append(rec(slot, WATCH if op == "watch" else UNWATCH, z(path, token)))
            elif op == "reset":
                recs.append(rec(slot, RESET_WATCHES, b""))
    # Commit what is open, in order.
    for slot, lst in open_txns.items():
        for _ in list(lst):
            recs.append(rec(slot, T_END, b"T\0", 1))
            lst.pop(0)
    return recs


def hand_written():
    out = {}
    g1, g2, g3 = 3, 4, 5
    # A guest fills its node quota, in a transaction and out of it (XSA-272, 421).
    out["xsa-272-421-node-quota-in-and-out-of-a-transaction"] = [rec(g1, MKDIR, z(b"device/n%d" % i)) for i in range(8)] + [
        rec(g1, T_START, b"\0"),
        *[rec(g1, WRITE, b"data/t%d\0x" % i, 1) for i in range(8)],
        rec(g1, T_END, b"T\0", 1),
    ]
    # A watcher that does not read, a long token, writes by another guest
    # it lets write (XSA-326, 324).
    out["xsa-324-326-oversized-events-for-a-watcher-that-does-not-read"] = [
        rec(g1, SET_PERMS, z(b"device", b"n1", b"w2", b"r2")),
        rec(g1, WATCH, z(b"device", b"k" * 4087), 0),
        *[rec(g2 | NO_DRAIN, WRITE, b"/local/domain/1/device/x\0v%d" % i) for i in range(6)],
        *[rec(g3 | NO_DRAIN, WRITE, b"/local/domain/1/device/x\0w%d" % i) for i in range(6)],
    ]
    # A stub domain writes in its target's home (SET_TARGET).
    out["set-target-stub-domain-writes-in-its-target"] = [
        rec(g3, WRITE, b"/local/domain/2/device/vif/0/state\x004"),
        rec(g3, READ, z(b"/local/domain/2/device/vif/0/state")),
        rec(g3, SET_PERMS, z(b"/local/domain/2/device", b"n2", b"r3")),
    ]
    # A transaction that conflicts with domain 0's write, then XSA-206's credit.
    out["xsa-206-conflict-then-conflict-credit"] = [
        rec(g1, T_START, b"\0"),
        rec(g1, READ, z(b"/local/domain/0/backend/vif/1/0/state"), 1),
        rec(g1, WRITE, b"device/c\0a", 1),
        rec(0, WRITE, b"/local/domain/0/backend/vif/1/0/state\x005"),
        rec(g1, T_END, b"T\0", 1),
        rec(g1, T_START, b"\0"),
        rec(g1, WRITE, b"device/c\0b", 1),
        rec(g2, WRITE, b"device/c\0c"),
        rec(g1, T_END, b"T\0", 1),
    ]
    # Release and introduce again, in a transaction; a dead domain's ACL
    # entries (XSA-322, 483).
    out["xsa-322-483-release-in-a-transaction-and-introduce-again"] = [
        rec(0, SET_PERMS, z(b"/local/domain/2/data", b"n2", b"r1")),
        rec(0, T_START, b"\0"),
        rec(0, RELEASE, z(b"1"), 1),
        rec(0, T_END, b"T\0", 1),
        rec(0, INTRODUCE, z(b"1", b"101", b"11")),
        rec(g1, READ, z(b"/local/domain/2/data")),
    ]
    # Directory listings past a payload: E2BIG on a ring, DIRECTORY_PART (XSA-72).
    out["xsa-72-directory-longer-than-a-payload"] = [rec(0, WRITE, b"/local/domain/1/data/%s\0" % (b"n%03d" % i * 20)) for i in range(60)] + [
        rec(g1, DIRECTORY, z(b"data")),
        rec(g1, DIRECTORY_PART, z(b"data", b"0")),
        rec(g1, DIRECTORY_PART, z(b"data", b"4000")),
        rec(0, CONTROL, z(b"watches")),
        rec(0, CONTROL, z(b"quota", b"1")),
    ]
    # Watches everywhere, then a removal of what they are on (XSA-115, 330).
    out["xsa-115-330-watches-below-a-removed-node"] = [
        rec(g1, WATCH, z(b"/local/domain/1", b"t0")),
        rec(g2, WATCH, z(b"/local/domain/1/device/a/b", b"t1")),
        rec(1, WATCH, z(b"/", b"t2")),
        rec(1, WATCH, z(b"@releaseDomain", b"t3")),
        rec(g1, WRITE, b"device/a/b/c\0x"),
        rec(0, RM, z(b"/local/domain/1/device")),
        rec(g1, RESET_WATCHES, b""),
    ]
    # A guest's transaction keeps its quota of bytes (transaction_bytes_max).
    out["transaction-byte-quota"] = [
        rec(g1, T_START, b"\0"),
        *[rec(g1, WRITE, b"data/b%d\0" % i + b"v" * 1100, 1) for i in range(3)],
        rec(g1, READ, z(b"data/b0"), 1),
        rec(g1, T_END, b"T\0", 1),
    ]
    # CONTROL quota in a transaction: the transaction's own version counts.
    out["control-quota-in-a-transaction"] = [
        rec(0, T_START, b"\0"),
        *[rec(0, WRITE, b"/local/domain/1/data/q%d\0v" % i, 1) for i in range(3)],
        rec(0, SET_PERMS, z(b"/local/domain/1/data/q0", b"n1"), 1),
        rec(0, CONTROL, z(b"quota", b"1"), 1),
        rec(0, CONTROL, z(b"quota", b"1")),
        rec(0, RM, z(b"/local/domain/1/data"), 1),
        rec(0, CONTROL, z(b"quota", b"1"), 1),
        rec(0, T_END, b"T\0", 1),
        rec(0, CONTROL, z(b"quota", b"1")),
        rec(0, CONTROL, z(b"quota", b"-1")),
    ]
    # The events of a commit, one per request as it ran, in order: watches
    # of a guest and a socket on what a transaction writes and removes.
    out["commit-events-in-order"] = [
        rec(g1, WATCH, z(b"data", b"a")),
        rec(g1, WATCH, z(b"/local/domain/1/data/x", b"b")),
        rec(1, WATCH, z(b"/local/domain/1", b"c")),
        rec(g1, T_START, b"\0"),
        rec(g1, WRITE, b"data/x\0" + b"1", 1),
        rec(g1, WRITE, b"data/y\0" + b"2", 1),
        rec(g1, WRITE, b"data/x\0" + b"3", 1),
        rec(g1, RM, z(b"data/y"), 1),
        rec(g1, MKDIR, z(b"data/z/w"), 1),
        rec(g1, T_END, b"T\0", 1),
        rec(0, T_START, b"\0"),
        rec(0, RM, z(b"/local/domain/1/data"), 1),
        rec(0, WRITE, b"/local/domain/1/data\0" + b"again", 1),
        rec(0, T_END, b"T\0", 1),
    ]
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    seeds = {}
    seeds["recorded-vm-baseline-and-start-as-domain-1"] = seed(scenario(["baseline.log", "start.log"], 1))
    seeds["recorded-vm-start-as-domain-2"] = seed(scenario(["start.log"], 2))
    seeds["recorded-vm-start-and-stop-as-domain-3"] = seed(scenario(["start.log", "stop.log"], 3))
    seeds["recorded-vm-stop-as-domain-1"] = seed(scenario(["stop.log"], 1))
    for name, recs in hand_written().items():
        seeds[name] = seed(recs)
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print(f"{name}: {len(data)} bytes")


main()
