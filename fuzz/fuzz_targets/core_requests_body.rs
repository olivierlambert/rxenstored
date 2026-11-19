// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
// The body of the fuzz targets `core_requests` and `core_requests_native`
// (their documentation is `core_requests.rs`'s), included by each after it
// declares `oracle` and `PROFILE`, the profile of the core.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;
use xs_core::log::{Record, Sink, Switches};
use xs_core::{Config, ConnId, Core, DomainState, GaveUp, Machine, Profile, Status};
use xs_wire::{write_header, Decoder, Errno, Message, MsgType, HEADER_LEN, PAYLOAD_MAX};

// ---------------------------------------------------------------------
// The configuration: small quotas, so that limits are reached quickly.

const ENTITY_MAX: usize = 4;
const WATCH_MAX: usize = 2;
const TRANSACTION_MAX: usize = 1;
const REQUEST_MAX: usize = 12;
const OUTSTANDING_MAX: usize = 6;
const WATCH_EVENT_MAX: usize = 4;
const ACL_MAX: usize = 3;
const SOFT_LIMIT: usize = 8 << 10;
const HARD_LIMIT: usize = 256 << 10;
const VALUE_MAX: usize = 2048;
/// `Core::audit` runs at every this many steps, and at the end of an input.
const AUDIT_EVERY: u64 = 4;
/// Bytes a guest's open transactions may keep (`transaction_bytes_max`):
/// small, so that a few requests reach it.
const TXN_BYTES_MAX: usize = 2048;

fn config() -> Config {
    Config {
        profile: PROFILE,
        value_max: VALUE_MAX,
        output_soft_limit: SOFT_LIMIT,
        output_hard_limit: HARD_LIMIT,
        entity_max: ENTITY_MAX,
        watch_max: Some(WATCH_MAX),
        transaction_max: Some(TRANSACTION_MAX),
        request_max: Some(REQUEST_MAX),
        outstanding_max: OUTSTANDING_MAX,
        watch_event_max: WATCH_EVENT_MAX,
        acl_max: ACL_MAX,
        transaction_bytes_max: Some(TXN_BYTES_MAX),
        conflict_burst_limit: 2.0,
        conflict_max_history: Duration::from_millis(50),
        conflict_rate_limit_is_aggregate: true,
        ..Config::default()
    }
}

/// The guests' domids.
const GUESTS: [u32; 3] = [1, 2, 3];
/// Slots: 0 and 1 sockets, 2 domain 0's ring, 3.. the guests.
const NSLOTS: usize = 3 + GUESTS.len();

// ---------------------------------------------------------------------
// The input.

#[derive(Arbitrary, Debug)]
enum Action {
    /// A well-framed request, fed and (if `now`) processed.
    Req { slot: u8, req: Req, now: bool },
    /// Raw bytes fed as they are.
    Raw { slot: u8, bytes: Vec<u8> },
    /// Process up to `n` buffered requests.
    Process { slot: u8, n: u8 },
    /// The connection reads `n` bytes of its output.
    Drain { slot: u8, n: u16 },
    /// Every connection reads all its output.
    DrainAll,
    /// Domain 0 introduces a guest, with its ring or another frame.
    Introduce {
        from: u8,
        dom: u8,
        gfn: u8,
        port: u8,
        tx: Tx,
    },
    /// Domain 0 releases a domain.
    Release { from: u8, dom: u8, tx: Tx },
    /// Domain 0 makes a domain act for another.
    SetTarget { from: u8, dom: u8, target: u8 },
    /// VIRQ_DOM_EXC: Xen's view of one domain changes.
    DomExc { dom: u8, fate: Fate },
    /// The guest asks for a ring reconnection.
    Reconnect { slot: u8 },
    /// The daemon gives up on a ring (corrupt indices).
    Ignore { slot: u8 },
    /// A socket client goes and another comes.
    Reopen { slot: u8 },
    /// Time passes.
    Tick { ms: u16 },
    /// The daemon fires a special watch itself.
    FireSpecial { release: bool },
    /// The next map or bind fails.
    FailMachine { connect: bool, rebind: bool },
    /// The common requests, well formed (the generic `Req` reaches them
    /// too, but rarely in this shape), processed at once.
    Op { slot: u8, op: Op, tx: Tx },
    /// Up to 6 watches on one path, tokens `b0`... (to reach the quota).
    Watches { slot: u8, path: PathArb, n: u8 },
    /// Up to 4 transactions started (to reach the quota).
    Starts { slot: u8, n: u8 },
}

#[derive(Arbitrary, Debug)]
enum Op {
    Read(PathArb),
    Directory(PathArb),
    GetPerms(PathArb),
    Write(PathArb, Val),
    Mkdir(PathArb),
    Rm(PathArb),
    SetPerms(PathArb, Vec<(u8, u8)>),
    Watch(PathArb, u8),
    Unwatch(PathArb, u8),
    Start,
    End(bool),
    Reset,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Fate {
    Running,
    Shutdown,
    Dead,
}

#[derive(Arbitrary, Debug)]
struct Req {
    ty: Ty,
    tx: Tx,
    fields: Vec<Field>,
    /// A NUL after the last field.
    nul: bool,
    req_id: Option<u32>,
}

#[derive(Arbitrary, Debug)]
enum Ty {
    Known(u8),
    Raw(u32),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Tx {
    None,
    /// One of the connection's open transactions, if any.
    Open(u8),
    Raw(u32),
}

#[derive(Arbitrary, Debug)]
enum Field {
    Path(PathArb),
    Perm { letter: u8, dom: Num },
    Num(Num),
    Token(u8),
    LongToken(u16),
    Value(Val),
    Lit(u8),
    Bytes(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct PathArb {
    start: Start,
    comps: Vec<Comp>,
    slash: bool,
}

#[derive(Arbitrary, Debug)]
enum Start {
    Abs,
    Rel,
    Home(u8),
    Special(u8),
    /// Below a directory a guest owns (its own, relative, or another's).
    Own(u8),
    /// A node the set-up makes (or the store starts with), as it is or
    /// as the parent of the components that follow.
    Known(u8),
}

#[derive(Arbitrary, Debug)]
enum Comp {
    Word(u8),
    Raw(Vec<u8>),
    Long(u16),
}

#[derive(Arbitrary, Debug)]
enum Num {
    Dom(u8),
    Int(i64),
    Text(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Val {
    Short(u8),
    Len(u16),
    Raw(Vec<u8>),
}

const WORDS: &[&[u8]] = &[
    b"local",
    b"domain",
    b"0",
    b"1",
    b"2",
    b"3",
    b"9",
    b"device",
    b"vif",
    b"vbd",
    b"backend",
    b"control",
    b"shutdown",
    b"data",
    b"memory",
    b"target",
    b"a",
    b"b",
    b"c",
    b"state",
    b"tool",
    b"xenstored",
    b"vm",
    b"@releaseDomain",
    b"@introduceDomain",
    b"..",
    b".",
    b"x y",
    b"-",
    b"_",
    b"1_0",
    b"+1",
    b"-1",
    b"feature",
    b"32752",
    b"4294967297",
];
const HOMES: &[&[u8]] = &[
    b"0",
    b"1",
    b"2",
    b"3",
    b"9",
    b"-1",
    b"+1",
    b"01",
    b"1_",
    b"4294967297",
    b"",
];
const OWN: &[&[u8]] = &[
    b"device/",
    b"data/",
    b"/local/domain/1/device/",
    b"/local/domain/2/data/",
    b"/local/domain/3/device/",
    b"control/shutdown",
];
const KNOWN: &[&[u8]] = &[
    b"/",
    b"/local",
    b"/local/domain",
    b"/local/domain/0",
    b"/local/domain/1",
    b"/local/domain/2",
    b"/local/domain/3",
    b"/local/domain/1/control",
    b"/local/domain/1/control/shutdown",
    b"/local/domain/2/device",
    b"/local/domain/3/data",
    b"/local/domain/0/backend/vif/1/0",
    b"/local/domain/0/backend/vif/2/0/state",
    b"/tool",
    b"/tool/xenstored",
    b"@releaseDomain",
    b"@introduceDomain",
    b"control/shutdown",
    b"device",
    b"data",
];
const SPECIALS: &[&[u8]] = &[
    b"@introduceDomain",
    b"@releaseDomain",
    b"@other",
    b"@",
    b"@releaseDomain/x",
];
const DOMS: &[&[u8]] = &[
    b"0",
    b"1",
    b"2",
    b"3",
    b"9",
    b"32752",
    b"32751",
    b"-1",
    b"+2",
    b"0x3",
    b"1_0",
    b" 1",
    b"4294967297",
    b"9223372036854775807",
    b"9223372036854775808",
    b"",
    b"abc",
];
const LITS: &[&[u8]] = &[
    b"T",
    b"F",
    b"X",
    b"",
    b"watches",
    b"quota",
    b"mfn",
    b"print",
    b"xenbus",
    b"live-update",
    b"help",
    b"memreport",
    b"-1",
];
const VALUES: &[&[u8]] = &[b"", b"x", b"yy", b"0", b"1", b"4", b"5", b"6", b"on", b"\xff\x00\n"];

fn pick<'a>(v: &[&'a [u8]], i: u8) -> &'a [u8] {
    v[i as usize % v.len()]
}

fn num(n: &Num, out: &mut Vec<u8>) {
    match n {
        Num::Dom(i) => out.extend_from_slice(pick(DOMS, *i)),
        Num::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Num::Text(t) => out.extend_from_slice(t),
    }
}

fn path(p: &PathArb, out: &mut Vec<u8>) {
    match p.start {
        Start::Abs => out.push(b'/'),
        Start::Rel => {}
        Start::Home(d) => {
            out.extend_from_slice(b"/local/domain/");
            out.extend_from_slice(pick(HOMES, d));
            out.push(b'/');
        }
        Start::Special(i) => out.extend_from_slice(pick(SPECIALS, i)),
        Start::Own(i) => out.extend_from_slice(pick(OWN, i)),
        Start::Known(i) => {
            out.extend_from_slice(pick(KNOWN, i));
            if !p.comps.is_empty() && !out.ends_with(b"/") {
                out.push(b'/');
            }
        }
    }
    for (i, c) in p.comps.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        match c {
            Comp::Word(w) => out.extend_from_slice(pick(WORDS, *w)),
            Comp::Raw(r) => out.extend_from_slice(r),
            Comp::Long(n) => out.extend(std::iter::repeat_n(b'l', *n as usize % 4000)),
        }
    }
    if p.slash {
        out.push(b'/');
    }
}

fn field(f: &Field, out: &mut Vec<u8>) {
    match f {
        Field::Path(p) => path(p, out),
        Field::Perm { letter, dom } => {
            out.push(b"nrwbx"[*letter as usize % 5]);
            num(dom, out);
        }
        Field::Num(n) => num(n, out),
        Field::Token(t) => out.extend_from_slice(format!("t{}", t % 4).as_bytes()),
        Field::LongToken(n) => out.extend(std::iter::repeat_n(b'k', *n as usize % 4096)),
        Field::Value(Val::Short(i)) => out.extend_from_slice(pick(VALUES, *i)),
        Field::Value(Val::Len(n)) => out.extend(std::iter::repeat_n(b'v', *n as usize % 5000)),
        Field::Value(Val::Raw(r)) => out.extend_from_slice(r),
        Field::Lit(i) => out.extend_from_slice(pick(LITS, *i)),
        Field::Bytes(b) => out.extend_from_slice(b),
    }
}

// ---------------------------------------------------------------------
// The machine: what the core asks of Xen.

#[derive(Default)]
struct FakeXen {
    /// Domains with a connection, as the machine saw them come and go.
    known: BTreeMap<u32, ConnId>,
    fail_connect: bool,
    fail_rebind: bool,
}

impl Machine for FakeXen {
    fn connect(&mut self, conn: ConnId, domid: u32, _gfn: u64, _port: u32) -> Result<(), Errno> {
        assert!(
            !self.known.contains_key(&domid),
            "connect of domain {domid}, which is connected"
        );
        assert!(domid < 0x7ff0, "connect of reserved domid {domid}");
        if std::mem::take(&mut self.fail_connect) {
            return Err(Errno::EINVAL);
        }
        self.known.insert(domid, conn);
        Ok(())
    }

    fn rebind(&mut self, conn: ConnId, domid: u32, _port: u32) -> Result<(), Errno> {
        assert_eq!(self.known.get(&domid), Some(&conn), "rebind of domain {domid}");
        if std::mem::take(&mut self.fail_rebind) {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    fn disconnect(&mut self, conn: ConnId, domid: u32) {
        assert_eq!(self.known.remove(&domid), Some(conn), "disconnect of domain {domid}");
    }
}

// ---------------------------------------------------------------------
// The access log, formatted as the daemon formats it.

struct LogCheck;

impl Sink for LogCheck {
    fn record(&self, r: &Record<'_>) {
        let mut data = Vec::new();
        r.data.copy_to(&mut data, 1 << 16);
        let mut line = Vec::new();
        xs_daemon::log::format::access_line(&mut line, None, r.who, r.tid, r.op, &data);
        assert!(
            !line.iter().any(|c| *c == b'\n' || *c == b'\r' || *c == 0),
            "an access-log line with a line break or NUL: {:?}",
            String::from_utf8_lossy(&line)
        );
    }
}

// ---------------------------------------------------------------------
// The harness's view of each connection.

type Store = oracle::Store;

/// A watch as the harness knows it from the replies.
#[derive(Clone, Debug)]
struct W {
    /// `Err(name)` for a special path, else the components.
    key: Result<Vec<Vec<u8>>, Vec<u8>>,
    token: Vec<u8>,
    relative: bool,
}

struct Slot {
    id: Option<ConnId>,
    domid: u32,
    ring: bool,
    target: Option<u32>,
    /// The core gave up on it (`ignore`): what it sends is discarded.
    dead: bool,
    /// The requests fed, as the core's decoder will read them.
    mirror: Decoder,
    /// Bytes of the output stream consumed and parsed.
    consumed: u64,
    parsed: u64,
    /// Messages parsed and not consumed: (start in the stream, kind).
    queued: VecDeque<(u64, Kind)>,
    watches: Vec<W>,
    /// Open transactions.
    txns: BTreeMap<u32, OpenTxn>,
    next_req: u32,
    /// It acted for domain 0 at some point: its holdings are not bounded.
    privileged: bool,
}

impl Slot {
    fn new(id: Option<ConnId>, domid: u32, ring: bool) -> Slot {
        Slot {
            id,
            domid,
            ring,
            target: None,
            dead: false,
            mirror: Decoder::new(),
            consumed: 0,
            parsed: 0,
            queued: VecDeque::new(),
            watches: Vec::new(),
            txns: BTreeMap::new(),
            next_req: 1,
            privileged: false,
        }
    }

    fn who(&self) -> oracle::Who {
        (self.domid, self.target)
    }

    fn is_dom0(&self) -> bool {
        oracle::is_dom0(self.who())
    }

    fn home(&self) -> Vec<u8> {
        format!("/local/domain/{}/", self.domid).into_bytes()
    }

    /// The output and everything that came with the connection's state go
    /// (reconnection, ignore).
    fn reset_output(&mut self) {
        self.consumed = 0;
        self.parsed = 0;
        self.queued.clear();
    }
}

/// An open transaction as the harness knows it.
struct OpenTxn {
    /// The store when it started.
    start: Rc<Store>,
    /// Who its connection was (domain and target) at each request handled
    /// in it. A commit on a store that nothing replaced since the
    /// transaction started publishes the transaction's version as its
    /// requests made it, with the rights they had then; otherwise its
    /// requests run again with the rights of the commit.
    ran_as: Vec<oracle::Who>,
}

/// What a queued message is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Reply,
    Event,
    /// An E2BIG error in place of a watch event too long for a ring.
    BigEvent,
}

/// What a request handled in this step was.
struct Handled {
    slot: usize,
    msg: Message,
    /// Its connection when it came: who, acting for domain 0 now or before.
    who: oracle::Who,
    privileged: bool,
    home: Vec<u8>,
}

struct H {
    core: Core,
    xen: FakeXen,
    slots: Vec<Slot>,
    now: Duration,
    /// The store before the step.
    before: Rc<Store>,
    /// The transaction that ended in this step.
    ended: Option<OpenTxn>,
    /// Connections the core gave up on in this step.
    gave_up: Vec<ConnId>,
    /// The domains with a connection before the step.
    domains: Vec<u32>,
    /// Replaying a seed's records: only what the harness must follow is
    /// followed (no audit, no store, permission or quota checks).
    fast: bool,
    /// `fingerprint` of the store `before` is a copy of: the store is
    /// copied again only when it changed.
    fingerprint: u64,
    /// Steps checked so far (`AUDIT_EVERY`).
    steps: u64,
}

fn flatten(core: &Core) -> Store {
    oracle::core_store(core)
}

/// A hash of the generations of every node, in tree order. Every change
/// of a node's value or permissions gives it a new generation, and every
/// change of its children (one added or removed) a new generation of its
/// children (`store::Gen`, `vgen` and `cgen`): two stores with the same
/// fingerprint are the same store (up to a collision of 64-bit hashes),
/// at the cost of a walk that copies nothing.
fn fingerprint(root: &xs_core::store::Node) -> u64 {
    fn mix(h: u64, v: u64) -> u64 {
        (h.rotate_left(5) ^ v).wrapping_mul(0x517c_c1b7_2722_0a95)
    }
    fn walk(n: &xs_core::store::Node, h: u64) -> u64 {
        let mut h = mix(mix(h, n.vgen), n.cgen);
        for (_, c) in n.children.iter() {
            h = walk(c, h);
        }
        mix(h, 1)
    }
    walk(root, 0)
}

/// The nodes an event's absolute path may name. A node made by a request
/// on a path starting with `@` is a child of the root whose name is all of
/// it, slashes included (`path::components`), and its events show it as
/// `/` + that name: so `/@a/b/c` may be `[@a, b, c]`, `[@a/b, c]` or
/// `[@a/b/c]`.
fn interpretations(abs: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let mut out: Vec<Vec<Vec<u8>>> = comps(abs).into_iter().collect();
    if let Some(rest) = abs.strip_prefix(b"/").filter(|r| r.first() == Some(&b'@')) {
        for (k, _) in rest.iter().enumerate().filter(|(_, c)| **c == b'/') {
            if let Some(mut tail) = comps(&rest[k..]) {
                tail.insert(0, rest[..k].to_vec());
                out.push(tail);
            }
        }
        out.push(vec![rest.to_vec()]);
    }
    out
}

/// Components of an absolute path, as the model parses them.
fn comps(abs: &[u8]) -> Option<Vec<Vec<u8>>> {
    oracle::parse_path(abs, b"/")
}

fn absolute(p: &[u8], home: &[u8]) -> Vec<u8> {
    match p.first() {
        Some(b'/') | Some(b'@') => p.to_vec(),
        _ => [home, p].concat(),
    }
}

fn may(store: &Store, p: &[Vec<u8>], who: oracle::Who, want: u8) -> bool {
    store.get(p).is_some_and(|n| allowed(&n.perms, who, want))
}

/// The model's `oracle::allowed`, for any number in the permissions: the
/// root's owner, once the domain that owned it is gone, is -1, shown as
/// 9223372036854775807 (the root's lost owner), which no domain is.
fn allowed(perms: &[u8], who: oracle::Who, want: u8) -> bool {
    let entries: Vec<(u8, u64)> = perms
        .split(|c| *c == 0)
        .filter_map(|e| e.split_first())
        .map(|(l, n)| {
            (
                *l,
                std::str::from_utf8(n)
                    .ok()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(u64::MAX),
            )
        })
        .collect();
    let Some(&(other, owner)) = entries.first() else {
        return false;
    };
    let ids: Vec<u64> = [Some(who.0), who.1].into_iter().flatten().map(u64::from).collect();
    if oracle::is_dom0(who) || ids.contains(&owner) {
        return true;
    }
    ids.iter().any(|d| {
        let letter = entries[1..].iter().find(|e| e.1 == *d).map_or(other, |e| e.0);
        letter == b'b' || letter == want
    })
}

/// Number of ACL entries of encoded permissions (the owner aside).
fn acl_len(perms: &[u8]) -> usize {
    perms.iter().filter(|c| **c == 0).count().saturating_sub(1)
}

impl H {
    fn new() -> H {
        let mut core = Core::new(config(), [0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321]);
        core.set_access_log(
            Some(Box::new(LogCheck)),
            Switches {
                read_ops: true,
                transaction_ops: true,
                special_ops: true,
            },
        );
        let mut slots = Vec::new();
        slots.push(Slot::new(Some(core.open()), 0, false));
        slots.push(Slot::new(Some(core.open()), 0, false));
        let d0 = core.open_domain(0);
        slots.push(Slot::new(Some(d0), 0, true));
        let mut xen = FakeXen::default();
        xen.known.insert(0, d0);
        for d in GUESTS {
            slots.push(Slot::new(None, d, true));
        }
        let before = Rc::new(flatten(&core));
        let mut h = H {
            core,
            xen,
            slots,
            now: Duration::ZERO,
            before,
            ended: None,
            gave_up: Vec::new(),
            domains: vec![0],
            // The set-up is the same for every input: followed, not checked.
            fast: true,
            fingerprint: 0,
            steps: 0,
        };
        // The toolstack's part of a domain's start, as in the recorded
        // scenario of xs-bench: the guest's home, read-only for it, with
        // directories it owns, and one node of domain 0 it may write.
        for d in GUESTS {
            let home = format!("/local/domain/{d}");
            let setup: Vec<(MsgType, Vec<u8>)> = vec![
                (MsgType::Mkdir, format!("{home}\0").into_bytes()),
                (MsgType::SetPerms, format!("{home}\0n0\0r{d}\0").into_bytes()),
                (MsgType::Mkdir, format!("{home}/device\0").into_bytes()),
                (MsgType::SetPerms, format!("{home}/device\0n{d}\0").into_bytes()),
                (MsgType::Mkdir, format!("{home}/data\0").into_bytes()),
                (MsgType::SetPerms, format!("{home}/data\0n{d}\0").into_bytes()),
                (MsgType::Write, format!("{home}/control/shutdown\0").into_bytes()),
                (MsgType::SetPerms, format!("{home}/control\0n0\0r{d}\0").into_bytes()),
                (
                    MsgType::SetPerms,
                    format!("{home}/control/shutdown\0n0\0w{d}\0").into_bytes(),
                ),
                (
                    MsgType::Write,
                    format!("/local/domain/0/backend/vif/{d}/0/state\0001").into_bytes(),
                ),
                (
                    MsgType::SetPerms,
                    format!("/local/domain/0/backend/vif/{d}/0\0n0\0r{d}\0").into_bytes(),
                ),
                (
                    MsgType::Introduce,
                    format!("{d}\0{}\0{}\0", 100 + d, 10 + d).into_bytes(),
                ),
            ];
            for (ty, payload) in setup {
                h.request(0, ty as u32, 0, payload, None);
                h.process(0, 1);
                h.drain_all();
            }
        }
        // Domain 3 is domain 2's stub domain.
        h.request(0, MsgType::SetTarget as u32, 0, b"3\x002\0".to_vec(), None);
        h.process(0, 1);
        h.slots.iter_mut().for_each(|s| s.privileged = false);
        h.drain_all();
        // Checked once, whole, at the end of the set-up.
        h.fast = false;
        h.before = Rc::new(flatten(&h.core));
        h.fingerprint = fingerprint(h.core.root());
        h.after(None);
        h
    }

    /// The live slot of a fuzzer's number, if it has a connection.
    fn live(&self, slot: u8) -> Option<usize> {
        let i = slot as usize % NSLOTS;
        self.slots[i].id.map(|_| i)
    }

    fn feed(&mut self, i: usize, bytes: &[u8]) {
        let s = &mut self.slots[i];
        let Some(id) = s.id else { return };
        if !s.dead {
            s.mirror.push(bytes);
        }
        self.core.feed(id, bytes);
    }

    fn tx(&self, i: usize, tx: Tx) -> u32 {
        match tx {
            Tx::None => 0,
            Tx::Open(k) => {
                let t: Vec<u32> = self.slots[i].txns.keys().copied().collect();
                if t.is_empty() {
                    0
                } else {
                    t[k as usize % t.len()]
                }
            }
            Tx::Raw(t) => t,
        }
    }

    fn request(&mut self, i: usize, ty: u32, tx: u32, payload: Vec<u8>, req_id: Option<u32>) {
        let s = &mut self.slots[i];
        let req = req_id.unwrap_or_else(|| {
            s.next_req = s.next_req.wrapping_add(1).max(1);
            s.next_req
        });
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
        write_header(&mut bytes, ty, req, tx, payload.len() as u32);
        bytes.extend_from_slice(&payload);
        self.feed(i, &bytes);
    }

    /// Processes up to `n` requests of slot `i`, one at a time, checking
    /// after each.
    fn process(&mut self, i: usize, n: usize) {
        for _ in 0..n {
            let Some(id) = self.slots[i].id else { return };
            let st = self.core.process_on(id, 1, &mut self.xen);
            let handled = if st == Status::More {
                let msg = match self.slots[i].mirror.next_message() {
                    Ok(Some(m)) => m,
                    other => panic!("the core handled a request the stream does not have: {other:?}"),
                };
                if trace() {
                    eprintln!(
                        "  slot {i} (domain {}, target {:?}) handled type {} req {} tx {} {:?}",
                        self.slots[i].domid,
                        self.slots[i].target,
                        msg.ty,
                        msg.req_id,
                        msg.tx_id,
                        String::from_utf8_lossy(&msg.payload)
                    );
                }
                let s = &mut self.slots[i];
                let who = s.who();
                if let Some(t) = s.txns.get_mut(&msg.tx_id) {
                    if !t.ran_as.contains(&who) {
                        t.ran_as.push(who);
                    }
                }
                Some(Handled {
                    slot: i,
                    msg,
                    who: s.who(),
                    privileged: s.privileged || s.is_dom0(),
                    home: s.home(),
                })
            } else {
                None
            };
            self.after(handled.as_ref());
            if st != Status::More {
                return;
            }
        }
    }

    fn drain_all(&mut self) {
        for i in 0..NSLOTS {
            if let Some(id) = self.slots[i].id {
                let n = self.core.output(id).len();
                self.consume(i, n);
            }
        }
        self.after(None);
    }

    fn consume(&mut self, i: usize, n: usize) {
        let Some(id) = self.slots[i].id else { return };
        let n = n.min(self.core.output(id).len());
        self.core.consume(id, n);
        let s = &mut self.slots[i];
        s.consumed += n as u64;
        while s.queued.front().is_some_and(|m| m.0 < s.consumed) {
            s.queued.pop_front();
        }
    }

    // -----------------------------------------------------------------
    // After every step.

    fn audit_now(&self) {
        if let Err(e) = timed(P_AUDIT, || self.core.audit()) {
            panic!("audit: {e}");
        }
    }

    fn after(&mut self, handled: Option<&Handled>) {
        // `Core::audit` recounts the whole store and every transaction: at
        // every fourth step, and at the end of each input (`audit_now`).
        // What it checks are counts that stay wrong once wrong, so a later
        // step still sees them.
        self.steps += 1;
        if !self.fast && self.steps % AUDIT_EVERY == 0 {
            self.audit_now();
        }
        // What the daemon does with connections the core gave up on.
        let mut dead = Vec::new();
        self.core.take_dead(&mut dead);
        self.gave_up = dead.iter().map(|d| d.0).collect();
        self.ended = None;
        let mut dirty = Vec::new();
        self.core.take_dirty(&mut dirty);
        let mut drops = Vec::new();
        self.core.take_drops(&mut drops);
        let after = if self.fast {
            self.before.clone()
        } else {
            let f = timed(P_FLATTEN, || fingerprint(self.core.root()));
            if f == self.fingerprint {
                self.before.clone()
            } else {
                self.fingerprint = f;
                Rc::new(timed(P_FLATTEN, || flatten(&self.core)))
            }
        };
        // Those that acted for a domain that went no longer do.
        let domains: Vec<u32> = self.core.domains().map(|d| d.0).collect();
        for d in std::mem::take(&mut self.domains) {
            if !domains.contains(&d) {
                self.domain_gone(d);
            }
        }
        self.domains = domains;
        self.refresh_slots();
        let mut parsed: Vec<(usize, Vec<Message>)> = Vec::new();
        for i in 0..NSLOTS {
            let msgs = timed(P_PARSE, || self.parse(i));
            if trace() {
                for m in &msgs {
                    let p = String::from_utf8_lossy(&m.payload);
                    let p: String = p.chars().take(80).collect();
                    eprintln!("    -> slot {i}: type {} req {} tx {} {p:?}", m.ty, m.req_id, m.tx_id);
                }
                if let Some(id) = self.slots[i].id {
                    let q = &self.slots[i].queued;
                    let ev = q.iter().filter(|m| m.1 != Kind::Reply).count();
                    if !q.is_empty() {
                        eprintln!(
                            "    slot {i}: {} bytes, {ev} events (or E2BIG for one) and {} replies unread",
                            self.core.output(id).len(),
                            q.len() - ev
                        );
                    }
                }
            }
            parsed.push((i, msgs));
        }
        timed(P_REPLIES, || self.check_replies(handled, &parsed));
        timed(P_EVENTS, || self.check_events(handled, &parsed, &after));
        if let (Some(h), false) = (handled, self.fast) {
            timed(P_STORE, || self.check_store(h, &after));
            timed(P_READS, || self.check_reads(h, &parsed));
        }
        if !self.fast {
            timed(P_HOLDINGS, || self.check_holdings(&after));
        }
        // Domains as the machine and the core see them.
        let core_domains: BTreeMap<u32, ConnId> = self.core.domains().collect();
        assert_eq!(core_domains, self.xen.known, "domains of the core and of the machine");
        let tracked: usize = self
            .slots
            .iter()
            .filter(|s| s.id.is_some())
            .map(|s| s.watches.len())
            .sum();
        assert_eq!(self.core.watches(), tracked, "watches of the core and of the replies");
        for s in &self.slots {
            if let Some(id) = s.id {
                assert_eq!(
                    self.core.transactions(id),
                    s.txns.len(),
                    "transactions of domain {}",
                    s.domid
                );
            }
        }
        for (id, why) in dead {
            if let Some(i) = self.slots.iter().position(|s| s.id == Some(id)) {
                if self.slots[i].ring {
                    self.ignore(i);
                } else {
                    let _ = why == GaveUp::Protocol;
                    self.core.close(id);
                    let s = &mut self.slots[i];
                    *s = Slot::new(None, 0, false);
                }
            } else if self.core.domains().any(|(_, c)| c == id) {
                self.core.ignore(id);
            } else {
                self.core.close(id);
            }
        }
        self.before = after;
    }

    /// Follows the domains' connections: a guest's may have gone (RELEASE,
    /// death) or come (INTRODUCE).
    fn refresh_slots(&mut self) {
        for i in 3..NSLOTS {
            let d = self.slots[i].domid;
            let now = self.core.domain_conn(d);
            if now != self.slots[i].id {
                self.slots[i] = Slot::new(now, d, true);
            }
        }
        // Domain 0's ring is replaced by nothing here; sockets stay.
        if self.core.domain_conn(0) != self.slots[2].id {
            panic!("domain 0's ring changed");
        }
    }

    /// Those that acted for a domain that went no longer do.
    fn domain_gone(&mut self, d: u32) {
        for s in &mut self.slots {
            if s.target == Some(d) {
                s.target = None;
            }
        }
    }

    fn ignore(&mut self, i: usize) {
        let Some(id) = self.slots[i].id else { return };
        self.core.ignore(id);
        let s = &mut self.slots[i];
        s.dead = true;
        s.mirror = Decoder::new();
        s.reset_output();
        s.watches.clear();
        s.txns.clear();
    }

    /// The messages queued for slot `i` since the last step, each checked
    /// for form.
    fn parse(&mut self, i: usize) -> Vec<Message> {
        let s = &mut self.slots[i];
        let Some(id) = s.id else { return Vec::new() };
        let out = self.core.output(id);
        assert!(s.parsed >= s.consumed);
        let skip = (s.parsed - s.consumed) as usize;
        assert!(skip <= out.len(), "output shrank: {skip} parsed, {} left", out.len());
        let mut rest = &out[skip..];
        let mut msgs = Vec::new();
        while !rest.is_empty() {
            assert!(rest.len() >= HEADER_LEN, "a partial header queued");
            let w = |k: usize| u32::from_le_bytes(rest[k..k + 4].try_into().unwrap());
            let (ty, req_id, tx_id, len) = (w(0), w(4), w(8), w(12) as usize);
            assert!(rest.len() >= HEADER_LEN + len, "a partial message queued");
            let payload = rest[HEADER_LEN..HEADER_LEN + len].to_vec();
            let unlimited = !s.ring
                && matches!(
                    MsgType::from_u32(ty),
                    Some(MsgType::Directory | MsgType::Control | MsgType::WatchEvent)
                );
            assert!(
                len <= PAYLOAD_MAX || unlimited,
                "a reply of {len} bytes, type {ty}, to domain {} (ring {})",
                s.domid,
                s.ring
            );
            let event = ty == MsgType::WatchEvent as u32;
            if ty == MsgType::Error as u32 {
                let name = payload.strip_suffix(b"\0").expect("an error name without its NUL");
                assert!(
                    Errno::ALL.iter().any(|e| e.name().as_bytes() == name),
                    "unknown error {:?}",
                    String::from_utf8_lossy(name)
                );
            }
            if event {
                assert_eq!((req_id, tx_id), (0, 0), "a watch event with ids");
                let f: Vec<&[u8]> = payload.split(|c| *c == 0).collect();
                assert!(f.len() == 3 && f[2].is_empty(), "malformed event {payload:?}");
            }
            let kind = if event {
                Kind::Event
            } else if ty == MsgType::Error as u32 && req_id == 0 && tx_id == 0 && payload == b"E2BIG\0" {
                Kind::BigEvent
            } else {
                Kind::Reply
            };
            s.queued.push_back((s.parsed, kind));
            s.parsed += (HEADER_LEN + len) as u64;
            msgs.push(Message {
                ty,
                req_id,
                tx_id,
                payload,
            });
            rest = &rest[HEADER_LEN + len..];
        }
        msgs
    }

    /// One reply per request handled, with its ids; replies change what
    /// the harness knows (watches, transactions, targets).
    fn check_replies(&mut self, handled: Option<&Handled>, parsed: &[(usize, Vec<Message>)]) {
        for (i, msgs) in parsed {
            let is_e2big_event =
                |m: &Message| m.ty == MsgType::Error as u32 && m.req_id == 0 && m.tx_id == 0 && m.payload == b"E2BIG\0";
            let replies: Vec<&Message> = msgs.iter().filter(|m| m.ty != MsgType::WatchEvent as u32).collect();
            match handled {
                Some(h) if h.slot == *i => {
                    let req = &h.msg;
                    let mt = MsgType::from_u32(req.ty);
                    let tid = if matches!(mt, Some(MsgType::Watch | MsgType::Unwatch)) {
                        0
                    } else {
                        req.tx_id
                    };
                    let mine: Vec<&&Message> = replies
                        .iter()
                        .filter(|m| !(is_e2big_event(m) && req.req_id != 0) || replies.len() == 1)
                        .collect();
                    let id = self.slots[*i].id;
                    if id.is_none() || self.slots[*i].dead || id.is_some_and(|id| self.gave_up.contains(&id)) {
                        continue;
                    }
                    if req.req_id != 0 {
                        assert_eq!(mine.len(), 1, "replies to one request: {replies:?}");
                    }
                    // E2BIG to a request of id 0 outside a transaction
                    // looks like an E2BIG in place of an event: it is the
                    // first of this step's (a reply goes before the events
                    // of its request), and a reply.
                    if req.req_id == 0 && tid == 0 && !replies.is_empty() && replies.iter().all(|m| is_e2big_event(m)) {
                        let s = &mut self.slots[*i];
                        let first = s.queued.len() - msgs.len();
                        let q = s.queued.iter_mut().skip(first).find(|q| q.1 == Kind::BigEvent);
                        q.expect("this step's E2BIG").1 = Kind::Reply;
                    }
                    let Some(r) = mine.last() else { continue };
                    assert_eq!(r.req_id, req.req_id, "reply's request id");
                    assert_eq!(r.tx_id, tid, "reply's transaction id");
                    assert!(
                        r.ty == req.ty || r.ty == MsgType::Error as u32,
                        "reply of type {}",
                        r.ty
                    );
                    let ok = r.ty == req.ty;
                    self.learn(*i, req, tid, ok, &r.payload);
                }
                _ => {
                    for r in &replies {
                        assert!(is_e2big_event(r), "a reply to no request: {r:?}");
                    }
                }
            }
        }
    }

    /// What a reply tells of the connection's state.
    fn learn(&mut self, i: usize, req: &Message, tid: u32, ok: bool, reply: &[u8]) {
        let Some(mt) = MsgType::from_u32(req.ty) else { return };
        let home = self.slots[i].home();
        let f = oracle::split(&req.payload, 8);
        match mt {
            MsgType::Watch if ok => {
                let (node, token) = (f[0], f[1]);
                let key = if node.first() == Some(&b'@') {
                    Err(node.to_vec())
                } else {
                    Ok(comps(&absolute(node, &home)).expect("a watch accepted on a path the model refuses"))
                };
                let relative = !matches!(node.first(), Some(b'/' | b'@'));
                self.slots[i].watches.push(W {
                    key,
                    token: token.to_vec(),
                    relative,
                });
            }
            MsgType::Unwatch if ok => {
                let (node, token) = (f[0], f[1]);
                let key = if node.first() == Some(&b'@') {
                    Err(node.to_vec())
                } else {
                    Ok(comps(&absolute(node, &home)).expect("an unwatch accepted on a path the model refuses"))
                };
                let w = &mut self.slots[i].watches;
                let k = w
                    .iter()
                    .position(|w| w.key == key && w.token == token)
                    .expect("unwatch of no watch");
                w.remove(k);
            }
            MsgType::ResetWatches if ok => {
                self.slots[i].watches.clear();
                self.slots[i].txns.clear();
            }
            MsgType::TransactionStart if ok => {
                let t: u32 = std::str::from_utf8(reply.strip_suffix(b"\0").unwrap())
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(t != 0 && !self.slots[i].txns.contains_key(&t), "transaction id {t}");
                let start = self.before.clone();
                self.slots[i].txns.insert(
                    t,
                    OpenTxn {
                        start,
                        ran_as: Vec::new(),
                    },
                );
            }
            MsgType::TransactionEnd => {
                // Ended, committed or not, unless refused before: a bad
                // argument, the request quota, or no such transaction.
                let refused = !ok && matches!(reply, b"EINVAL\0" | b"EQUOTA\0" | b"ENOSPC\0" | b"EIO\0" | b"ENOENT\0");
                if !refused {
                    self.ended = self.slots[i].txns.remove(&tid);
                }
            }
            MsgType::SetTarget if ok => {
                let (d, t) = (f[0], f[1]);
                let d = u32::try_from(xs_core::path::c_int(d)).unwrap();
                let t = u32::try_from(xs_core::path::c_int(t.split(|c| *c == 0).next().unwrap())).ok();
                let conn = self.core.domain_conn(d);
                for s in &mut self.slots {
                    if s.id.is_some() && s.id == conn {
                        s.target = t;
                        if t == Some(0) {
                            s.privileged = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Every event matches a watch of its connection, and a guest's is
    /// for a node it may read.
    fn check_events(&self, handled: Option<&Handled>, parsed: &[(usize, Vec<Message>)], after: &Store) {
        for (i, msgs) in parsed {
            let s = &self.slots[*i];
            let home = s.home();
            let mut last_watch: Option<&Message> = None;
            for m in msgs {
                if m.ty != MsgType::WatchEvent as u32 {
                    if handled.is_some_and(|h| h.slot == *i && h.msg.ty == MsgType::Watch as u32) {
                        last_watch = handled.map(|h| &h.msg);
                    }
                    continue;
                }
                let f: Vec<&[u8]> = m.payload.split(|c| *c == 0).collect();
                let (ep, token) = (f[0], f[1]);
                // The first event of a new watch: unchecked, by design.
                if let Some(w) = last_watch.take() {
                    let wf = oracle::split(&w.payload, 8);
                    if wf[0] == ep && wf[1] == token {
                        continue;
                    }
                }
                let ea = absolute(ep, &home);
                let ec = if ea.first() == Some(&b'@') {
                    None
                } else {
                    Some(interpretations(&ea))
                };
                let matches = s.watches.iter().any(|w| {
                    w.token == token
                        && match (&w.key, &ec) {
                            (Err(name), _) => *name == ea,
                            (Ok(k), Some(cs)) => {
                                cs.iter().any(|c| c.starts_with(k)) && (w.relative || ep.first() == Some(&b'/'))
                            }
                            (Ok(_), None) => false,
                        }
                });
                assert!(
                    matches,
                    "event {:?} {:?} for domain {} (slot {i}), which has no such watch: {:?}",
                    String::from_utf8_lossy(ep),
                    String::from_utf8_lossy(token),
                    s.domid,
                    s.watches
                );
                if s.is_dom0() || !s.ring || self.fast {
                    continue;
                }
                // Permissions: the stores the change was checked against.
                let mut stores: Vec<&Store> = vec![&self.before, after];
                if let Some(h) = handled {
                    stores.extend(self.slots[h.slot].txns.values().map(|t| &*t.start));
                    if let Some(snap) = self.ended_snapshot(h) {
                        stores.push(snap);
                    }
                }
                let who = s.who();
                let readable = match &ec {
                    None => {
                        // A special path: the root's permissions or its node's.
                        let in_txn = handled.is_some_and(|h| h.msg.tx_id != 0);
                        in_txn
                            || stores
                                .iter()
                                .any(|st| may(st, &[], who, b'r') || may(st, &[ea.clone()], who, b'r'))
                    }
                    Some(cs) => cs.iter().filter(|c| !c.is_empty()).any(|c| {
                        stores
                            .iter()
                            .any(|st| may(st, c, who, b'r') || may(st, &c[..c.len() - 1], who, b'r'))
                    }),
                };
                assert!(
                    readable,
                    "domain {} (target {:?}) got an event for {:?}, which it may not read",
                    s.domid,
                    s.target,
                    String::from_utf8_lossy(&ea)
                );
            }
        }
    }

    /// The snapshot of the transaction a TRANSACTION_END of this step ended.
    fn ended_snapshot(&self, _h: &Handled) -> Option<&Store> {
        self.ended.as_ref().map(|t| &*t.start)
    }

    /// A guest request changed only what it may write, and took no owner
    /// past its node quota.
    fn check_store(&self, h: &Handled, after: &Store) {
        if h.privileged {
            return;
        }
        let before = &*self.before;
        let s = &self.slots[h.slot];
        let end = h.msg.ty == MsgType::TransactionEnd as u32;
        // Who the connection is now, and at the commit of a transaction
        // whose store is still the one it started from, who it was when
        // its requests ran: such a commit publishes the transaction as it
        // ran, as oxenstored's does (`try_commit`). Any other commit runs
        // the requests again, with the rights of now.
        let mut whos = vec![h.who];
        if let (true, Some(t)) = (end, &self.ended) {
            if Rc::ptr_eq(&t.start, &self.before) || *t.start == *before {
                whos.extend(t.ran_as.iter().filter(|w| **w != h.who));
            }
        }
        let can = |p: &[Vec<u8>]| whos.iter().any(|w| may(before, p, *w, b'w'));
        let show = |p: &[Vec<u8>]| String::from_utf8_lossy(&oracle::show(p)).into_owned();
        for (p, n) in after {
            match before.get(p) {
                None => {
                    // Created: the nearest node that existed was writable.
                    let a = (0..p.len())
                        .rev()
                        .map(|k| &p[..k])
                        .find(|a| before.contains_key(*a))
                        .unwrap();
                    assert!(
                        can(a),
                        "domain {} created {} below {}, which it may not write",
                        s.domid,
                        show(p),
                        show(a)
                    );
                }
                Some(old) if old != n => {
                    let parent = &p[..p.len().saturating_sub(1)];
                    // Removed and created again in a transaction: the
                    // parent's permissions (with the guest as owner in the
                    // native profile), which it may write.
                    let native = PROFILE == Profile::Native;
                    let again = end
                        && !p.is_empty()
                        && after
                            .get(parent)
                            .is_some_and(|q| oracle::created(&q.perms, h.who, native) == n.perms)
                        && can(parent);
                    assert!(
                        can(p) || again,
                        "domain {} changed {}, which it may not write",
                        s.domid,
                        show(p)
                    );
                    if old.perms != n.perms && !again {
                        let (o, o2) = (owner(&old.perms), owner(&n.perms));
                        assert_eq!(o, o2, "domain {} gave {} away", s.domid, show(p));
                        assert!(
                            p.is_empty() || whos.iter().any(|w| Some(w.0) == o || (w.1.is_some() && w.1 == o)),
                            "domain {} changed the permissions of {}, which it does not own",
                            s.domid,
                            show(p)
                        );
                        assert!(
                            acl_len(&n.perms) <= ACL_MAX,
                            "domain {} set an ACL past its quota",
                            s.domid
                        );
                    }
                }
                Some(_) => {}
            }
        }
        for p in before.keys().filter(|p| !after.contains_key(*p)) {
            // Removed: the top of what went was writable (or the root, for
            // a removal of the root).
            let mut top: &[Vec<u8>] = p;
            while top.len() > 1 && !after.contains_key(&top[..top.len() - 1]) {
                top = &top[..top.len() - 1];
            }
            assert!(
                can(top) || (top.len() == 1 && can(&[])),
                "domain {} removed {}, which it may not write",
                s.domid,
                show(p)
            );
        }
        // Node quotas: no owner other than domain 0 goes past entity_max
        // by a guest's request (it may be past it by domain 0's doing).
        let counts = |st: &Store| {
            let mut c: BTreeMap<u32, usize> = BTreeMap::new();
            for (p, n) in st {
                if let (false, Some(o)) = (p.is_empty(), owner(&n.perms)) {
                    *c.entry(o).or_default() += 1;
                }
            }
            c
        };
        let (cb, ca) = (counts(before), counts(after));
        for (o, n) in ca {
            if o == 0 || o == u32::MAX {
                continue;
            }
            let was = cb.get(&o).copied().unwrap_or(0);
            assert!(
                n <= was.max(ENTITY_MAX),
                "domain {}'s request took domain {o} from {was} to {n} nodes (quota {ENTITY_MAX})",
                s.domid
            );
        }
    }

    /// A guest's answered READ, DIRECTORY, GET_PERMS or DIRECTORY_PART
    /// outside a transaction was for a node that exists and that it may read.
    fn check_reads(&self, h: &Handled, parsed: &[(usize, Vec<Message>)]) {
        let s = &self.slots[h.slot];
        if h.privileged || h.msg.tx_id != 0 {
            return;
        }
        let Some(mt @ (MsgType::Read | MsgType::Directory | MsgType::GetPerms | MsgType::DirectoryPart)) =
            MsgType::from_u32(h.msg.ty)
        else {
            return;
        };
        let answered = parsed[h.slot].1.iter().any(|m| m.ty == mt as u32);
        if !answered {
            return;
        }
        let raw = oracle::split(&h.msg.payload, 2)[0];
        let Some(p) = comps(&absolute(raw, &h.home)) else {
            panic!(
                "domain {} got an answer for path {:?}",
                s.domid,
                String::from_utf8_lossy(raw)
            );
        };
        assert!(
            self.before.contains_key(&p),
            "domain {} got an answer for {:?}, which does not exist",
            s.domid,
            String::from_utf8_lossy(raw)
        );
        assert!(
            may(&self.before, &p, h.who, b'r'),
            "domain {} (target {:?}) read {:?}, which it may not read",
            s.domid,
            s.target,
            String::from_utf8_lossy(raw)
        );
    }

    /// What each guest holds stays within its quotas.
    fn check_holdings(&self, after: &Store) {
        for (p, n) in after {
            assert!(
                n.value.len() <= VALUE_MAX,
                "a value of {} bytes at {:?}",
                n.value.len(),
                String::from_utf8_lossy(&oracle::show(p))
            );
        }
        for s in &self.slots[3..] {
            let Some(id) = s.id else { continue };
            if s.privileged || s.is_dom0() || s.dead {
                continue;
            }
            let d = s.domid;
            // One more than the quota, or the quota in the native profile.
            let extra = usize::from(!PROFILE.rules().exact_counts);
            assert!(
                s.watches.len() <= WATCH_MAX + extra,
                "domain {d} has {} watches",
                s.watches.len()
            );
            assert!(
                s.txns.len() <= TRANSACTION_MAX + extra,
                "domain {d} has {} transactions",
                s.txns.len()
            );
            let count = |k: Kind| s.queued.iter().filter(|m| m.1 == k).count();
            // A request in a transaction is refused once the connection's
            // transactions keep the quota: past it by one request at most
            // (a request and its reply, a listing in about a payload).
            let tb = self.core.transaction_bytes(id);
            let tb_max = TXN_BYTES_MAX + 4 * (HEADER_LEN + PAYLOAD_MAX);
            assert!(
                tb <= tb_max,
                "domain {d}'s transactions keep {tb} bytes (bound {tb_max})"
            );
            // An E2BIG in place of an event is an event for the quota.
            let (events, replies) = (count(Kind::Event) + count(Kind::BigEvent), count(Kind::Reply));
            assert!(
                events <= 2 * WATCH_EVENT_MAX,
                "domain {d} has {events} watch events (or E2BIG in their place) queued"
            );
            assert!(
                replies <= OUTSTANDING_MAX,
                "domain {d} has {replies} replies queued (quota {OUTSTANDING_MAX})"
            );
            let bytes = self.core.output(id).len();
            let max = SOFT_LIMIT + (HEADER_LEN + PAYLOAD_MAX) * (1 + 2 * WATCH_EVENT_MAX);
            assert!(
                bytes <= max,
                "domain {d} has {bytes} bytes of output queued (bound {max})"
            );
        }
    }

    // -----------------------------------------------------------------
    // Actions.

    fn act(&mut self, a: Action) {
        match a {
            Action::Req { slot, req, now } => {
                let Some(i) = self.live(slot) else { return };
                let ty = match req.ty {
                    Ty::Known(k) => MsgType::ALL[k as usize % MsgType::ALL.len()] as u32,
                    Ty::Raw(t) => t,
                };
                let tx = self.tx(i, req.tx);
                let mut payload = Vec::new();
                for (k, f) in req.fields.iter().enumerate() {
                    if k > 0 {
                        payload.push(0);
                    }
                    field(f, &mut payload);
                }
                if req.nul {
                    payload.push(0);
                }
                self.request(i, ty, tx, payload, req.req_id);
                if now {
                    self.process(i, 1);
                }
            }
            Action::Raw { slot, bytes } => {
                if let Some(i) = self.live(slot) {
                    self.feed(i, &bytes);
                }
            }
            Action::Process { slot, n } => {
                if let Some(i) = self.live(slot) {
                    self.process(i, n as usize % 8 + 1);
                }
            }
            Action::Drain { slot, n } => {
                if let Some(i) = self.live(slot) {
                    self.consume(i, n as usize);
                    self.after(None);
                }
            }
            Action::DrainAll => self.drain_all(),
            Action::Introduce {
                from,
                dom,
                gfn,
                port,
                tx,
            } => {
                let Some(i) = self.live(from) else { return };
                let d = [1u32, 2, 3, 9, 0, 0x7fef][dom as usize % 6];
                let gfn = if gfn % 4 == 0 { 100 + d as u64 } else { gfn as u64 };
                let port = if port % 4 == 0 { 10 + d } else { port as u32 };
                let tx = self.tx(i, tx);
                self.request(
                    i,
                    MsgType::Introduce as u32,
                    tx,
                    format!("{d}\0{gfn}\0{port}\0").into_bytes(),
                    None,
                );
                self.process(i, 1);
            }
            Action::Release { from, dom, tx } => {
                let Some(i) = self.live(from) else { return };
                let d = [1u32, 2, 3, 9, 0][dom as usize % 5];
                let tx = self.tx(i, tx);
                self.request(i, MsgType::Release as u32, tx, format!("{d}\0").into_bytes(), None);
                self.process(i, 1);
            }
            Action::SetTarget { from, dom, target } => {
                let Some(i) = self.live(from) else { return };
                let d = [1u32, 2, 3, 9, 0][dom as usize % 5];
                let t = [1u32, 2, 3, 9, 0][target as usize % 5];
                self.request(
                    i,
                    MsgType::SetTarget as u32,
                    0,
                    format!("{d}\0{t}\0").into_bytes(),
                    None,
                );
                self.process(i, 1);
            }
            Action::DomExc { dom, fate } => {
                let d = [1u32, 2, 3, 9][dom as usize % 4];
                let st = match fate {
                    Fate::Running => DomainState::Running,
                    Fate::Shutdown => DomainState::Shutdown,
                    Fate::Dead => DomainState::Dead,
                };
                self.core
                    .domains_changed(&mut |x| if x == d { st } else { DomainState::Running }, &mut self.xen);
                self.after(None);
            }
            Action::Reconnect { slot } => {
                let Some(i) = self.live(slot).filter(|i| self.slots[*i].ring) else {
                    return;
                };
                self.core.reconnect(self.slots[i].id.unwrap());
                let s = &mut self.slots[i];
                if !s.dead {
                    s.mirror = Decoder::new();
                }
                s.reset_output();
                s.watches.clear();
                s.txns.clear();
                self.after(None);
            }
            Action::Ignore { slot } => {
                let Some(i) = self.live(slot).filter(|i| self.slots[*i].ring) else {
                    return;
                };
                self.ignore(i);
                self.after(None);
            }
            Action::Reopen { slot } => {
                let i = slot as usize % 2;
                if let Some(id) = self.slots[i].id {
                    self.core.close(id);
                }
                self.slots[i] = Slot::new(Some(self.core.open()), 0, false);
                self.after(None);
            }
            Action::Tick { ms } => {
                self.now += Duration::from_millis(ms as u64);
                self.core.tick(self.now);
                self.after(None);
            }
            Action::FireSpecial { release } => {
                let p: &[u8] = if release {
                    b"@releaseDomain"
                } else {
                    b"@introduceDomain"
                };
                self.core.fire_special(p);
                self.after(None);
            }
            Action::Op { slot, op, tx } => {
                let Some(i) = self.live(slot) else { return };
                let mut p = Vec::new();
                let (ty, tx) = match &op {
                    Op::Read(a) | Op::Directory(a) | Op::GetPerms(a) | Op::Mkdir(a) | Op::Rm(a) => {
                        path(a, &mut p);
                        p.push(0);
                        let ty = match op {
                            Op::Read(_) => MsgType::Read,
                            Op::Directory(_) => MsgType::Directory,
                            Op::GetPerms(_) => MsgType::GetPerms,
                            Op::Mkdir(_) => MsgType::Mkdir,
                            _ => MsgType::Rm,
                        };
                        (ty, tx)
                    }
                    Op::Write(a, v) => {
                        path(a, &mut p);
                        p.push(0);
                        field(
                            &Field::Value(match v {
                                Val::Short(x) => Val::Short(*x),
                                Val::Len(n) => Val::Len(*n),
                                Val::Raw(r) => Val::Raw(r.clone()),
                            }),
                            &mut p,
                        );
                        (MsgType::Write, tx)
                    }
                    Op::SetPerms(a, perms) => {
                        path(a, &mut p);
                        p.push(0);
                        // Owner first; an empty list is the owner of domain 0.
                        let perms = if perms.is_empty() { &[(0, 0)][..] } else { &perms[..] };
                        for (letter, dom) in perms.iter().take(6) {
                            p.push(b"nrwb"[*letter as usize % 4]);
                            p.extend_from_slice(pick(&[b"0", b"1", b"2", b"3", b"9"], *dom));
                            p.push(0);
                        }
                        (MsgType::SetPerms, tx)
                    }
                    Op::Watch(a, t) | Op::Unwatch(a, t) => {
                        path(a, &mut p);
                        p.push(0);
                        p.extend_from_slice(format!("t{}", t % 4).as_bytes());
                        p.push(0);
                        (
                            if matches!(op, Op::Watch(..)) {
                                MsgType::Watch
                            } else {
                                MsgType::Unwatch
                            },
                            Tx::None,
                        )
                    }
                    Op::Start => {
                        p.push(0);
                        (MsgType::TransactionStart, Tx::None)
                    }
                    Op::End(commit) => {
                        p.extend_from_slice(if *commit { b"T\0" } else { b"F\0" });
                        (
                            MsgType::TransactionEnd,
                            if matches!(tx, Tx::None) { Tx::Open(0) } else { tx },
                        )
                    }
                    Op::Reset => (MsgType::ResetWatches, Tx::None),
                };
                let tx = self.tx(i, tx);
                self.request(i, ty as u32, tx, p, None);
                self.process(i, 1);
            }
            Action::Watches { slot, path: a, n } => {
                let Some(i) = self.live(slot) else { return };
                let mut p = Vec::new();
                path(&a, &mut p);
                for k in 0..n % 6 + 1 {
                    let payload = [&p[..], b"\0", format!("b{k}").as_bytes(), b"\0"].concat();
                    self.request(i, MsgType::Watch as u32, 0, payload, None);
                    self.process(i, 1);
                }
            }
            Action::Starts { slot, n } => {
                let Some(i) = self.live(slot) else { return };
                for _ in 0..n % 4 + 1 {
                    self.request(i, MsgType::TransactionStart as u32, 0, b"\0".to_vec(), None);
                    self.process(i, 1);
                }
            }
            Action::FailMachine { connect, rebind } => {
                self.xen.fail_connect = connect;
                self.xen.fail_rebind = rebind;
            }
        }
    }
}

/// FUZZ_TRACE set: the actions and requests are printed (to follow a
/// failing input: `FUZZ_TRACE=1 core_requests FILE`).
fn trace() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE.get_or_init(|| std::env::var_os("FUZZ_TRACE").is_some())
}

/// The owner in encoded permissions (`n0\0...`), if it is a number.
fn owner(perms: &[u8]) -> Option<u32> {
    let first = perms.split(|c| *c == 0).next()?;
    std::str::from_utf8(first.get(1..)?).ok()?.parse().ok()
}

/// Replays the records of an input that starts with `RXS1` (seeds made by
/// fuzz/gen_seeds.py from a recorded VM start and hand-written sequences),
/// up to a slot byte of 0xff; returns the rest. A record: slot (bit 7: do
/// not read the output after it), type, transaction (0: none; k: the
/// connection's open transaction k-1, in order of their ids), payload length
/// (u16, little endian), payload.
fn replay<'a>(h: &mut H, data: &'a [u8]) -> &'a [u8] {
    let Some(rest) = data.strip_prefix(b"RXS1") else {
        return data;
    };
    h.fast = true;
    let rest = replay_records(h, rest);
    h.fast = false;
    h.before = Rc::new(flatten(&h.core));
    h.fingerprint = fingerprint(h.core.root());
    h.after(None);
    rest
}

fn replay_records<'a>(h: &mut H, mut rest: &'a [u8]) -> &'a [u8] {
    while let [slot, ty, tx, l0, l1, more @ ..] = rest {
        if *slot == 0xff {
            return &rest[1..];
        }
        let len = u16::from_le_bytes([*l0, *l1]) as usize;
        let Some(payload) = more.get(..len) else { return &[] };
        rest = &more[len..];
        let Some(i) = h.live(*slot & 0x7f) else { continue };
        let tx = match *tx {
            0 => Tx::None,
            k => Tx::Open(k - 1),
        };
        let tx = h.tx(i, tx);
        h.request(i, *ty as u32, tx, payload.to_vec(), None);
        h.process(i, 1);
        if *slot & 0x80 == 0 {
            h.drain_all();
        }
    }
    &[]
}

const P_SETUP: usize = 0;
const P_REPLAY: usize = 1;
const P_ACTIONS: usize = 2;
const P_AUDIT: usize = 3;
const P_FLATTEN: usize = 4;
const P_PARSE: usize = 5;
const P_REPLIES: usize = 6;
const P_EVENTS: usize = 7;
const P_STORE: usize = 8;
const P_READS: usize = 9;
const P_HOLDINGS: usize = 10;
const P_END: usize = 11;
const P_NAMES: [&str; 12] = [
    "setup", "replay", "actions", "audit", "flatten", "parse", "replies", "events", "store", "reads", "holdings", "end",
];

thread_local! {
    static PROF: std::cell::RefCell<[Duration; 12]> = const { std::cell::RefCell::new([Duration::ZERO; 12]) };
}

/// FUZZ_PROFILE set: the time of each part of the harness is summed, and
/// printed per input (`prof` and microseconds in `P_NAMES` order; the
/// checks' times are inside `actions`, `replay` and `setup`).
fn profiling() -> bool {
    static P: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *P.get_or_init(|| std::env::var_os("FUZZ_PROFILE").is_some())
}

fn timed<T>(k: usize, f: impl FnOnce() -> T) -> T {
    if !profiling() {
        return f();
    }
    let t = std::time::Instant::now();
    let r = f();
    let d = t.elapsed();
    PROF.with(|p| p.borrow_mut()[k] += d);
    r
}

fuzz_target!(|data: &[u8]| {
    if profiling() {
        PROF.with(|p| *p.borrow_mut() = [Duration::ZERO; 12]);
    }
    run(data);
    if profiling() {
        PROF.with(|p| {
            let p = p.borrow();
            let us: Vec<String> = p.iter().map(|d| d.as_micros().to_string()).collect();
            eprintln!("prof {} {}", data.len(), us.join(" "));
        });
    }
});

fn run(data: &[u8]) {
    let mut h = timed(P_SETUP, H::new);
    let data = timed(P_REPLAY, || replay(&mut h, data));
    let mut u = Unstructured::new(data);
    let mut steps = 0;
    while !u.is_empty() && steps < 500 {
        let Ok(a) = Action::arbitrary(&mut u) else { break };
        if trace() {
            eprintln!("action {a:?}");
        }
        timed(P_ACTIONS, || h.act(a));
        steps += 1;
    }
    // The end: everything buffered is handled, and everything read.
    timed(P_END, || {
        for i in 0..NSLOTS {
            h.process(i, 64);
        }
        h.drain_all();
        h.audit_now();
    });
}
