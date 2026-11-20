// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The xenstore core: store, transactions, watches and connection state
//! machines. No I/O: the caller feeds the bytes a connection sent, asks the
//! core to process them, and writes out what the core queued for each
//! connection. Everything is deterministic.
//!
//! Costs, with d the depth of a path: a store operation is O(d) (and O(d ·
//! log₁₆ siblings) node copies when it writes); a watch dispatch is O(d +
//! matching watches); TRANSACTION_START is O(1); a commit is proportional
//! to the operations of the transaction. Nothing walks all connections,
//! all watches, all transactions or all nodes.
//!
//! `no_std`: `core` and `alloc` only (but in its own test build), so that
//! it can run where there is no operating system, in a stub domain
//! (`scripts/nostd.sh` checks it). The `std` feature, off by default, builds
//! it against std: `scripts/mutants.sh` turns it on so that the code
//! cargo-mutants writes (`::std::iter::empty()`, `Box::new(..)`) builds.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::get_unwrap,
        clippy::unwrap_in_result,
        clippy::panic_in_result_fn,
        clippy::exit,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unchecked_time_subtraction
    )
)]

// `vec!` and `format!` in every module, as std's prelude gives them.
#[macro_use]
extern crate alloc;

/// The names std's prelude has and `core`'s does not, for this `no_std` crate.
mod prelude {
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
}

pub mod bytes;
mod conflict;
pub mod idtable;
pub mod log;
pub mod path;
pub mod perms;
pub mod pmap;
pub mod quota;
pub mod sip;
pub mod store;
mod txlog;
pub mod watch;

use crate::prelude::*;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use bytes::Bytes;
use conflict::{Conflicts, Started};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use path::Name;
use perms::{int_of_string, ocaml_int, parse_domid, Access, Caller, Perms};
use quota::{Acct, Delta, Entries};
use store::{execute, execute_in, lookup, Change, ChangeKind, Ctx, Gen, Node, Op, Outcome};
use watch::{Key, WatchId, WatchIndex};
use xs_wire::{write_header, Decoder, Errno, Message, MsgType, HEADER_LEN, PAYLOAD_MAX};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What the core asks of the machine it runs on. The daemon implements it
/// over the Xen devices; tests use a recording fake.
pub trait Machine {
    /// INTRODUCE of a domain the core does not know: map the ring page at
    /// guest frame `gfn` and bind an event channel to `remote_port`.
    /// `conn` is the id the domain's connection will have if this succeeds.
    /// An error fails the request with that error and creates nothing;
    /// oxenstored answers EINVAL whatever failed (`ox/process.ml:602-607`).
    fn connect(&mut self, conn: ConnId, domid: u32, gfn: u64, remote_port: u32) -> Result<(), Errno>;
    /// INTRODUCE of a known domain: bind its event channel again, to this
    /// port. An error fails the request with that error; oxenstored's is
    /// EIO, the bind failure escaping its error mapping (`ox/process.ml:597-600, 737-740`).
    fn rebind(&mut self, conn: ConnId, domid: u32, remote_port: u32) -> Result<(), Errno>;
    /// The domain's connection is gone (RELEASE, or the domain died): unbind and unmap.
    fn disconnect(&mut self, conn: ConnId, domid: u32);
}

/// What Xen says of a domain (the daemon gets it from the hypervisor).
/// `xs_sys::backend::DomainState` is its twin on purpose: the core does no
/// I/O and depends on no system crate, so the daemon maps one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Running,
    /// Shut down, not dying yet.
    Shutdown,
    /// Dying, or gone.
    Dead,
}

/// The machine of `process`: nothing can be mapped or bound.
struct NoMachine;

impl Machine for NoMachine {
    fn connect(&mut self, _: ConnId, _: u32, _: u64, _: u32) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }

    fn rebind(&mut self, _: ConnId, _: u32, _: u32) -> Result<(), Errno> {
        Err(Errno::EIO)
    }

    fn disconnect(&mut self, _: ConnId, _: u32) {}
}

/// `DOMID_SELF`, which IS_DOMAIN_INTRODUCED says is (`ox/define.ml:40`).
const DOMID_SELF: i64 = 0x7FF0;

/// `DOMID_FIRST_RESERVED` (`xen.h`): this and above name no domain.
const DOMID_FIRST_RESERVED: u32 = 0x7FF0;

/// Which behaviour to follow where oxenstored 4.17 and C xenstored differ
/// (`Rules`, decided once from the profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `--compat=oxenstored`, and `Config::default()`: oxenstored 4.17's
    /// behaviour.
    Oxenstored,
    /// rxenstored's own command line and configuration file.
    Native,
}

/// What a profile changes in how requests are handled: every point where
/// the profiles differ reads one of these, and only `Profile::rules`
/// sets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    /// The error of every quota on counts and bytes (nodes, watches,
    /// transactions, requests and bytes of a transaction, ACL entries):
    /// oxenstored's EQUOTA (`ox/process.ml:437-439`), or ENOSPC, C
    /// xenstored's (`cx417/xenstored_core.c:1494-1496`). A value too long
    /// is E2BIG in both.
    pub quota_error: Errno,
    /// A quota of N on watches and on open transactions allows N; without
    /// it, N + 1, as oxenstored (`ox/connection.ml:277-280, 382-385`).
    pub exact_counts: bool,
    /// CONTROL from a domain other than 0 is EACCES, as in C xenstored
    /// (`cx417/xenstored_core.c:2035-2037`); without it, OK and nothing
    /// done (`ox/process.ml:221-223`).
    pub control_is_privileged: bool,
    /// A node created by a domain other than 0 that does not act for
    /// domain 0 is owned by that domain (its own domid, also when it acts
    /// for another through SET_TARGET), and counts in its quota: its
    /// parent's permissions with the creator as owner
    /// (`cx417/xenstored_core.c:1416-1424`, `conn->id`). Without it, a node
    /// gets its parent's permissions, owner included, and counts for that
    /// owner (`ox/store.ml:415-436`).
    pub creator_owns: bool,
    /// A WRITE or MKDIR that fails creates nothing (`cx417/xenstored_core.c:1515-1521`);
    /// without it, the missing parents made before the failure stay
    /// (`ox/process.ml:74-87, 301-308`).
    pub all_or_nothing: bool,
    /// A missing node is ENOENT only to a caller that may access its
    /// nearest existing ancestor as the request asks (read, or write for
    /// RM and SET_PERMS), and EACCES to others (`cx417/xenstored_core.c:936-950`);
    /// without it, ENOENT to everybody (`ox/store.ml:178-181`).
    pub hide_missing: bool,
    /// RM of the root is EINVAL to a caller that may write it
    /// (`cx417/xenstored_core.c:1725-1726`); without it, it removes the
    /// root's children (`ox/store.ml:302-305`).
    pub root_stays: bool,
}

impl Profile {
    /// The rules of the profile.
    pub const fn rules(self) -> Rules {
        match self {
            Profile::Oxenstored => Rules {
                quota_error: Errno::EQUOTA,
                exact_counts: false,
                control_is_privileged: false,
                creator_owns: false,
                all_or_nothing: false,
                hide_missing: false,
                root_stays: false,
            },
            Profile::Native => Rules {
                quota_error: Errno::ENOSPC,
                exact_counts: true,
                control_is_privileged: true,
                creator_owns: true,
                all_or_nothing: true,
                hide_missing: true,
                root_stays: true,
            },
        }
    }
}

impl Rules {
    /// Is a count of `n` at a quota of `max`, so that one more is refused?
    pub fn full(&self, n: usize, max: usize) -> bool {
        if self.exact_counts {
            n >= max
        } else {
            n > max
        }
    }
}

/// The configuration. The quotas are oxenstored's (defaults: those of its
/// code, `ox/define.ml:24-31`, `ox/quota.ml:22-23`); "held" connections
/// are those of domains other than 0 that do not act for domain 0
/// (`Perms.Connection.is_dom0`): sockets are domain 0. A quota refuses
/// with the profile's error (`Rules::quota_error`): EQUOTA below, ENOSPC
/// in the native profile.
#[derive(Debug, Clone)]
pub struct Config {
    /// The behaviour profile, set by the daemon's front end (`Rules`).
    pub profile: Profile,
    /// `quota-path-max`: longest path, or relative part of a
    /// `/local/domain/<n>/...` path.
    pub path_max: usize,
    /// `quota-maxsize`: longest node value, for everybody
    /// (`ox/quota.ml:51-55`). E2BIG.
    pub value_max: usize,
    /// A connection with this many bytes of unsent output gets no request
    /// processed until it has read some.
    pub output_soft_limit: usize,
    /// A connection whose unsent output would exceed this is closed: it is
    /// not reading its watch events.
    pub output_hard_limit: usize,
    /// Value of `/tool/xenstored` (oxenstored writes its executable path).
    pub tool_xenstored: Vec<u8>,
    /// `perms-activate`: check node permissions.
    pub perms_activate: bool,
    /// `perms-watch-activate`: a watch fires only for a watcher that may
    /// read the node or its parent.
    pub perms_watch_activate: bool,
    /// `quota-activate`: without it, values have no size limit and
    /// neither `entity_max`, `watch_max` nor `acl_max` apply; the other
    /// quotas do (`ox/quota.ml:58-60`, `ox/connection.ml:278`).
    pub quota_activate: bool,
    /// `quota-maxentity`: a held connection may create a node only while
    /// its owner (other than domain 0) owns fewer (`ox/store.ml:415-436`).
    /// The owner is the parent's, or the creator with
    /// `Rules::creator_owns`. EQUOTA.
    pub entity_max: usize,
    /// `quota-maxwatch` (None if not positive): a held connection may
    /// register a watch while it has at most this many, so one more than
    /// this in all (`ox/connection.ml:277-280`); this many with
    /// `Rules::exact_counts`. EQUOTA.
    pub watch_max: Option<usize>,
    /// `quota-transaction` (None if not positive): a held connection may
    /// start a transaction while it has at most this many open, so one
    /// more than this in all (`ox/connection.ml:382-385`); this many with
    /// `Rules::exact_counts`. EQUOTA.
    pub transaction_max: Option<usize>,
    /// `quota-maxrequests` (None if negative): requests of a held
    /// connection in one transaction; the next one, whatever it is, and
    /// every one after it, TRANSACTION_END included, is refused. With 0 a
    /// held connection gets nothing done, transaction or not
    /// (`ox/transaction.ml:150-157`, `ox/process.ml:416, 708-716`). EQUOTA.
    pub request_max: Option<usize>,
    /// `quota-maxoutstanding`: a connection with this many replies unsent
    /// gets no request processed until it has read some (`xb/xb.ml:246-248`).
    pub outstanding_max: usize,
    /// `quota-maxwatchevents`: unsent watch events a connection may have.
    /// A held connection whose request gives a watcher more is held until
    /// the watcher has read below it, as oxenstored holds the source of
    /// events it cannot queue (`ox/connection.ml:329-339, 409`). Domain 0
    /// and sockets are never held: their events for a held watcher that
    /// has twice this many unsent are dropped.
    pub watch_event_max: usize,
    /// Entries a held connection may give a node's ACL (not in
    /// oxenstored, which takes what fits in a payload: about 1400). Keeps
    /// what an ACL costs within what a value may. EQUOTA.
    pub acl_max: usize,
    /// Bytes the open transactions of a held connection may keep, all
    /// together (`Txn::bytes`: their requests and replies, packed; not the
    /// versions of the store they share with it), with `quota-activate`.
    /// None: no limit. Not in oxenstored: there a guest's transactions
    /// keep what `quota-maxrequests` and `quota-transaction` let them
    /// (the requests and replies of 11 x 1,024 requests). The daemon's
    /// default is what one transaction of `quota-maxrequests` requests of
    /// the longest path and value needs (`transaction_bytes_for`), far
    /// above what guests do. A request in a transaction while the
    /// connection keeps that much is refused, before it runs. EQUOTA.
    pub transaction_bytes_max: Option<usize>,
    /// `conflict-burst-limit`: the conflicts a domain other than 0 may
    /// cause before it is paused (XSA-206, `conflict.rs`). Infinite: never.
    pub conflict_burst_limit: f64,
    /// `conflict-max-history-seconds`: how long a transaction is
    /// protected, and how often a point of credit is given back.
    pub conflict_max_history: Duration,
    /// `conflict-rate-limit-is-aggregate`: a point per period for one
    /// domain, not one each.
    pub conflict_rate_limit_is_aggregate: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            profile: Profile::Oxenstored,
            path_max: path::PATH_MAX,
            value_max: store::VALUE_MAX,
            output_soft_limit: 1 << 20,
            output_hard_limit: 64 << 20,
            tool_xenstored: b"rxenstored".to_vec(),
            perms_activate: true,
            perms_watch_activate: true,
            quota_activate: true,
            entity_max: 1000,
            watch_max: Some(100),
            transaction_max: Some(10),
            request_max: Some(1024),
            outstanding_max: 1024,
            watch_event_max: 1024,
            acl_max: 256,
            transaction_bytes_max: Some(Config::transaction_bytes_for(1024, path::PATH_MAX, store::VALUE_MAX)),
            conflict_burst_limit: 5.0,
            conflict_max_history: Duration::from_millis(50),
            conflict_rate_limit_is_aggregate: true,
        }
    }
}

impl Config {
    /// The default of `transaction_bytes_max` for these quotas: what one
    /// transaction of `requests` requests, each with a path of `path_max`
    /// and a value of `value_max` bytes, takes as a client sends it.
    pub const fn transaction_bytes_for(requests: usize, path_max: usize, value_max: usize) -> usize {
        requests.saturating_mul(path_max.saturating_add(value_max))
    }

    /// May the connection have a request processed? oxenstored reads one
    /// only if there is room for its reply and the connection has no
    /// events it could not queue (`xb/xb.ml:246-248`, `ox/connection.ml:409`),
    /// and not from a domain without conflict credit (`ox/xenstored.ml:55-67`).
    fn can_input(&self, c: &Conn) -> bool {
        c.out.len() < self.output_soft_limit && c.out.replies < self.outstanding_max && c.holds == 0 && c.credit > 0.0
    }
}

/// What `process` stopped on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No complete request is buffered.
    Idle,
    /// The budget ran out; requests may remain.
    More,
    /// The connection may not have requests processed now: its output is
    /// above the soft limit, or it has `outstanding_max` replies unsent,
    /// or it is held until a watcher it flooded reads, or its domain has
    /// no conflict credit left. It may go on once it has read (`consume`);
    /// a held one, once `take_dirty` reports it.
    Blocked,
    /// The connection is closed, or must be (see `take_dead`).
    Closed,
}

/// A streak of watch events dropped for a held watcher (see
/// `Config::watch_event_max`), as `take_drops` reports it: once when it
/// starts, once with the count when it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drops {
    /// The first event dropped for this watcher since it last read enough.
    Started(log::Who),
    /// The streak ended (the watcher read enough, or is gone) after this
    /// many events were dropped.
    Ended(log::Who, u64),
}

/// Why the core gave up on a connection (`take_dead`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaveUp {
    /// It broke the protocol: a header announcing more than a payload.
    Protocol,
    /// Its unsent output would have gone past the hard limit.
    Overflow,
}

/// Bytes queued for a connection, sent from the front, and the messages
/// not started yet: what oxenstored has in its queue of packets
/// (`xb/xb.ml:227-244`), by class.
#[derive(Debug, Default)]
struct OutBuf {
    buf: Vec<u8>,
    pos: usize,
    /// Bytes sent since the buffer was created.
    sent: u64,
    /// Where each message not started yet begins, in bytes since the
    /// buffer was created, and what it is.
    msgs: VecDeque<(u64, Class)>,
    replies: usize,
    events: usize,
    /// Of `events`, those a request of a connection that may be held
    /// caused, by that connection: each is held for its own events only.
    from: BTreeMap<ConnId, usize>,
}

/// What a queued message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Reply,
    /// A watch event of domain 0, of a socket or of the daemon.
    Event,
    /// A watch event a request of this connection, which may be held,
    /// caused.
    EventFrom(ConnId),
}

impl OutBuf {
    /// The bytes not sent yet. `pos` is at most `buf.len()`: `consume`
    /// moves it by at most what is left.
    fn pending(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.pending().len()
    }

    /// Unsent events a request of `source` caused.
    fn from(&self, source: ConnId) -> usize {
        self.from.get(&source).copied().unwrap_or(0)
    }

    /// A message is about to be appended.
    fn begin(&mut self, class: Class) {
        self.msgs.push_back((self.sent + self.len() as u64, class));
        match class {
            Class::Reply => self.replies += 1,
            Class::Event => self.events += 1,
            Class::EventFrom(s) => {
                self.events += 1;
                *self.from.entry(s).or_insert(0) += 1;
            }
        }
    }

    fn consume(&mut self, n: usize) {
        let n = n.min(self.len());
        self.sent += n as u64;
        // A message whose first byte went is no longer queued.
        while let Some(&(_, class)) = self.msgs.front().filter(|m| m.0 < self.sent) {
            self.msgs.pop_front();
            match class {
                Class::Reply => self.replies = self.replies.saturating_sub(1),
                Class::Event => self.events = self.events.saturating_sub(1),
                Class::EventFrom(s) => {
                    self.events = self.events.saturating_sub(1);
                    let left = self.from.remove(&s).unwrap_or(0).saturating_sub(1);
                    if left > 0 {
                        self.from.insert(s, left);
                    }
                }
            }
        }
        self.pos += n;
        match self.buf.get(self.pos..) {
            Some([]) => {
                self.buf.clear();
                self.pos = 0;
                if self.buf.capacity() > 1 << 20 {
                    self.buf.shrink_to(64 << 10);
                }
            }
            // `get` succeeded, so `pos <= buf.len()`: the drain is in bounds.
            Some(_) if self.pos > 64 << 10 && self.pos * 2 > self.buf.len() => {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            _ => {}
        }
    }
}

struct Txn {
    /// The store when the transaction started.
    snapshot: Arc<Node>,
    /// The transaction's own version, where its requests run.
    tree: Arc<Node>,
    /// Every store request with its reply and the change it made, re-run
    /// at commit if anything was committed since the snapshot. It keeps
    /// no version of the store: only `snapshot` and `tree` are versions.
    log: Vec<txlog::Entry>,
    /// The listings its requests saw, kept once each.
    listings: txlog::Listings,
    /// What `tree` changed in the node counts.
    delta: Delta,
    /// What its log keeps, for `transaction_bytes_max` (`Entry::cost`).
    bytes: usize,
    /// Requests made in it, for `request_max`.
    requests: usize,
    /// Its place in the conflict history.
    started: Started,
}

struct Conn {
    decoder: Decoder,
    out: OutBuf,
    in_dirty: bool,
    dead: bool,
    /// Watchers this connection gave too many events: it gets no request
    /// processed until they have read some.
    holds: usize,
    /// Connections held until this one has read some events.
    waiters: Vec<ConnId>,
    /// The request during which a waiter was last added (requests are
    /// numbered by `Conns::epoch`): one request has one source.
    waited: u64,
    /// Watch events dropped for it since it last read enough (`Drops`).
    dropping: u64,
    watches: usize,
    /// A shared ring, not a socket: a reply or event longer than a payload
    /// is replaced by E2BIG (`ox/connection.ml:242-246`).
    ring: bool,
    /// Its domain (0 for a socket) and SET_TARGET domain.
    caller: Caller,
    /// `/local/domain/<domid>/`: base of relative paths.
    home: Arc<[u8]>,
    txns: BTreeMap<u32, Txn>,
    next_tid: u32,
    /// The token of its last watch: a client that registers many watches
    /// with one token (xenopsd: one per domain) stores it once.
    last_token: Bytes,
    /// Conflict credit (`ox/domain.ml:47-49`): no request is processed
    /// at 0 or less.
    credit: f64,
}

/// The ring of a domain other than 0: its changes are recorded for blame
/// (`ox/history.ml:46-50`, `is_free_to_conflict`).
fn blamable(ring: bool, caller: Caller) -> bool {
    ring && caller.domid != 0
}

impl Conn {
    fn blamable(&self) -> bool {
        blamable(self.ring, self.caller)
    }

    fn peer(&self) -> Peer {
        Peer {
            caller: self.caller,
            ring: self.ring,
            home: self.home.clone(),
        }
    }
}

/// The requests on the store, which `store::execute` runs.
#[derive(Debug, Clone, Copy)]
enum StoreKind {
    Read,
    Directory,
    GetPerms,
    Write,
    Mkdir,
    Rm,
    SetPerms,
}

/// Who a request is from, as its connection was when it was taken from
/// the input: what handling it reads of the connection, so that it need
/// not look the connection up again.
struct Peer {
    caller: Caller,
    ring: bool,
    home: Arc<[u8]>,
}

/// The connections and what they have to send.
struct Conns {
    map: BTreeMap<ConnId, Conn>,
    dirty: Vec<ConnId>,
    dead: Vec<(ConnId, GaveUp)>,
    hard_limit: usize,
    event_max: usize,
    /// The number of the request being handled.
    epoch: u64,
    /// Watch events not queued: the watcher had too many.
    dropped: u64,
    /// Their streaks, for `take_drops`.
    drops: Vec<Drops>,
    log: log::Log,
}

impl Conns {
    fn send(&mut self, id: ConnId, ty: u32, req_id: u32, tx_id: u32, parts: &[&[u8]]) {
        self.queue(id, Class::Reply, ty, req_id, tx_id, parts);
    }

    /// Queues a message of class `class` (a reply, or an event, as
    /// `event` sends them). A connection of domain 0 is never given up on
    /// for its unsent output, as oxenstored never gives up on one: what
    /// it is owed is bounded by its own soft limit for replies and, for
    /// events guests cause, by holding each guest at `event_max` unsent
    /// events of its own; domain 0's own events are its own doing.
    fn queue(&mut self, id: ConnId, class: Class, ty: u32, req_id: u32, tx_id: u32, parts: &[&[u8]]) {
        // A connection the core gave up on gets nothing more.
        let Some(c) = self.map.get_mut(&id).filter(|c| !c.dead) else {
            return;
        };
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if c.ring && len > PAYLOAD_MAX {
            // The E2BIG error takes the message's place and its class: in
            // place of an event, it is counted, held for and dropped as
            // the event would be. oxenstored makes it in place of the
            // event (`ox/connection.ml:242-246, 329-333`) and passes it
            // through the source's and the watch's queues of events, which
            // hold the source (`ox/connection.ml:169, 409`).
            let e2big = Errno::E2BIG.name().as_bytes();
            return self.queue(id, class, MsgType::Error as u32, req_id, tx_id, &[e2big, b"\0"]);
        }
        if !c.caller.is_dom0() && c.out.len() + HEADER_LEN + len > self.hard_limit {
            c.dead = true;
            self.dead.push((id, GaveUp::Overflow));
            return;
        }
        c.out.begin(class);
        write_header(&mut c.out.buf, ty, req_id, tx_id, len as u32);
        for p in parts {
            c.out.buf.extend_from_slice(p);
        }
        self.mark_dirty(id);
        self.log_reply(id, ty, tx_id, parts);
    }

    fn mark_dirty(&mut self, id: ConnId) {
        if let Some(c) = self.map.get_mut(&id).filter(|c| !c.in_dirty) {
            c.in_dirty = true;
            self.dirty.push(id);
        }
    }

    fn error(&mut self, id: ConnId, req_id: u32, tx_id: u32, e: Errno) {
        self.send(id, MsgType::Error as u32, req_id, tx_id, &[e.name().as_bytes(), b"\0"]);
    }

    /// A watch event for `id`, caused by a request of `source` (None: by
    /// the daemon itself). The watcher gets it; a source that may be held
    /// and has `event_max` events of its own unsent there waits for the
    /// watcher to read them, as oxenstored holds a source whose events
    /// its watch's queue cannot take (`ox/connection.ml:329-339, 409`). So
    /// one guest's events never hold another guest. A watcher other than
    /// domain 0 with twice `event_max` events unsent gets nothing more.
    fn event(&mut self, id: ConnId, source: Option<ConnId>, path: &[u8], token: &[u8]) {
        // A source that released its own domain is gone.
        let source = source.filter(|s| self.map.get(s).is_some_and(|c| !c.caller.is_dom0()));
        let Some(c) = self.map.get_mut(&id).filter(|c| !c.dead) else {
            return;
        };
        if !c.caller.is_dom0() && c.out.events >= self.event_max.saturating_mul(2) {
            self.dropped += 1;
            if c.dropping == 0 {
                self.drops.push(Drops::Started(log::Who::of(id, c)));
            }
            c.dropping += 1;
            return;
        }
        if let Some(s) = source.filter(|s| c.out.from(*s) >= self.event_max) {
            self.hold(s, id);
        }
        let class = source.map_or(Class::Event, Class::EventFrom);
        let ty = MsgType::WatchEvent as u32;
        self.queue(id, class, ty, 0, 0, &[path, b"\0", token, b"\0"]);
    }

    /// `source` waits until `watcher` reads, once per request.
    /// Both are open: `event` found them.
    fn hold(&mut self, source: ConnId, watcher: ConnId) {
        let epoch = self.epoch;
        if let Some(w) = self.map.get_mut(&watcher).filter(|w| w.waited != epoch) {
            w.waited = epoch;
            w.waiters.push(source);
            self.map.entry(source).and_modify(|s| s.holds += 1);
        }
    }

    /// Lets go of those held by `id` if it has read enough, and ends its
    /// streak of dropped events if it can take one again.
    fn release(&mut self, id: ConnId) {
        let event_max = self.event_max;
        if let Some(c) = self
            .map
            .get_mut(&id)
            .filter(|c| c.dropping > 0 && c.out.events < event_max.saturating_mul(2))
        {
            self.drops
                .push(Drops::Ended(log::Who::of(id, c), core::mem::take(&mut c.dropping)));
        }
        // Those whose own events it has read below the limit go on.
        let free = self.map.get_mut(&id).map(|c| {
            let (out, mut free) = (&c.out, Vec::new());
            c.waiters.retain(|s| {
                let held = out.from(*s) >= event_max;
                if !held {
                    free.push(*s);
                }
                held
            });
            free
        });
        self.unhold(free.unwrap_or_default());
    }

    /// Each of `waiters` waits for one watcher less; those free are
    /// reported by `take_dirty`, so that they get a turn.
    fn unhold(&mut self, waiters: Vec<ConnId>) {
        for s in waiters {
            // Gone, if not there.
            if let Some(c) = self.map.get_mut(&s) {
                c.holds = c.holds.saturating_sub(1);
                if c.holds == 0 {
                    self.mark_dirty(s);
                }
            }
        }
    }
}

pub struct Core {
    cfg: Config,
    /// The rules of `cfg.profile`.
    rules: Rules,
    root: Arc<Node>,
    /// The node counts of `root`.
    entries: Entries,
    gen: Gen,
    index: WatchIndex,
    conns: Conns,
    next_conn: u64,
    /// The domains that have a connection.
    domains: BTreeMap<u32, Domain>,
    scratch: Vec<WatchId>,
    conflicts: Conflicts,
}

/// A domain the core knows (`ox/domain.ml`).
struct Domain {
    conn: ConnId,
    /// The ring page and the remote event channel port INTRODUCE gave.
    gfn: u64,
    port: u32,
}

/// The version of the store a request runs against, its transaction's or
/// the store, with its node counts. The transaction exists: `handle`
/// checked it (`count_request`), and None would be the request's EIO.
fn version<'a>(
    root: &'a mut Arc<Node>,
    entries: &'a mut Entries,
    conns: &'a mut Conns,
    id: ConnId,
    tid: u32,
) -> Option<(&'a mut Arc<Node>, Acct<'a>)> {
    if tid == 0 {
        Some((root, Acct::Store(entries)))
    } else {
        conns
            .map
            .get_mut(&id)
            .and_then(|c| c.txns.get_mut(&tid))
            .map(|t| (&mut t.tree, Acct::Txn(entries, &mut t.delta)))
    }
}

/// C's `atoi`, assigned to an unsigned offset (`cx/core.c:1288`): white
/// space, a sign, digits; a negative number is a huge offset.
fn c_offset(s: &[u8]) -> usize {
    let mut s = s;
    while let [b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r', rest @ ..] = s {
        s = rest;
    }
    let (neg, s) = match s {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, s),
    };
    let v = s
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0i32, |v, c| v.wrapping_mul(10).wrapping_add((c - b'0') as i32));
    (if neg { v.wrapping_neg() } else { v }) as u32 as usize
}

/// A DIRECTORY_PART reply (`cx/core.c:1273-1320`): the generation of the
/// set of children, then the names that fit in a payload from byte `off`
/// of the list, then an empty name if the list ends there.
/// The list is not built: a part costs a walk of the names before it,
/// and a payload.
fn part_reply(cgen: u64, children: &pmap::PMap<Name, Node>, off: usize) -> Vec<u8> {
    let mut out = format!("{cgen}\0").into_bytes();
    let max = PAYLOAD_MAX - out.len() - 1;
    let mut names = children.keys();
    // The rest of the name that byte `off` of the list is in (maybe
    // only its NUL).
    let mut at = 0;
    let mut piece = loop {
        let Some(name) = names.next() else {
            out.push(0);
            return out;
        };
        // `at <= off`: `at` passed only names that end before `off`.
        if let Some(rest) = name.get(off - at..) {
            break rest;
        }
        at += name.len() + 1;
    };
    let mut len = 0;
    while len + piece.len() < max {
        out.extend_from_slice(piece);
        out.push(0);
        len += piece.len() + 1;
        match names.next() {
            Some(name) => piece = name,
            None => {
                out.push(0);
                break;
            }
        }
    }
    out
}

/// Permissions that decide whether a watch on `path` fires for `change`:
/// those of the node and of its parent, in each version the change looks
/// at (`ox/connection.ml:317-324`). None for the root.
fn watch_perms<'a>(roots: impl Iterator<Item = &'a Node>, path: &[Name]) -> Vec<&'a Perms> {
    let mut out = Vec::new();
    let Some((name, parent)) = path.split_last() else {
        return out;
    };
    for p in roots.filter_map(|root| lookup(root, parent)) {
        out.push(&*p.perms);
        out.extend(p.child(name).map(|c| &*c.perms));
    }
    out
}

/// Pushes the children of the trie node `tn` on the stack of an RM's walk
/// (`Core::dispatch`), the first by name on top, each with its name and
/// `store_node`, the store node of `tn` in the version the RM looks at.
fn push_children<'a>(
    index: &'a WatchIndex,
    stack: &mut Vec<(&'a Name, u32, Option<&'a Node>)>,
    tn: u32,
    store_node: Option<&'a Node>,
) {
    // Below what the store had, no watch on the way down a chain of
    // single children fires or is looked at: go to its end (same
    // watches, same order).
    let tn = if store_node.is_none() { index.down(tn) } else { tn };
    let first = stack.len();
    stack.extend(index.children(tn).map(|(name, c)| (name, c, store_node)));
    // Listed by name: the first goes last.
    stack.get_mut(first..).unwrap_or_default().reverse();
}

/// `Perms.can_fire_watch`: some of those permissions let the watcher
/// read, or watches are not checked (`ox/perms.ml:179-181`).
fn can_fire(cfg: &Config, conn: &Conn, perms: &[&Perms]) -> bool {
    !cfg.perms_watch_activate
        || perms
            .iter()
            .any(|p| !p.lacks(cfg.perms_activate, &conn.caller, Access::Read))
}

/// The path of a watch as its client gave it: a relative one was
/// registered below the connection's home.
fn own_path(index: &WatchIndex, wid: WatchId, conn: &Conn) -> Vec<u8> {
    let p = index.path(wid);
    match p.strip_prefix(&*conn.home) {
        Some(rest) if index.get(wid).relative => rest.to_vec(),
        _ => p,
    }
}

/// The DIRECTORY reply, or as much of it as goes past `limit`: a ring
/// gets E2BIG for a listing longer than a payload, however long.
fn names(children: &pmap::PMap<Name, Node>, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for k in children.keys() {
        if out.len() > limit {
            break;
        }
        out.extend_from_slice(k);
        out.push(0);
    }
    out
}

impl Core {
    /// A core with the store of a daemon that starts. `hash_key` keys the
    /// hash tables whose keys clients choose (watch paths and tokens): give
    /// it random bits, drawn anew at each start, or a client that knows it
    /// can make every lookup in those tables walk all their entries.
    pub fn new(cfg: Config, hash_key: [u64; 2]) -> Core {
        let mut gen = Gen::default();
        let mut entries = Entries::default();
        let root = store::initial(&mut gen, &cfg.tool_xenstored, &mut Acct::Store(&mut entries));
        let conns = Conns {
            map: BTreeMap::new(),
            dirty: Vec::new(),
            dead: Vec::new(),
            hard_limit: cfg.output_hard_limit,
            event_max: cfg.watch_event_max,
            epoch: 0,
            dropped: 0,
            drops: Vec::new(),
            log: log::Log::default(),
        };
        let conflicts = Conflicts::new(&cfg);
        Core {
            rules: cfg.profile.rules(),
            cfg,
            root,
            entries,
            gen,
            index: WatchIndex::new(sip::SipKey::new(hash_key)),
            conns,
            next_conn: 1,
            domains: BTreeMap::new(),
            scratch: Vec::new(),
            conflicts,
        }
    }

    /// A new connection over the unix socket: it acts as domain 0.
    pub fn open(&mut self) -> ConnId {
        self.new_conn(0, false)
    }

    /// The ring connection of a domain that is not introduced (domain 0's
    /// own). A domain has one: a second one takes its place, and the first
    /// is closed (`close`), its watches and transactions with it. Its ring
    /// is at frame 0, as oxenstored records domain 0's (`ox/domains.ml:162-172`).
    pub fn open_domain(&mut self, domid: u32) -> ConnId {
        if let Some(old) = self.domain_conn(domid) {
            self.close(old);
        }
        let conn = self.new_conn(domid, true);
        self.domains.insert(domid, Domain { conn, gfn: 0, port: 0 });
        conn
    }

    fn new_conn(&mut self, domid: u32, ring: bool) -> ConnId {
        let id = ConnId(self.next_conn);
        self.next_conn += 1;
        let conn = Conn {
            decoder: Decoder::new(),
            out: OutBuf::default(),
            in_dirty: false,
            dead: false,
            holds: 0,
            waiters: Vec::new(),
            waited: 0,
            dropping: 0,
            watches: 0,
            ring,
            caller: Caller { domid, target: None },
            home: Arc::from(format!("/local/domain/{domid}/").into_bytes()),
            txns: BTreeMap::new(),
            next_tid: 1,
            last_token: Bytes::EMPTY,
            credit: 0.0,
        };
        let conn = Conn {
            credit: self.conflicts.initial(conn.blamable()),
            ..conn
        };
        self.conns.log_conn(id, &conn, log::Op::NewConn);
        self.conns.map.insert(id, conn);
        id
    }

    /// The connection is gone: its watches and transactions go with it,
    /// and the core forgets the domain it was the connection of. Costs
    /// O(its watches · depth). For a socket: a ring the caller gives up
    /// on is to be ignored (`ignore`), as its domain must stay known.
    pub fn close(&mut self, id: ConnId) {
        if let Some(c) = self.conns.map.remove(&id) {
            self.conns.log_conn(id, &c, log::Op::EndConn);
            if c.dropping > 0 {
                self.conns.drops.push(Drops::Ended(log::Who::of(id, &c), c.dropping));
            }
            self.index.remove_all(id);
            uncount(&mut self.conflicts.open, c.txns.len(), "open transactions");
            self.conflicts.forget(id, c.credit);
            // Its events are gone: those it held may go on.
            self.conns.unhold(c.waiters);
            if self.domain_conn(c.caller.domid) == Some(id) {
                self.domains.remove(&c.caller.domid);
            }
        }
    }

    /// The connection of a domain, if it has one.
    pub fn domain_conn(&self, domid: u32) -> Option<ConnId> {
        self.domains.get(&domid).map(|d| d.conn)
    }

    /// The domains that have a connection (any order).
    pub fn domains(&self) -> impl Iterator<Item = (u32, ConnId)> + '_ {
        self.domains.iter().map(|(domid, d)| (*domid, d.conn))
    }

    /// The guest asked for a ring reconnection (`xenstore-ring.txt`): its
    /// partial input, unsent output, watches and transactions go; the
    /// connection, its domain and its SET_TARGET stay, and transaction ids
    /// start again from 1 (`ox/connection.ml:150-158`). oxenstored 4.17
    /// leaves the watches in its global index, where they keep firing
    /// (`4.17 ox/connection.ml:150-160`, fixed on master by a2ca4f8b98):
    /// not reproduced, the protocol says they go. A connection held for
    /// a watcher it flooded stays held: oxenstored keeps the events it
    /// could not queue (`ox/connection.ml:150-158`).
    pub fn reconnect(&mut self, id: ConnId) {
        let Some(c) = self.conns.map.get_mut(&id) else { return };
        c.decoder = Decoder::new();
        c.out = OutBuf::default();
        uncount(&mut self.conflicts.open, c.txns.len(), "open transactions");
        c.txns.clear();
        c.next_tid = 1;
        self.drop_watches(id);
        self.conns.release(id);
        // `ox/history.ml:42-44`
        self.conflicts.trim();
    }

    /// Forgets a domain and closes its connection; false if it had none.
    /// Those that acted for it no longer do: a new domain with its domid
    /// is not theirs. (oxenstored 4.17 keeps the relation,
    /// `ox/connections.ml:179-181`, `ox/connection.ml:239-240`.) Costs
    /// O(domains), as the walk of the store that comes with it does more.
    fn drop_domain(&mut self, domid: u32, machine: &mut dyn Machine) -> bool {
        let Some(d) = self.domains.remove(&domid) else {
            return false;
        };
        self.close(d.conn);
        machine.disconnect(d.conn, domid);
        for other in self.domains.values() {
            self.conns.map.entry(other.conn).and_modify(|c| {
                if c.caller.target == Some(domid) {
                    c.caller.target = None;
                }
            });
        }
        true
    }

    /// VIRQ_DOM_EXC fired: `state` gives Xen's view of a domain. It is
    /// asked, in domid order, for every domain that has a connection but
    /// domain 0. The dead lose their connection, their nodes and their ACL
    /// entries; then `@releaseDomain` fires once if a domain died or is
    /// shut down: it fires again at every VIRQ while one stays shut down
    /// (`ox/domains.ml:120-148`, `ox/xenstored.ml:488-497`).
    pub fn domains_changed(&mut self, state: &mut dyn FnMut(u32) -> DomainState, machine: &mut dyn Machine) {
        // A BTreeMap: in domid order.
        let ids: Vec<u32> = self.domains.keys().copied().filter(|d| *d != 0).collect();
        let mut shutdown = false;
        let mut dead = Vec::new();
        for domid in ids {
            match state(domid) {
                DomainState::Running => {}
                DomainState::Shutdown => shutdown = true,
                DomainState::Dead => dead.push(domid),
            }
        }
        store::forget_domains(
            &mut self.root,
            &mut self.gen,
            &dead,
            &mut Acct::Store(&mut self.entries),
        );
        for &domid in &dead {
            self.drop_domain(domid, machine);
        }
        if shutdown || !dead.is_empty() {
            self.fire_special(b"@releaseDomain");
        }
    }

    /// Bytes received on a connection; processed by `process`.
    pub fn feed(&mut self, id: ConnId, bytes: &[u8]) {
        if let Some(c) = self.conns.map.get_mut(&id).filter(|c| !c.dead) {
            c.decoder.push(bytes);
        }
    }

    /// Handles up to `budget` buffered requests of a connection, for a
    /// caller without domains: INTRODUCE fails as when oxenstored cannot
    /// map a ring (EINVAL) or bind an event channel again (EIO).
    pub fn process(&mut self, id: ConnId, budget: usize) -> Status {
        self.process_on(id, budget, &mut NoMachine)
    }

    /// As `process`, with the machine the domain requests act on.
    pub fn process_on(&mut self, id: ConnId, budget: usize, machine: &mut dyn Machine) -> Status {
        for _ in 0..budget {
            let Some(c) = self.conns.map.get_mut(&id) else {
                return Status::Closed;
            };
            if c.dead {
                return Status::Closed;
            }
            if !self.cfg.can_input(c) {
                return Status::Blocked;
            }
            match c.decoder.next_message() {
                Ok(Some(msg)) => {
                    let peer = c.peer();
                    self.handle(id, &peer, msg, machine)
                }
                Ok(None) => return Status::Idle,
                Err(_) => {
                    // Framing is lost (oversized length, or a decoder out
                    // of step): drop the client.
                    c.dead = true;
                    self.conns.dead.push((id, GaveUp::Protocol));
                    return Status::Closed;
                }
            }
        }
        Status::More
    }

    /// False while the connection may not have requests processed (see
    /// `Status::Blocked`), or is gone.
    pub fn wants_input(&self, id: ConnId) -> bool {
        self.conns
            .map
            .get(&id)
            .is_some_and(|c| !c.dead && self.cfg.can_input(c))
    }

    /// Unsent output of a connection.
    pub fn output(&self, id: ConnId) -> &[u8] {
        match self.conns.map.get(&id) {
            Some(c) => c.out.pending(),
            None => &[],
        }
    }

    /// The first `n` bytes of `output(id)` were sent. Connections held
    /// until it read some events may go on: `take_dirty` reports them.
    pub fn consume(&mut self, id: ConnId, n: usize) {
        if let Some(c) = self.conns.map.get_mut(&id) {
            c.out.consume(n);
            self.conns.release(id);
        }
    }

    /// Connections that got output since the last call, and those that
    /// may have requests processed again after being held.
    pub fn take_dirty(&mut self, out: &mut Vec<ConnId>) {
        for id in self.conns.dirty.drain(..) {
            if let Some(c) = self.conns.map.get_mut(&id) {
                c.in_dirty = false;
                out.push(id);
            }
        }
    }

    /// Connections the core gave up on, and why: they get nothing more
    /// and have nothing processed. The caller closes a socket (`close`)
    /// and ignores a ring (`ignore`).
    pub fn take_dead(&mut self, out: &mut Vec<(ConnId, GaveUp)>) {
        out.append(&mut self.conns.dead);
    }

    /// The streaks of dropped watch events that started or ended since
    /// the last call, in order: for the daemon's log, which says so once
    /// per streak, never per event.
    pub fn take_drops(&mut self, out: &mut Vec<Drops>) {
        out.append(&mut self.conns.drops);
    }

    /// The caller gives up on a connection without closing it, as on a
    /// ring that will not be served any more (`take_dead`, or corrupt
    /// indices): its partial input, unsent output, watches and
    /// transactions go, it gets nothing more and what it sends is
    /// discarded; its domain stays known, with its nodes and permissions,
    /// until RELEASE or death close it (XSA-325: `cx/domain.c:1081-1104`,
    /// `ox/connection.ml:143-146`).
    pub fn ignore(&mut self, id: ConnId) {
        let Some(c) = self.conns.map.get_mut(&id) else { return };
        c.dead = true;
        c.decoder = Decoder::new();
        c.out = OutBuf::default();
        uncount(&mut self.conflicts.open, c.txns.len(), "open transactions");
        c.txns.clear();
        if c.dropping > 0 {
            self.conns
                .drops
                .push(Drops::Ended(log::Who::of(id, c), core::mem::take(&mut c.dropping)));
        }
        // Its events are gone: those it held may go on.
        let waiters = core::mem::take(&mut c.waiters);
        self.conns.unhold(waiters);
        self.drop_watches(id);
    }

    pub fn connections(&self) -> usize {
        self.conns.map.len()
    }

    pub fn watches(&self) -> usize {
        self.index.len()
    }

    /// The bytes the open transactions of a connection keep, as
    /// `Config::transaction_bytes_max` counts them.
    pub fn transaction_bytes(&self, id: ConnId) -> usize {
        self.conns
            .map
            .get(&id)
            .map_or(0, |c| c.txns.values().map(|t| t.bytes).sum())
    }

    pub fn transactions(&self, id: ConnId) -> usize {
        self.conns.map.get(&id).map_or(0, |c| c.txns.len())
    }

    /// The current store.
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Handles one request of an open connection.
    fn handle(&mut self, id: ConnId, peer: &Peer, msg: Message, machine: &mut dyn Machine) {
        self.conns.epoch += 1;
        self.conns.log_request(id, &msg);
        let mt = msg.msg_type();
        // WATCH and UNWATCH ignore the transaction (`ox/process.ml:686-691`).
        let tid = if matches!(mt, Some(MsgType::Watch | MsgType::Unwatch)) {
            0
        } else {
            msg.tx_id
        };
        if let Err(e) = self.count_request(id, peer, tid) {
            return self.conns.error(id, msg.req_id, tid, e);
        }
        let r = match mt {
            Some(MsgType::Read) => self.store_request(id, peer, &msg, tid, StoreKind::Read),
            Some(MsgType::Directory) => self.store_request(id, peer, &msg, tid, StoreKind::Directory),
            Some(MsgType::GetPerms) => self.store_request(id, peer, &msg, tid, StoreKind::GetPerms),
            Some(MsgType::Write) => self.store_request(id, peer, &msg, tid, StoreKind::Write),
            Some(MsgType::Mkdir) => self.store_request(id, peer, &msg, tid, StoreKind::Mkdir),
            Some(MsgType::Rm) => self.store_request(id, peer, &msg, tid, StoreKind::Rm),
            Some(MsgType::SetPerms) => self.store_request(id, peer, &msg, tid, StoreKind::SetPerms),
            Some(MsgType::Watch) => self.watch(id, peer, &msg),
            Some(MsgType::Unwatch) => self.unwatch(id, peer, &msg),
            Some(MsgType::TransactionStart) => self.transaction_start(id, peer, &msg, tid),
            Some(MsgType::TransactionEnd) => self.transaction_end(id, peer, &msg, tid),
            Some(MsgType::GetDomainPath) => match path::split(&msg.payload, 8)[..] {
                [domid, b""] => {
                    let reply = format!("/local/domain/{}\0", path::c_int(domid));
                    self.conns.send(id, msg.ty, msg.req_id, tid, &[reply.as_bytes()]);
                    Ok(())
                }
                _ => Err(Errno::EINVAL),
            },
            Some(MsgType::ResetWatches) => {
                self.reset(id);
                self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
                Ok(())
            }
            Some(MsgType::SetTarget) => self.set_target(id, peer, &msg, tid),
            Some(MsgType::Introduce) => self.introduce(id, peer, &msg, tid, machine),
            Some(MsgType::Release) => self.release(id, peer, &msg, tid, machine),
            Some(MsgType::IsDomainIntroduced) => Self::dom0_only(peer).and_then(|()| {
                // `ox/process.ml:338-346`
                let domid = Self::first_number(&msg)?;
                let known = domid == DOMID_SELF || self.known(domid);
                self.conns
                    .send(id, msg.ty, msg.req_id, tid, &[if known { b"T\0" } else { b"F\0" }]);
                Ok(())
            }),
            Some(MsgType::Resume) => Self::dom0_only(peer).and_then(|()| {
                // Nothing to do for a known domain (`ox/process.ml:628-638`, `ox/domains.ml:150-151`).
                if !self.known(Self::first_number(&msg)?) {
                    return Err(Errno::EINVAL);
                }
                self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
                Ok(())
            }),
            Some(MsgType::Control) => {
                self.control(id, peer, &msg, tid);
                Ok(())
            }
            Some(MsgType::DirectoryPart) => self.directory_part(id, peer, &msg, tid),
            // Unknown, server-to-client only, or not in oxenstored either
            // (RESTRICT, GET/SET_FEATURE, GET/SET_QUOTA).
            _ => Err(Errno::ENOSYS),
        };
        if let Err(e) = r {
            self.conns.error(id, msg.req_id, tid, e);
        }
    }

    /// A request in transaction `tid` (0: none): its transaction must
    /// exist, and have room for it (`request_max`), which is checked
    /// before anything else and counted only if it passes
    /// (`ox/process.ml:412-417, 688-716`).
    fn count_request(&mut self, id: ConnId, peer: &Peer, tid: u32) -> Result<(), Errno> {
        let held = !peer.caller.is_dom0();
        let full = |n: usize| held && self.cfg.request_max.is_some_and(|max| n >= max);
        let quota = self.rules.quota_error;
        if tid == 0 {
            return if full(0) { Err(quota) } else { Ok(()) };
        }
        // oxenstored fails the lookup outside its error mapping (`ox/process.ml:713-720, 739`).
        let t = self
            .conns
            .map
            .get_mut(&id)
            .and_then(|c| c.txns.get_mut(&tid))
            .ok_or(Errno::EIO)?;
        if full(t.requests) {
            return Err(quota);
        }
        t.requests += 1;
        Ok(())
    }

    fn ctx(&self, caller: Caller) -> Ctx {
        let active = self.cfg.quota_activate;
        Ctx {
            caller,
            rules: self.rules,
            perms_active: self.cfg.perms_activate,
            value_max: if active { self.cfg.value_max } else { usize::MAX },
            entity_max: (active && !caller.is_dom0()).then_some(self.cfg.entity_max),
        }
    }

    /// The domain requests are for domain 0, or a domain acting for it.
    fn dom0_only(peer: &Peer) -> Result<(), Errno> {
        if peer.caller.is_dom0() {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    /// The domid that starts a payload, as `int_of_string` reads it.
    fn first_number(msg: &Message) -> Result<i64, Errno> {
        // `split` gives at least one piece.
        let first = path::split(&msg.payload, 2).first().copied().unwrap_or_default();
        ocaml_int(first, 63).ok_or(Errno::EINVAL)
    }

    fn known(&self, domid: i64) -> bool {
        u32::try_from(domid).is_ok_and(|d| self.domains.contains_key(&d))
    }

    /// SET_TARGET: the connection of a domain also acts as another domain
    /// (a stub domain as its guest). For domain 0 only; ENOENT if the
    /// domain has no connection (`ox/process.ml:347-352`,
    /// `ox/connections.ml:179-181`). Both numbers are OCaml ints: one that
    /// is no domid names no domain, so the first is ENOENT and the second
    /// a target the connection acts for in nothing (oxenstored keeps the
    /// number, which no owner matches).
    fn set_target(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32) -> Result<(), Errno> {
        Self::dom0_only(peer)?;
        let (domid, target) = match msg.payload.split(|c| *c == 0).collect::<Vec<_>>()[..] {
            [domid, target, b""] => (
                u32::try_from(path::c_int(domid)),
                u32::try_from(path::c_int(target)).ok(),
            ),
            _ => return Err(Errno::EINVAL),
        };
        let conn = domid
            .ok()
            .and_then(|d| self.domain_conn(d))
            .and_then(|c| self.conns.map.get_mut(&c))
            .ok_or(Errno::ENOENT)?;
        conn.caller.target = target;
        self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
        Ok(())
    }

    /// INTRODUCE `<domid>|<gfn>|<port>|` (`ox/process.ml:585-610`).
    fn introduce(
        &mut self,
        id: ConnId,
        peer: &Peer,
        msg: &Message,
        tid: u32,
        machine: &mut dyn Machine,
    ) -> Result<(), Errno> {
        Self::dom0_only(peer)?;
        let [domid, gfn, port, ..] = path::split(&msg.payload, 8)[..] else {
            return Err(Errno::EINVAL);
        };
        // OCaml evaluates the tuple right to left: the port is read first;
        // a bad frame number fails with `Nativeint.of_string`'s message,
        // which escapes the error mapping (`ox/process.ml:588-593, 737-740`).
        let port = ocaml_int(port, 63).ok_or(Errno::EINVAL)?;
        let gfn = ocaml_int(gfn, 64).ok_or(Errno::EIO)? as u64;
        // No domain has a domid that is not one, and no event channel a
        // port that is not one: they fail as the mapping and the binding
        // would.
        let domid = u32::try_from(ocaml_int(domid, 63).ok_or(Errno::EINVAL)?).map_err(|_| Errno::EINVAL)?;
        // A reserved domid is no domain: nothing to map (`cx/domain.c:805-814`).
        if domid >= DOMID_FIRST_RESERVED {
            return Err(Errno::EINVAL);
        }
        let port = u32::try_from(port).ok();
        match self.domains.get_mut(&domid) {
            Some(d) => {
                // Known: the event channel is bound again if the ring is
                // the same and the domain does not introduce itself. Then
                // the ring and port must be those asked for.
                if d.gfn == gfn && d.conn != id {
                    let p = port.ok_or(Errno::EIO)?;
                    machine.rebind(d.conn, domid, p)?;
                    d.port = p;
                }
                if d.gfn != gfn || Some(d.port) != port {
                    return Err(Errno::EINVAL);
                }
            }
            None => {
                let port = port.ok_or(Errno::EINVAL)?;
                // The version of the store the request runs against, which
                // connecting the domain does not change.
                let Some(root) =
                    version(&mut self.root, &mut self.entries, &mut self.conns, id, tid).map(|(v, _)| v.clone())
                else {
                    return Err(Errno::EIO);
                };
                let conn = ConnId(self.next_conn);
                machine.connect(conn, domid, gfn, port)?;
                self.new_conn(domid, true);
                self.domains.insert(domid, Domain { conn, gfn, port });
                // Fired before the reply is queued, checked against that version.
                self.fire_special_at(&root, b"@introduceDomain", Some(id));
            }
        }
        self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
        Ok(())
    }

    /// RELEASE `<domid>|` (`4.17 ox/process.ml:585-599`): the domain and its
    /// connection go, and its nodes and ACL entries (in the version of the
    /// store the request runs against), whether it was known or not. Only
    /// then is an unknown domain an error; a known one fires
    /// `@releaseDomain`, before the reply.
    fn release(
        &mut self,
        id: ConnId,
        peer: &Peer,
        msg: &Message,
        tid: u32,
        machine: &mut dyn Machine,
    ) -> Result<(), Errno> {
        Self::dom0_only(peer)?;
        let domid = match path::split(&msg.payload, 8)[..] {
            [domid, b""] => ocaml_int(domid, 63).ok_or(Errno::EINVAL)?,
            _ => return Err(Errno::EINVAL),
        };
        // A domid that is not one owns nothing and names no one.
        let domid = u32::try_from(domid).ok();
        // Domain 0 owns most of the store, and it and the reserved domids
        // are not released: refused before anything is touched, as C
        // xenstored does (`cx/domain.c:1244-1260`). oxenstored would
        // remove every node domain 0 owns (`ox/process.ml:585-599`).
        if domid.is_some_and(|d| d == 0 || d >= DOMID_FIRST_RESERVED) {
            return Err(Errno::EINVAL);
        }
        // The store first, while the transaction (of a domain releasing
        // itself) still exists: nothing in between looks at it.
        let Some((store, mut acct)) = version(&mut self.root, &mut self.entries, &mut self.conns, id, tid) else {
            return Err(Errno::EIO);
        };
        store::forget_domains(store, &mut self.gen, domid.as_slice(), &mut acct);
        let root = store.clone();
        if !domid.is_some_and(|d| self.drop_domain(d, machine)) {
            return Err(Errno::EINVAL);
        }
        self.fire_special_at(&root, b"@releaseDomain", Some(id));
        self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
        Ok(())
    }

    /// CONTROL (DEBUG) `<cmd>|[<params>|]` (`4.17 ox/process.ml:221-257`):
    /// for domain 0 only, but others get OK; and so do commands that are
    /// unknown, malformed or that only log (`print`). Never an error in
    /// oxenstored; here ENOSYS for what needs what the core does not have:
    /// `live-update` (the daemon's) and `xenbus` (ring state). Master adds
    /// `compact`, `trim` and others: OK in 4.17. With
    /// `Rules::control_is_privileged`, others get EACCES.
    fn control(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32) {
        let reply = if let Err(e) = Self::dom0_only(peer) {
            if self.rules.control_is_privileged {
                return self.conns.error(id, msg.req_id, tid, e);
            }
            None
        } else {
            match path::split(&msg.payload, 8)[..] {
                [b"watches", ..] => Some(self.watch_list()),
                [b"print", text, ..] => self.conns.log_print(id, text),
                [b"mfn", domid, ..] => parse_domid(domid)
                    .and_then(|d| self.domains.get(&d))
                    .map(|d| format!("{}\0", d.gfn as i64).into_bytes()),
                [b"live-update", _, ..] => return self.conns.error(id, msg.req_id, tid, Errno::ENOSYS),
                [b"quota", d, ..] => int_of_string(d).map(|d| self.quota_line(id, tid, d)),
                [b"xenbus", d, ..] if ocaml_int(d, 63).is_some_and(|d| self.known(d)) => {
                    return self.conns.error(id, msg.req_id, tid, Errno::ENOSYS)
                }
                _ => None,
            }
        };
        let reply = reply.as_deref().unwrap_or(b"OK\0");
        self.conns.send(id, msg.ty, msg.req_id, tid, &[reply]);
    }

    /// CONTROL `quota <domid>`: the nodes a domain owns in the version of
    /// the store the request runs against (`ox/process.ml:231-234`,
    /// `ox/quota.ml:39-44`): in a transaction, its own version (the store
    /// when it started, with its changes), counted node by node, as no
    /// count of that version is kept. The root's lost owner is -1, as
    /// there (`store::NO_OWNER`); no other negative number owns anything.
    fn quota_line(&self, id: ConnId, tid: u32, domid: i64) -> Vec<u8> {
        let n = match self.conns.map.get(&id).and_then(|c| c.txns.get(&tid)) {
            Some(t) => Entries::recount(&t.tree).get(domid),
            None => self.entries.get(domid),
        };
        match n {
            0 => format!("dom{domid} quota: not set\0"),
            n => format!("dom{domid} quota: {n}/{}\0", self.cfg.entity_max),
        }
        .into_bytes()
    }

    /// CONTROL `watches`: `watch <who>: <path> <token>` lines, domains
    /// first, then sockets, then a NUL (`ox/connections.ml:209-212`,
    /// `ox/connection.ml:476-479`). A debugging command: it walks every
    /// connection.
    fn watch_list(&self) -> Vec<u8> {
        let mut conns: Vec<_> = self.conns.map.iter().collect();
        conns.sort_by_key(|(id, c)| (!c.ring, **id));
        let mut out = Vec::new();
        for (id, c) in conns {
            let who = if c.ring {
                format!("D{}", c.caller.domid)
            } else {
                format!("A{}", id.0)
            };
            for wid in self.index.of(*id) {
                out.extend_from_slice(format!("watch {who}: ").as_bytes());
                out.extend_from_slice(&own_path(&self.index, wid, c));
                out.push(b' ');
                out.extend_from_slice(&self.index.get(wid).token);
                out.push(b'\n');
            }
        }
        out.push(0);
        out
    }

    /// DIRECTORY_PART `<path>|<offset>|`, which oxenstored 4.17 lacks
    /// (ENOSYS) and libxenstore uses when a directory is too long for a
    /// ring (`cx/core.c:1273-1320`). Checked and recorded in a transaction
    /// as a DIRECTORY.
    fn directory_part(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32) -> Result<(), Errno> {
        // Two strings: two NULs (`xs_count_strings`), so three pieces.
        let nuls = msg.payload.iter().filter(|c| **c == 0).count();
        let ([path, offset, _], 2) = (&path::split(&msg.payload, 3)[..], nuls) else {
            return Err(Errno::EINVAL);
        };
        let p = path::parse(path, &peer.home, self.cfg.path_max)?;
        self.run_op(id, peer, msg, tid, Op::Directory(p), Some(c_offset(offset)));
        Ok(())
    }

    fn parse_op(&self, peer: &Peer, msg: &Message, kind: StoreKind) -> Result<Op, Errno> {
        let p = |raw: &[u8]| path::parse(raw, &peer.home, self.cfg.path_max);
        let one = || match path::split(&msg.payload, 2)[..] {
            [path, b""] => p(path),
            _ => Err(Errno::EINVAL),
        };
        Ok(match kind {
            StoreKind::Read => Op::Read(one()?),
            StoreKind::Directory => Op::Directory(one()?),
            StoreKind::GetPerms => Op::GetPerms(one()?),
            StoreKind::Mkdir => Op::Mkdir(one()?),
            StoreKind::Rm => Op::Rm(one()?),
            StoreKind::Write => match path::split(&msg.payload, 2)[..] {
                [path, value] => Op::Write(p(path)?, value.into()),
                _ => return Err(Errno::EINVAL),
            },
            StoreKind::SetPerms => match path::split(&msg.payload, 2)[..] {
                [path, perms] => {
                    let (path, perms) = (p(path)?, Perms::parse(perms)?);
                    if perms.acl.len() > self.cfg.acl_max && self.cfg.quota_activate && !peer.caller.is_dom0() {
                        return Err(self.rules.quota_error);
                    }
                    Op::SetPerms(path, Arc::new(perms))
                }
                _ => return Err(Errno::EINVAL),
            },
        })
    }

    /// `part`: the offset of a DIRECTORY_PART.
    fn reply_outcome(
        &mut self,
        id: ConnId,
        ring: bool,
        msg: &Message,
        tid: u32,
        outcome: &Outcome,
        part: Option<usize>,
    ) {
        let (ty, req) = (msg.ty, msg.req_id);
        match outcome {
            Outcome::Done => self.conns.send(id, ty, req, tid, &[b"OK\0"]),
            Outcome::Value { value, .. } => self.conns.send(id, ty, req, tid, &[value]),
            Outcome::Perms { perms, .. } => self.conns.send(id, ty, req, tid, &[&perms.encode()]),
            Outcome::Children { cgen, children } => {
                let reply = match part {
                    None => names(children, if ring { PAYLOAD_MAX } else { usize::MAX }),
                    Some(off) => part_reply(*cgen, children, off),
                };
                self.conns.send(id, ty, req, tid, &[&reply])
            }
            Outcome::Failed(e) => self.conns.error(id, req, tid, *e),
        }
    }

    fn store_request(
        &mut self,
        id: ConnId,
        peer: &Peer,
        msg: &Message,
        tid: u32,
        kind: StoreKind,
    ) -> Result<(), Errno> {
        let op = self.parse_op(peer, msg, kind)?;
        self.run_op(id, peer, msg, tid, op, None);
        Ok(())
    }

    fn run_op(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32, op: Op, part: Option<usize>) {
        let ctx = self.ctx(peer.caller);
        if tid == 0 {
            let mut changes = Vec::new();
            // Every store request counts (`ox/process.ml:634-657`): one that changed nothing is not recorded.
            let before = self.wants_record(peer).then(|| self.root.clone());
            let outcome = execute(
                &mut self.root,
                &mut self.gen,
                &op,
                &ctx,
                &mut Acct::Store(&mut self.entries),
                &mut changes,
            );
            if let Some(before) = before {
                self.conflicts.record(id, before, &self.root);
            }
            // The reply goes first, then the events (`ox/process.ml:362-368`).
            self.reply_outcome(id, peer.ring, msg, tid, &outcome, part);
            for c in &changes {
                self.dispatch(c, id);
            }
        } else {
            // A connection whose transactions keep their quota of bytes
            // gets no more in any of them (dom0 and sockets are not held).
            let held = !peer.caller.is_dom0() && self.cfg.quota_activate;
            if held
                && self
                    .cfg
                    .transaction_bytes_max
                    .is_some_and(|max| self.transaction_bytes(id) >= max)
            {
                return self.conns.error(id, msg.req_id, tid, self.rules.quota_error);
            }
            // The transaction exists: `handle` checked it (`count_request`).
            let Some(txn) = self.conns.map.get_mut(&id).and_then(|c| c.txns.get_mut(&tid)) else {
                return self.conns.error(id, msg.req_id, tid, Errno::EIO);
            };
            let (outcome, fired) = execute_in(
                &mut txn.tree,
                &mut self.gen,
                &op,
                &ctx,
                &mut Acct::Txn(&self.entries, &mut txn.delta),
            );
            let entry = txlog::Entry::new(op, &outcome, fired, &mut txn.listings);
            txn.bytes += entry.cost();
            txn.log.push(entry);
            self.reply_outcome(id, peer.ring, msg, tid, &outcome, part);
        }
    }

    /// Fires the watches a change made by a request of `source` concerns
    /// (`ox/connections.ml:152-167`).
    fn dispatch(&mut self, change: &Change, source: ConnId) {
        let perms = watch_perms(change.roots(), &change.path);
        self.scratch.clear();
        self.index.on_path(&change.path, &mut self.scratch);
        if !self.scratch.is_empty() {
            let full = path::to_string(&change.path);
            for &wid in &self.scratch {
                let w = self.index.get(wid);
                let Some(conn) = self.conns.map.get(&w.conn).filter(|c| {
                    self.conns
                        .fires(can_fire(&self.cfg, c, &perms), w.conn, c, &perms, || &full)
                }) else {
                    continue;
                };
                // A relative watch gets a relative path (`ox/connection.ml:351-362`).
                let p = match full.strip_prefix(&*conn.home) {
                    Some(rest) if w.relative => rest,
                    _ => &full[..],
                };
                self.conns.event(w.conn, Some(source), p, &w.token);
            }
        }
        if change.kind == ChangeKind::Rm {
            // Watches below a removed node fire with their own path, if
            // their parent existed (`ox/connections.ml:165-166`): in the
            // order of a walk of the watch trie below the node, a node
            // before what is below it, children by name
            // (`ox/trie.ml:73-78`, a map ordered by name).
            let Some(top) = self.index.node(&change.path) else {
                return;
            };
            // An RM keeps the old version (`store::run`); without it, the
            // node would be taken as missing, and nothing below it fire.
            let top_node = change.before.as_deref().and_then(|before| lookup(before, &change.path));
            // Trie nodes to visit, the next on top, each with its name and
            // the store node of its parent.
            let mut stack = Vec::new();
            push_children(&self.index, &mut stack, top, top_node);
            while let Some((name, tn, parent)) = stack.pop() {
                let store_node = parent.and_then(|n| n.child(name));
                let perms: Vec<&Perms> = parent.into_iter().chain(store_node).map(|n| &*n.perms).collect();
                for wid in self.index.watches_at(tn) {
                    let w = self.index.get(wid);
                    if let Some(c) = self.conns.map.get(&w.conn).filter(|c| {
                        self.conns.fires(can_fire(&self.cfg, c, &perms), w.conn, c, &perms, || {
                            self.index.path(wid)
                        })
                    }) {
                        let p = own_path(&self.index, wid, c);
                        self.conns.event(w.conn, Some(source), &p, &w.token);
                    }
                }
                push_children(&self.index, &mut stack, tn, store_node);
            }
        }
    }

    /// Fires the watches on a special path such as `@introduceDomain`
    /// (`ox/connections.ml:174-177`), for the daemon itself.
    pub fn fire_special(&mut self, path: &[u8]) {
        self.fire_special_at(&self.root.clone(), path, None);
    }

    /// As `fire_special`, checked against this version of the store, for
    /// a request of `source`.
    fn fire_special_at(&mut self, root: &Node, path: &[u8], source: Option<ConnId>) {
        let p = [Name::from(path)];
        let perms = watch_perms(core::iter::once(root), &p);
        for wid in self.index.special(path) {
            let w = self.index.get(wid);
            if self.conns.map.get(&w.conn).is_some_and(|c| {
                self.conns
                    .fires(can_fire(&self.cfg, c, &perms), w.conn, c, &perms, || path)
            }) {
                self.conns.event(w.conn, source, path, &w.token);
            }
        }
    }

    fn watch_args(msg: &Message) -> Result<(&[u8], &[u8]), Errno> {
        match path::split(&msg.payload, 8)[..] {
            [node, token, b""] if !node.is_empty() => Ok((node, token)),
            _ => Err(Errno::EINVAL),
        }
    }

    /// WATCH (`ox/connections.ml:128-139`, `ox/connection.ml:277-287`):
    /// the path, the quota, then whether it is there already. oxenstored
    /// does not limit the length of a watched path; here a held
    /// connection's is limited as a node's is: no node it could watch is
    /// longer, and each component costs a node of the index.
    fn watch(&mut self, id: ConnId, peer: &Peer, msg: &Message) -> Result<(), Errno> {
        let (node, token) = Self::watch_args(msg)?;
        let apath = path::absolute(node, &peer.home);
        let key = if node.first() == Some(&b'@') {
            Key::Special(node.into())
        } else {
            Key::Tree(path::components(&apath)?)
        };
        let held = !peer.caller.is_dom0();
        if held && path::checked_len(&apath) > self.cfg.path_max {
            return Err(Errno::EINVAL);
        }
        // The connection is open: `handle` runs for open ones only.
        let Some(conn) = self.conns.map.get_mut(&id) else {
            return Err(Errno::EIO);
        };
        if held && self.cfg.quota_activate && self.cfg.watch_max.is_some_and(|max| self.rules.full(conn.watches, max)) {
            return Err(self.rules.quota_error);
        }
        let tok = if *conn.last_token == *token {
            conn.last_token.clone()
        } else {
            Bytes::from(token)
        };
        if self.index.find(id, &key, token).is_some() {
            return Err(Errno::EEXIST);
        }
        let relative = !matches!(node.first(), Some(b'/' | b'@'));
        self.index.add(id, &key, tok.clone(), relative);
        conn.last_token = tok;
        conn.watches += 1;
        self.conns.send(id, msg.ty, msg.req_id, 0, &[b"OK\0"]);
        // A new watch fires once, unchecked (`ox/process.ml:536-546`).
        self.conns.event(id, Some(id), node, token);
        Ok(())
    }

    fn unwatch(&mut self, id: ConnId, peer: &Peer, msg: &Message) -> Result<(), Errno> {
        let (node, token) = Self::watch_args(msg)?;
        let apath = path::absolute(node, &peer.home);
        // A path that cannot be watched is not watched.
        let key = if node.first() == Some(&b'@') {
            Key::Special(node.into())
        } else {
            Key::Tree(path::components(&apath).map_err(|_| Errno::ENOENT)?)
        };
        let wid = self.index.find(id, &key, token).ok_or(Errno::ENOENT)?;
        self.index.remove(wid);
        self.conns
            .map
            .entry(id)
            .and_modify(|c| c.watches = c.watches.saturating_sub(1));
        self.conns.send(id, msg.ty, msg.req_id, 0, &[b"OK\0"]);
        Ok(())
    }

    fn reset(&mut self, id: ConnId) {
        let open = &mut self.conflicts.open;
        self.conns.map.entry(id).and_modify(|c| {
            uncount(open, c.txns.len(), "open transactions");
            c.txns.clear();
        });
        self.drop_watches(id);
    }

    /// Costs O(the connection's watches · depth).
    fn drop_watches(&mut self, id: ConnId) {
        self.index.remove_all(id);
        self.conns.map.entry(id).and_modify(|c| c.watches = 0);
    }

    /// TRANSACTION_START: not in a transaction, then the quota
    /// (`ox/process.ml:539-543`, `ox/connection.ml:382-385`).
    fn transaction_start(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32) -> Result<(), Errno> {
        if tid != 0 {
            return Err(Errno::EBUSY);
        }
        // The connection is open: `handle` runs for open ones only.
        let Some(conn) = self.conns.map.get_mut(&id) else {
            return Err(Errno::EIO);
        };
        if !peer.caller.is_dom0()
            && self
                .cfg
                .transaction_max
                .is_some_and(|max| self.rules.full(conn.txns.len(), max))
        {
            return Err(self.rules.quota_error);
        }
        // Ids from 1 per connection, skipping open ones, wrapping below
        // 0x3fffffff (`ox/connection.ml:364-380`).
        let mut t = conn.next_tid;
        loop {
            if t == 0 || t >= 0x3fff_ffff {
                t = 1;
            }
            if !conn.txns.contains_key(&t) {
                break;
            }
            t += 1;
        }
        conn.next_tid = t + 1;
        let txn = Txn {
            snapshot: self.root.clone(),
            tree: self.root.clone(),
            log: Vec::new(),
            listings: txlog::Listings::default(),
            delta: Delta::default(),
            bytes: 0,
            requests: 0,
            started: self.conflicts.start(),
        };
        conn.txns.insert(t, txn);
        self.conns.log_txn(id, t, log::Op::Start);
        self.conns
            .send(id, msg.ty, msg.req_id, tid, &[t.to_string().as_bytes(), b"\0"]);
        Ok(())
    }

    fn transaction_end(&mut self, id: ConnId, peer: &Peer, msg: &Message, tid: u32) -> Result<(), Errno> {
        let commit = match path::split(&msg.payload, 8).first().copied() {
            Some(b"T") => true,
            Some(b"F") => false,
            _ => return Err(Errno::EINVAL),
        };
        let txn = self
            .conns
            .map
            .get_mut(&id)
            .and_then(|c| c.txns.remove(&tid))
            .ok_or(Errno::ENOENT)?;
        self.conns.log_txn(id, tid, log::Op::End);
        let ctx = self.ctx(peer.caller);
        // A transaction that changed nothing is not committed: it cannot
        // fail (`ox/process.ml:565`, `ox/transaction.ml:142`).
        let Txn {
            snapshot,
            tree,
            log,
            delta,
            started,
            ..
        } = txn;
        if commit && log.iter().any(|e| e.fired.is_some()) {
            let before = self.root.clone();
            if Arc::ptr_eq(&self.root, &snapshot) {
                // Nothing committed since the snapshot (so the counts are
                // the snapshot's): publish the transaction's version as it is.
                self.root = tree;
                self.entries.apply(delta);
            } else {
                drop(tree);
                // Re-execute every request on the current store, quotas
                // included; a different reply means a conflict
                // (`ox/process.ml:473-501`).
                let mut tree = self.root.clone();
                let mut delta = Delta::default();
                for e in &log {
                    let mut acct = Acct::Txn(&self.entries, &mut delta);
                    let (outcome, _) = execute_in(&mut tree, &mut self.gen, &e.op(), &ctx, &mut acct);
                    if !e.same_reply(&outcome) {
                        self.conns.log_txn(id, tid, log::Op::Conflict);
                        self.blame(id, &log, started, &ctx);
                        self.conflicts.end(started);
                        return Err(Errno::EAGAIN);
                    }
                }
                self.root = tree;
                self.entries.apply(delta);
            }
            self.conns.log_txn(id, tid, log::Op::Commit);
            // Recorded after the end, as `ox/process.ml:544-555` does.
            self.conflicts.end(started);
            if self.wants_record(peer) {
                self.conflicts.record(id, before, &self.root);
            }
            // oxenstored queues the events before the reply (`ox/process.ml:567-569`):
            // one change per request that changed the transaction's version
            // when it ran there, in the order they ran, whatever running
            // them again changed (`ox/process.ml:60-72`, the paths the
            // transaction recorded, `ox/transaction.ml:147`). Each is
            // checked against the store before the transaction and after
            // it, not as the requests before it left it (XSA-115). There
            // "after" is the transaction's own version even when it was
            // run again; here it is what was committed.
            for (kind, e) in log.iter().filter_map(|e| e.fired.map(|k| (k, e))) {
                let c = Change {
                    path: e.path(),
                    kind,
                    before: Some(snapshot.clone()),
                    after: (kind != ChangeKind::Rm).then(|| self.root.clone()),
                };
                self.dispatch(&c, id);
            }
        } else {
            self.conflicts.end(started);
        }
        self.conns.send(id, msg.ty, msg.req_id, tid, &[b"OK\0"]);
        Ok(())
    }

    /// A commit failed: those whose changes made it fail lose credit
    /// (`ox/process.ml:472-499`). Each is judged by running the
    /// transaction again on the store before and after its change, with
    /// the node counts of now: what changed in the tree decides.
    fn blame(&mut self, id: ConnId, log: &[txlog::Entry], started: Started, ctx: &Ctx) {
        for culprit in self.culprits(id, log, started, ctx, true) {
            self.conflicts.penalise(&mut self.conns, culprit);
        }
    }

    /// Who `blame` blames. A record whose versions the transaction cannot
    /// tell apart (`txlog::Footprint`) is not judged if `skip`: that
    /// changes no verdict (it commits on both or on neither), and spares
    /// running the transaction once or twice per record of the history.
    fn culprits(&mut self, id: ConnId, log: &[txlog::Entry], started: Started, ctx: &Ctx, skip: bool) -> Vec<ConnId> {
        let (gen, entries) = (&mut self.gen, &self.entries);
        let commits = |store: &Arc<Node>| {
            let (mut tree, mut delta) = (store.clone(), Delta::default());
            let mut acct = Acct::Txn(entries, &mut delta);
            log.iter()
                .all(|e| e.same_reply(&execute_in(&mut tree, gen, &e.op(), ctx, &mut acct).0))
        };
        let footprint = txlog::Footprint::of(log);
        let same = |a: &Node, b: &Node| skip && footprint.same(a, b);
        self.conflicts.culprits(started, id, same, commits)
    }

    /// Is a change by this connection to be recorded for blame? Only if
    /// a transaction that may need it is open.
    fn wants_record(&self, peer: &Peer) -> bool {
        self.conflicts.open > 0 && blamable(peer.ring, peer.caller)
    }

    /// The loop gives the time (monotonic, from any origin), once per
    /// pass: transactions are stamped with it, and conflict credit is
    /// given back with it (`ox/xenstored.ml:447-452`). A domain that
    /// gets requests processed again is reported by `take_dirty`.
    pub fn tick(&mut self, now: Duration) {
        self.conflicts.tick(&mut self.conns, now);
    }

    /// When `tick` must be called next at the latest, if at all: credit
    /// is owed (`ox/xenstored.ml:595-600`).
    pub fn next_tick(&self) -> Option<Duration> {
        self.conflicts.deadline()
    }

    /// Recounts what the quotas count, from what is counted (for tests and
    /// debugging; it walks every version of the store): the nodes of the
    /// store and the changes of every transaction, the watches, unsent
    /// messages and holds of every connection. The first difference, if any.
    pub fn audit(&self) -> Result<(), String> {
        let recount = Entries::recount(&self.root);
        if recount != self.entries {
            return Err(format!("store: counted {:?}, holds {recount:?}", self.entries));
        }
        // Transactions mostly share their versions: each is counted once.
        let mut counted: BTreeMap<*const Node, Entries> = BTreeMap::new();
        let mut count = |v: &Arc<Node>| {
            counted
                .entry(Arc::as_ptr(v))
                .or_insert_with(|| Entries::recount(v))
                .clone()
        };
        for (id, c) in &self.conns.map {
            for (tid, t) in &c.txns {
                let bytes: usize = t.log.iter().map(txlog::Entry::cost).sum();
                if bytes != t.bytes {
                    return Err(format!(
                        "{id:?} transaction {tid}: {} bytes counted, {bytes} kept",
                        t.bytes
                    ));
                }
                let changed = quota::diff(&count(&t.tree), &count(&t.snapshot));
                if changed != t.delta {
                    return Err(format!(
                        "{id:?} transaction {tid}: counted {:?}, changed {changed:?}",
                        t.delta
                    ));
                }
            }
            let watches = self.index.of(*id).count();
            let events = c.out.msgs.iter().filter(|m| m.1 != Class::Reply).count();
            let mut from = BTreeMap::new();
            for (_, class) in &c.out.msgs {
                if let Class::EventFrom(s) = class {
                    *from.entry(*s).or_insert(0) += 1;
                }
            }
            if from != c.out.from {
                return Err(format!(
                    "{id:?}: events by source counted {:?}, are {from:?}",
                    c.out.from
                ));
            }
            let held = self
                .conns
                .map
                .values()
                .map(|w| w.waiters.iter().filter(|s| *s == id).count())
                .sum::<usize>();
            let (counted, real) = (
                (c.watches, c.out.events, c.out.replies, c.holds),
                (watches, events, c.out.msgs.len() - events, held),
            );
            if counted != real {
                return Err(format!(
                    "{id:?}: watches, events, replies, holds counted {counted:?}, are {real:?}"
                ));
            }
        }
        self.conflicts.audit(&self.conns)
    }
}

/// Unit tests that build an impossible state on purpose, to check the
/// fallback that follows `impossible`, count themselves here while they
/// run (`tests::expect_impossible`).
static EXPECTING_IMPOSSIBLE: AtomicUsize = AtomicUsize::new(0);

/// Called where the code meets a state its invariants rule out (a stale
/// index, an empty node, a count about to go below zero). A debug build
/// stops there: a test or a debug daemon has found a bug. A release build
/// goes on with the caller's fallback, which loses a link or a count
/// rather than the daemon.
#[track_caller]
pub(crate) fn impossible(what: &str) {
    debug_assert!(
        EXPECTING_IMPOSSIBLE.load(Ordering::Relaxed) > 0,
        "impossible state: {what}"
    );
}

/// `*count -= n`, for a count the code keeps at least `n`; were it less,
/// `impossible`, and 0 rather than a wrap.
pub(crate) fn uncount(count: &mut usize, n: usize, what: &str) {
    match count.checked_sub(n) {
        Some(c) => *count = c,
        None => {
            impossible(what);
            *count = 0;
        }
    }
}

/// The path of a node as components.
#[cfg(test)]
pub fn parse_absolute(p: &str) -> Result<path::Path, Errno> {
    path::components(p.as_bytes())
}

#[cfg(test)]
mod tests;
