// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Unit tests of the request handling, through the public byte interface.

use super::*;
use std::hash::BuildHasher;
use xs_wire::nul_terminated;

/// A key for `Core::new` drawn as the daemon draws it: the tests see a
/// different layout of the watch index at every run. A failed test shows the key it drew (the test harness
/// prints what a failed test printed); `XS_TEST_HASH_KEY=A,B` (as shown)
/// replays it.
pub(crate) fn random_key() -> [u64; 2] {
    let key = match std::env::var("XS_TEST_HASH_KEY") {
        Ok(v) => {
            let k: Vec<u64> = v
                .split(',')
                .map(|x| {
                    u64::from_str_radix(x.trim().trim_start_matches("0x"), 16).expect("XS_TEST_HASH_KEY=A,B in hex")
                })
                .collect();
            [k[0], k[1]]
        }
        Err(_) => {
            let s = std::hash::RandomState::new();
            [s.hash_one(0u8), s.hash_one(1u8)]
        }
    };
    println!("XS_TEST_HASH_KEY={:#x},{:#x}", key[0], key[1]);
    key
}

/// Taken by the tests that meet an impossible state on purpose, and by the
/// one that checks a debug build stops at one: they run one at a time.
static IMPOSSIBLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// While it lives, `impossible` lets the fallback run (`EXPECTING_IMPOSSIBLE`).
pub(crate) struct ExpectImpossible(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

pub(crate) fn expect_impossible() -> ExpectImpossible {
    let g = IMPOSSIBLE.lock().unwrap_or_else(|e| e.into_inner());
    EXPECTING_IMPOSSIBLE.fetch_add(1, Ordering::SeqCst);
    ExpectImpossible(g)
}

impl Drop for ExpectImpossible {
    fn drop(&mut self) {
        EXPECTING_IMPOSSIBLE.fetch_sub(1, Ordering::SeqCst);
    }
}

#[test]
#[should_panic(expected = "impossible state: a test's")]
fn a_debug_build_stops_at_an_impossible_state() {
    let _one_at_a_time = IMPOSSIBLE.lock().unwrap_or_else(|e| e.into_inner());
    impossible("a test's");
}

#[test]
fn a_count_that_would_go_below_zero_stays_at_zero() {
    let _g = expect_impossible();
    let mut n = 2;
    uncount(&mut n, 3, "a test's");
    assert_eq!(n, 0);
    uncount(&mut n, 0, "a test's");
    assert_eq!(n, 0);
}

struct H {
    core: Core,
    req: u32,
    machine: Rec,
}

/// What the core asked of the machine.
#[derive(Debug, Clone, PartialEq)]
enum Call {
    Connect(ConnId, u32, u64, u32),
    Rebind(ConnId, u32, u32),
    Disconnect(ConnId, u32),
}

/// A machine that records what it is asked, and fails with `fail` if set.
#[derive(Default)]
struct Rec {
    calls: Vec<Call>,
    fail: Option<Errno>,
}

impl Machine for Rec {
    fn connect(&mut self, conn: ConnId, domid: u32, gfn: u64, remote_port: u32) -> Result<(), Errno> {
        self.calls.push(Call::Connect(conn, domid, gfn, remote_port));
        self.fail.map_or(Ok(()), Err)
    }

    fn rebind(&mut self, conn: ConnId, domid: u32, remote_port: u32) -> Result<(), Errno> {
        self.calls.push(Call::Rebind(conn, domid, remote_port));
        self.fail.map_or(Ok(()), Err)
    }

    fn disconnect(&mut self, conn: ConnId, domid: u32) {
        self.calls.push(Call::Disconnect(conn, domid));
    }
}

/// A decoded output message: type, req_id, tx_id, payload.
type Out = (u32, u32, u32, Vec<u8>);

fn ty(t: MsgType) -> u32 {
    t as u32
}

std::thread_local! {
    /// The profile `H::with` gives every core it makes, if set (`in_profile`).
    static PROFILE: std::cell::Cell<Option<Profile>> = const { std::cell::Cell::new(None) };
}

/// Runs `test` with every core the harness makes in `profile`.
fn in_profile(profile: Profile, test: fn()) {
    PROFILE.set(Some(profile));
    test();
    PROFILE.set(None);
}

/// The rules of the cores the harness makes now.
fn rules() -> Rules {
    PROFILE.get().unwrap_or(Profile::Oxenstored).rules()
}

/// The name of the error of a quota, for the cores the harness makes now.
fn quota_error() -> &'static str {
    rules().quota_error.name()
}

/// Does the harness make cores in the native profile now?
fn native() -> bool {
    PROFILE.get() == Some(Profile::Native)
}

impl H {
    fn new() -> H {
        H::with(Config::default())
    }

    fn with(cfg: Config) -> H {
        let cfg = Config {
            profile: PROFILE.get().unwrap_or(cfg.profile),
            ..cfg
        };
        H {
            core: Core::new(cfg, random_key()),
            req: 100,
            machine: Rec::default(),
        }
    }

    /// Queues a raw request on `c` and processes it, on the recording
    /// machine; then checks what the quotas count.
    fn send(&mut self, c: ConnId, t: u32, tx: u32, payload: &[u8]) -> Status {
        self.push(c, t, tx, payload);
        let st = self.core.process_on(c, 1000, &mut self.machine);
        self.core.audit().unwrap();
        st
    }

    /// Queues a raw request on `c`, unprocessed.
    fn push(&mut self, c: ConnId, t: u32, tx: u32, payload: &[u8]) {
        self.req += 1;
        let mut bytes = Vec::new();
        write_header(&mut bytes, t, self.req, tx, payload.len() as u32);
        bytes.extend_from_slice(payload);
        self.core.feed(c, &bytes);
    }

    /// Sends and drains the output of `c` only: the messages it got.
    fn drain_one(&mut self, c: ConnId) -> Vec<Out> {
        let bytes = self.core.output(c).to_vec();
        self.core.consume(c, bytes.len());
        let mut out = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let w = |i: usize| u32::from_le_bytes(rest[i..i + 4].try_into().unwrap());
            let len = w(12) as usize;
            out.push((w(0), w(4), w(8), rest[16..16 + len].to_vec()));
            rest = &rest[16 + len..];
        }
        out
    }

    /// Sends a raw request, returns everything queued for every connection.
    fn raw(&mut self, c: ConnId, t: u32, tx: u32, payload: &[u8]) -> Vec<(ConnId, Out)> {
        assert_ne!(self.send(c, t, tx, payload), Status::More);
        self.drain()
    }

    /// What the machine was asked since the last call.
    fn calls(&mut self) -> Vec<Call> {
        std::mem::take(&mut self.machine.calls)
    }

    /// INTRODUCE of a new domain by `c`: its connection.
    fn introduce(&mut self, c: ConnId, domid: u32, gfn: u64, port: u32) -> ConnId {
        // A nativeint: signed.
        let r = self.ok(
            c,
            MsgType::Introduce,
            0,
            format!("{domid}\0{}\0{port}\0", gfn as i64).as_bytes(),
        );
        assert_eq!(r, b"OK\0");
        let id = self.core.domain_conn(domid).unwrap();
        assert_eq!(self.calls(), [Call::Connect(id, domid, gfn, port)]);
        id
    }

    /// Fires VIRQ_DOM_EXC with these states (Running for the others);
    /// returns the domains asked about.
    fn dom_exc(&mut self, states: &[(u32, DomainState)]) -> Vec<u32> {
        let mut asked = Vec::new();
        let mut state = |d: u32| {
            asked.push(d);
            states.iter().find(|s| s.0 == d).map_or(DomainState::Running, |s| s.1)
        };
        self.core.domains_changed(&mut state, &mut self.machine);
        asked
    }

    fn drain(&mut self) -> Vec<(ConnId, Out)> {
        let mut dirty = Vec::new();
        self.core.take_dirty(&mut dirty);
        let mut out = Vec::new();
        for id in dirty {
            let bytes = self.core.output(id).to_vec();
            self.core.consume(id, bytes.len());
            // Decoded by hand: socket replies may exceed PAYLOAD_MAX.
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                let w = |i: usize| u32::from_le_bytes(rest[i..i + 4].try_into().unwrap());
                let len = w(12) as usize;
                out.push((id, (w(0), w(4), w(8), rest[16..16 + len].to_vec())));
                rest = &rest[16 + len..];
            }
        }
        out
    }

    /// The reply to a request on `c`, asserting there is exactly one.
    fn call(&mut self, c: ConnId, t: MsgType, tx: u32, payload: &[u8]) -> Out {
        let out = self.raw(c, ty(t), tx, payload);
        let replies: Vec<_> = out
            .iter()
            .filter(|(id, m)| *id == c && m.0 != ty(MsgType::WatchEvent))
            .collect();
        assert_eq!(replies.len(), 1, "{out:?}");
        assert_eq!(replies[0].1 .1, self.req);
        replies[0].1.clone()
    }

    fn ok(&mut self, c: ConnId, t: MsgType, tx: u32, payload: &[u8]) -> Vec<u8> {
        let r = self.call(c, t, tx, payload);
        assert_ne!(
            r.0,
            ty(MsgType::Error),
            "{t:?} {:?}: {}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(&r.3)
        );
        assert_eq!(r.0, ty(t));
        r.3
    }

    fn err(&mut self, c: ConnId, t: MsgType, tx: u32, payload: &[u8]) -> String {
        let r = self.call(c, t, tx, payload);
        assert_eq!(
            r.0,
            ty(MsgType::Error),
            "{t:?} succeeded: {:?}",
            String::from_utf8_lossy(&r.3)
        );
        let s = String::from_utf8(r.3).unwrap();
        s.strip_suffix('\0').unwrap().to_string()
    }

    fn write(&mut self, c: ConnId, tx: u32, p: &str, v: &str) {
        assert_eq!(
            self.ok(c, MsgType::Write, tx, &[p.as_bytes(), b"\0", v.as_bytes()].concat()),
            b"OK\0"
        );
    }

    fn read(&mut self, c: ConnId, tx: u32, p: &str) -> Result<String, String> {
        let r = self.call(c, MsgType::Read, tx, &nul_terminated(&[p.as_bytes()]));
        if r.0 == ty(MsgType::Error) {
            Err(String::from_utf8(r.3).unwrap().trim_end_matches('\0').into())
        } else {
            Ok(String::from_utf8(r.3).unwrap())
        }
    }

    fn ls(&mut self, c: ConnId, tx: u32, p: &str) -> Vec<String> {
        let r = self.ok(c, MsgType::Directory, tx, &nul_terminated(&[p.as_bytes()]));
        let s = String::from_utf8(r).unwrap();
        s.split_terminator('\0').map(str::to_string).collect()
    }

    fn one(&mut self, c: ConnId, t: MsgType, p: &str) -> Vec<u8> {
        self.ok(c, t, 0, &nul_terminated(&[p.as_bytes()]))
    }

    fn start(&mut self, c: ConnId) -> u32 {
        let r = self.ok(c, MsgType::TransactionStart, 0, b"\0");
        String::from_utf8(r).unwrap().trim_end_matches('\0').parse().unwrap()
    }

    fn end(&mut self, c: ConnId, tx: u32, commit: bool) -> Result<(), String> {
        let r = self.call(c, MsgType::TransactionEnd, tx, if commit { b"T\0" } else { b"F\0" });
        assert_eq!(r.2, tx);
        if r.0 == ty(MsgType::Error) {
            Err(String::from_utf8(r.3).unwrap().trim_end_matches('\0').into())
        } else {
            Ok(())
        }
    }

    /// Registers a watch, returns the events of the registration.
    fn watch(&mut self, c: ConnId, p: &str, token: &str) -> Vec<(ConnId, String, String)> {
        let out = self.raw(
            c,
            ty(MsgType::Watch),
            0,
            &nul_terminated(&[p.as_bytes(), token.as_bytes()]),
        );
        assert_eq!(out[0].1 .0, ty(MsgType::Watch), "{out:?}");
        assert_eq!(out[0].1 .3, b"OK\0");
        events(&out)
    }
}

/// The watch events in an output, as (connection, path, token).
fn events(out: &[(ConnId, Out)]) -> Vec<(ConnId, String, String)> {
    let mut v: Vec<_> = out
        .iter()
        .filter(|(_, m)| m.0 == ty(MsgType::WatchEvent))
        .map(|(c, m)| {
            assert_eq!((m.1, m.2), (0, 0));
            let s = String::from_utf8(m.3.clone()).unwrap();
            let f: Vec<&str> = s.split('\0').collect();
            assert_eq!(f.len(), 3, "{s:?}");
            assert_eq!(f[2], "");
            (*c, f[0].to_string(), f[1].to_string())
        })
        .collect();
    v.sort();
    v
}

/// The watch events of connection `c` in an output, in the order it got
/// them, as (path, token).
fn events_of(out: &[(ConnId, Out)], c: ConnId) -> Vec<(String, String)> {
    out.iter()
        .filter(|(id, m)| *id == c && m.0 == ty(MsgType::WatchEvent))
        .map(|(_, m)| {
            let s = String::from_utf8(m.3.clone()).unwrap();
            let f: Vec<&str> = s.split('\0').collect();
            (f[0].to_string(), f[1].to_string())
        })
        .collect()
}

/// The tokens of `events_of`.
fn tokens_of(out: &[(ConnId, Out)], c: ConnId) -> Vec<String> {
    events_of(out, c).into_iter().map(|e| e.1).collect()
}

fn ev(c: ConnId, p: &str, t: &str) -> (ConnId, String, String) {
    (c, p.into(), t.into())
}

fn wr(p: &str, v: &str) -> Vec<u8> {
    [p.as_bytes(), b"\0", v.as_bytes()].concat()
}

// ---------------------------------------------------------------- basics

#[test]
fn read_write_directory() {
    let mut h = H::new();
    let a = h.core.open();
    assert_eq!(h.ls(a, 0, "/"), ["@introduceDomain", "@releaseDomain", "local", "tool"]);
    assert_eq!(h.read(a, 0, "/tool/xenstored").unwrap(), "rxenstored");
    h.write(a, 0, "/vm/x/name", "hello");
    assert_eq!(h.read(a, 0, "/vm/x/name").unwrap(), "hello");
    assert_eq!(h.read(a, 0, "/vm/x").unwrap(), "");
    assert_eq!(h.read(a, 0, "/vm/y"), Err("ENOENT".into()));
    h.write(a, 0, "/vm/x/b", "");
    h.write(a, 0, "/vm/x/a", "");
    assert_eq!(h.ls(a, 0, "/vm/x"), ["a", "b", "name"]);
    assert_eq!(
        h.one(a, MsgType::Directory, "/vm/x/a"),
        b"",
        "no children: empty payload"
    );
    assert_eq!(h.err(a, MsgType::Directory, 0, b"/nope\0"), "ENOENT");
}

#[test]
fn values_are_bytes() {
    let mut h = H::new();
    let a = h.core.open();
    h.ok(a, MsgType::Write, 0, b"/v\0a\0b\0");
    assert_eq!(h.one(a, MsgType::Read, "/v"), b"a\0b\0");
    h.ok(a, MsgType::Write, 0, b"/e\0");
    assert_eq!(h.one(a, MsgType::Read, "/e"), b"");
}

#[test]
fn relative_paths_are_under_domain_0() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "backend/vbd/1", "x");
    assert_eq!(h.read(a, 0, "/local/domain/0/backend/vbd/1").unwrap(), "x");
    assert_eq!(h.read(a, 0, "backend/vbd/1").unwrap(), "x");
    assert_eq!(h.ls(a, 0, "/local/domain/0"), ["backend"]);
}

#[test]
fn mkdir_creates_and_tolerates_existing() {
    let mut h = H::new();
    let a = h.core.open();
    assert_eq!(h.one(a, MsgType::Mkdir, "/a/b/c"), b"OK\0");
    assert_eq!(h.ls(a, 0, "/a/b"), ["c"]);
    h.write(a, 0, "/a/b/c", "v");
    assert_eq!(h.one(a, MsgType::Mkdir, "/a/b/c"), b"OK\0");
    assert_eq!(h.read(a, 0, "/a/b/c").unwrap(), "v", "mkdir keeps the value");
}

#[test]
fn rm_semantics() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/a/b/c", "1");
    assert_eq!(h.one(a, MsgType::Rm, "/a/b/x"), b"OK\0", "absent node, parent present");
    assert_eq!(h.err(a, MsgType::Rm, 0, b"/a/x/y\0"), "ENOENT", "absent parent");
    assert_eq!(h.err(a, MsgType::Rm, 0, b"/q/x/y\0"), "ENOENT");
    assert_eq!(h.one(a, MsgType::Rm, "/a/b"), b"OK\0");
    assert_eq!(h.ls(a, 0, "/a"), Vec::<String>::new());
    assert_eq!(h.read(a, 0, "/a/b/c"), Err("ENOENT".into()));
    h.one(a, MsgType::Rm, "/");
    assert_eq!(h.ls(a, 0, "/"), Vec::<String>::new(), "rm / empties the store");
}

#[test]
fn permissions_are_stored_and_returned() {
    let mut h = H::new();
    let a = h.core.open();
    assert_eq!(h.one(a, MsgType::GetPerms, "/"), b"n0\0");
    h.write(a, 0, "/d", "");
    assert_eq!(h.ok(a, MsgType::SetPerms, 0, b"/d\0n0\0r4\0b7\0"), b"OK\0");
    assert_eq!(h.one(a, MsgType::GetPerms, "/d"), b"n0\0r4\0b7\0");
    // Children inherit their parent's permissions.
    h.write(a, 0, "/d/e/f", "");
    assert_eq!(h.one(a, MsgType::GetPerms, "/d/e/f"), b"n0\0r4\0b7\0");
    h.one(a, MsgType::Mkdir, "/d/g");
    assert_eq!(h.one(a, MsgType::GetPerms, "/d/g"), b"n0\0r4\0b7\0");
    assert_eq!(h.err(a, MsgType::SetPerms, 0, b"/nope\0n0\0"), "ENOENT");
    assert_eq!(h.err(a, MsgType::GetPerms, 0, b"/nope\0"), "ENOENT");
    assert_eq!(h.err(a, MsgType::SetPerms, 0, b"/d\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::SetPerms, 0, b"/d\0x1\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::SetPerms, 0, b"/d"), "EINVAL");
    // No access check for socket connections: domain 0 can do anything.
    h.ok(a, MsgType::SetPerms, 0, b"/d\0n5\0");
    h.write(a, 0, "/d/x", "1");
    assert_eq!(h.read(a, 0, "/d/x").unwrap(), "1");
}

#[test]
fn get_domain_path() {
    let mut h = H::new();
    let a = h.core.open();
    assert_eq!(h.ok(a, MsgType::GetDomainPath, 0, b"7\0"), b"/local/domain/7\0");
    assert_eq!(h.ok(a, MsgType::GetDomainPath, 0, b"x12y\0"), b"/local/domain/12\0");
    assert_eq!(h.ok(a, MsgType::GetDomainPath, 0, b"\0"), b"/local/domain/0\0");
    assert_eq!(h.err(a, MsgType::GetDomainPath, 0, b"7"), "EINVAL");
    assert_eq!(h.err(a, MsgType::GetDomainPath, 0, b"7\0\0"), "EINVAL");
}

#[test]
fn payload_validation() {
    let mut h = H::new();
    let a = h.core.open();
    for t in [
        MsgType::Read,
        MsgType::Directory,
        MsgType::GetPerms,
        MsgType::Mkdir,
        MsgType::Rm,
    ] {
        assert_eq!(h.err(a, t, 0, b"/a"), "EINVAL", "{t:?}: no NUL");
        assert_eq!(h.err(a, t, 0, b"/a\0\0"), "EINVAL", "{t:?}: extra field");
        assert_eq!(h.err(a, t, 0, b"\0"), "EINVAL", "{t:?}: empty path");
        assert_eq!(h.err(a, t, 0, b"/a/\0"), "EINVAL", "{t:?}: trailing slash");
        assert_eq!(h.err(a, t, 0, b"/a b\0"), "EINVAL", "{t:?}: bad character");
        assert_eq!(h.err(a, t, 0, b""), "EINVAL", "{t:?}: empty payload");
    }
    assert_eq!(
        h.err(a, MsgType::Write, 0, b"/a"),
        "EINVAL",
        "write needs a NUL after the path"
    );
    assert_eq!(h.err(a, MsgType::Write, 0, b"a//b\0v"), "EINVAL");
    let long = format!("/{}\0", "a".repeat(crate::path::PATH_MAX));
    assert_eq!(h.err(a, MsgType::Read, 0, long.as_bytes()), "EINVAL", "path too long");
    let value = wr("/big", &"v".repeat(2049));
    assert_eq!(h.err(a, MsgType::Write, 0, &value), "E2BIG");
    h.ok(a, MsgType::Write, 0, &wr("/big", &"v".repeat(2048)));
}

#[test]
fn unknown_and_unimplemented_types_answer_enosys() {
    let mut h = H::new();
    let a = h.core.open();
    // Server-to-client types, RESTRICT, and what oxenstored 4.17 lacks
    // too (its operations end at RESET_WATCHES, `4.17 xb/op.ml:17-31`).
    for t in [15u32, 16, 20, 23, 24, 25, 26, 27, 0xffff, u32::MAX] {
        let out = h.raw(a, t, 0, b"x\0");
        assert_eq!(out.len(), 1);
        let (_, (rt, rq, rtx, p)) = &out[0];
        assert_eq!((*rt, *rq, *rtx), (ty(MsgType::Error), h.req, 0), "type {t}");
        assert_eq!(p, b"ENOSYS\0");
    }
}

// ----------------------------------------------------------- permissions

/// A socket connection, and a guest (domain 5) that owns its home.
fn with_guest(cfg: Config) -> (H, ConnId, ConnId) {
    let mut h = H::with(cfg);
    let a = h.core.open();
    let g = h.core.open_domain(5);
    h.one(a, MsgType::Mkdir, "/local/domain/5");
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0");
    (h, a, g)
}

#[test]
fn a_guest_is_confined_by_permissions() {
    let (mut h, a, g) = with_guest(Config::default());
    // Its relative paths are under its home, which it owns.
    h.write(g, 0, "data/x", "1");
    assert_eq!(h.read(a, 0, "/local/domain/5/data/x").unwrap(), "1");
    assert_eq!(h.one(g, MsgType::GetPerms, "data/x"), b"n5\0");
    assert_eq!(h.ok(g, MsgType::GetDomainPath, 0, b"5\0"), b"/local/domain/5\0");
    // Everything else belongs to domain 0 and is closed to others.
    assert_eq!(h.read(g, 0, "/tool/xenstored"), Err("EACCES".into()));
    for t in [
        MsgType::Read,
        MsgType::Directory,
        MsgType::GetPerms,
        MsgType::Mkdir,
        MsgType::Rm,
    ] {
        assert_eq!(h.err(g, t, 0, b"/local\0"), "EACCES", "{t:?}");
    }
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("/local/domain/0/x", "1")), "EACCES");
    assert_eq!(h.err(g, MsgType::SetPerms, 0, b"/local\0n5\0"), "EACCES");
    assert_eq!(
        h.err(g, MsgType::SetPerms, 0, b"data\0n0\0"),
        "EACCES",
        "giving a node away"
    );
    assert_eq!(
        h.read(g, 0, "/local/nothing"),
        Err("ENOENT".into()),
        "existence is not hidden"
    );
    // Domain 0 opens a node to it.
    h.write(a, 0, "/shared", "s");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0r5\0");
    assert_eq!(h.read(g, 0, "/shared").unwrap(), "s");
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("/shared", "1")), "EACCES");
    // A socket is domain 0 whatever it asks.
    assert_eq!(h.ls(a, 0, "/local/domain/5"), ["data"]);
}

#[test]
fn a_guest_transaction_is_checked_when_it_runs_and_when_it_is_replayed() {
    let (mut h, a, g) = with_guest(Config::default());
    h.write(a, 0, "/shared", "s");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0b5\0");
    let t = h.start(g);
    h.write(g, t, "/shared", "mine");
    assert_eq!(h.err(g, MsgType::Write, t, &wr("/tool/x", "1")), "EACCES");
    // Something else is committed: the transaction is replayed, as domain 5.
    h.write(a, 0, "/other", "1");
    assert_eq!(h.end(g, t, true), Ok(()));
    assert_eq!(h.read(a, 0, "/shared").unwrap(), "mine");
    assert_eq!(h.read(a, 0, "/tool/x"), Err("ENOENT".into()));
    // Access withdrawn before the commit: the replay answers differently.
    let t = h.start(g);
    h.write(g, t, "/shared", "again");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0");
    assert_eq!(h.end(g, t, true), Err("EAGAIN".into()));
    assert_eq!(h.read(a, 0, "/shared").unwrap(), "mine");
}

#[test]
fn set_target_lets_a_domain_act_for_another() {
    let (mut h, a, g) = with_guest(Config::default());
    let stub = h.core.open_domain(7);
    h.write(g, 0, "data/x", "1");
    assert_eq!(h.read(stub, 0, "/local/domain/5/data/x"), Err("EACCES".into()));
    // For domain 0 only, and for a domain that has a connection.
    assert_eq!(h.err(g, MsgType::SetTarget, 0, b"7\x005\0"), "EACCES");
    assert_eq!(
        h.err(stub, MsgType::SetTarget, 0, b"bad"),
        "EACCES",
        "before the arguments"
    );
    for bad in [&b"7\0"[..], b"7\x005", b"7\x005\0x\0", b"", b"7\x005\0\0"] {
        assert_eq!(h.err(a, MsgType::SetTarget, 0, bad), "EINVAL", "{bad:?}");
    }
    assert_eq!(h.err(a, MsgType::SetTarget, 0, b"9\x005\0"), "ENOENT");
    assert_eq!(
        h.err(a, MsgType::SetTarget, 0, b"0\x005\0"),
        "ENOENT",
        "a socket is not domain 0's connection"
    );
    assert_eq!(h.ok(a, MsgType::SetTarget, 0, b"7\x005\0"), b"OK\0");
    // The stub domain now has domain 5's access, and owns what it owns.
    assert_eq!(h.read(stub, 0, "/local/domain/5/data/x").unwrap(), "1");
    h.ok(stub, MsgType::SetPerms, 0, b"/local/domain/5/data/x\0n5\0r9\0");
    assert_eq!(h.read(stub, 0, "/tool/xenstored"), Err("EACCES".into()));
    // Its own paths are still relative to its own home.
    assert_eq!(h.err(stub, MsgType::Write, 0, &wr("y", "1")), "EACCES");
    // A domain acting for domain 0 is domain 0.
    assert_eq!(h.ok(a, MsgType::SetTarget, 0, b"7\x000\0"), b"OK\0");
    assert_eq!(h.read(stub, 0, "/tool/xenstored").unwrap(), "rxenstored");
    assert_eq!(h.ok(stub, MsgType::SetTarget, 0, b"5\x000\0"), b"OK\0");
    assert_eq!(h.read(g, 0, "/tool/xenstored").unwrap(), "rxenstored");
    // The target goes with the connection.
    h.core.close(stub);
    assert_eq!(h.err(a, MsgType::SetTarget, 0, b"7\x005\0"), "ENOENT");
    let stub = h.core.open_domain(7);
    assert_eq!(h.read(stub, 0, "/tool/xenstored"), Err("EACCES".into()));
    // A second connection of a domain takes the place of the first, which
    // is closed: closing it again leaves the second there.
    h.watch(stub, "w", "t");
    let n = h.core.connections();
    let second = h.core.open_domain(7);
    assert_eq!((h.core.connections(), h.core.watches()), (n, 0));
    assert_eq!(h.send(stub, ty(MsgType::Read), 0, b"w\0"), Status::Closed);
    h.core.close(stub);
    // Closing a domain's connection forgets the domain; closing another
    // one of its domid (a socket is domain 0) does not.
    let d0 = h.core.open_domain(0);
    let b = h.core.open();
    h.core.close(b);
    assert_eq!(h.core.domain_conn(0), Some(d0));
    h.core.close(d0);
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"0\0"), b"F\0");
    assert_eq!(h.ok(a, MsgType::SetTarget, 0, b"7\x005\0"), b"OK\0");
    assert_eq!(h.read(second, 0, "/local/domain/5/data/x").unwrap(), "1");
}

#[test]
fn a_watch_fires_for_who_may_read_the_node_or_its_parent() {
    let (mut h, a, g) = with_guest(Config::default());
    h.watch(g, "/secret", "s");
    h.watch(g, "/local/domain/5/data", "d");
    h.watch(g, "@releaseDomain", "r");
    h.watch(a, "@releaseDomain", "r0");
    let fired = |h: &mut H, c: ConnId, t: MsgType, p: &[u8]| events(&h.raw(c, ty(t), 0, p));
    assert_eq!(
        fired(&mut h, a, MsgType::Write, b"/secret/x\0v"),
        [],
        "neither /secret/x nor /secret is readable"
    );
    assert_eq!(
        fired(&mut h, a, MsgType::Write, b"/local/domain/5/data/x\0v"),
        [ev(g, "/local/domain/5/data/x", "d")]
    );
    // Readable parent, unreadable node; then the reverse.
    h.ok(a, MsgType::SetPerms, 0, b"/secret\0n0\0r5\0");
    assert_eq!(
        fired(&mut h, a, MsgType::Write, b"/secret/x\0v"),
        [ev(g, "/secret/x", "s")]
    );
    assert_eq!(
        fired(&mut h, a, MsgType::Write, b"/secret/x/deep\0v"),
        [],
        "/secret/x and /secret/x/deep are closed"
    );
    h.ok(a, MsgType::SetPerms, 0, b"/secret/x/deep\0n0\0r5\0");
    assert_eq!(
        fired(&mut h, a, MsgType::Write, b"/secret/x/deep\0v"),
        [ev(g, "/secret/x/deep", "s")]
    );
    // SET_PERMS looks at the node before and after: taking access away fires.
    assert_eq!(
        fired(&mut h, a, MsgType::SetPerms, b"/secret/x/deep\0n0\0"),
        [ev(g, "/secret/x/deep", "s")]
    );
    assert_eq!(fired(&mut h, a, MsgType::SetPerms, b"/secret/x/deep\0n0\0"), []);
    // A removal fires the watches below with the permissions it removes.
    h.watch(g, "/secret/x/deep", "below");
    assert_eq!(
        fired(&mut h, a, MsgType::Rm, b"/secret/x\0"),
        [ev(g, "/secret/x", "s")],
        "not the watch on the closed node below"
    );
    // Special watches are checked against the special node.
    h.core.fire_special(b"@releaseDomain");
    assert_eq!(events(&h.drain()), [ev(a, "@releaseDomain", "r0")]);
    h.ok(a, MsgType::SetPerms, 0, b"@releaseDomain\0n0\0r5\0");
    h.drain();
    h.core.fire_special(b"@releaseDomain");
    assert_eq!(
        events(&h.drain()),
        [ev(a, "@releaseDomain", "r0"), ev(g, "@releaseDomain", "r")]
    );
}

#[test]
fn permission_checks_can_be_switched_off() {
    // perms-watch-activate off: every watch fires, even where there is
    // nothing to check (a change of the root).
    let (mut h, a, g) = with_guest(Config {
        perms_watch_activate: false,
        ..Config::default()
    });
    h.watch(g, "/", "root");
    assert_eq!(
        events(&h.raw(a, ty(MsgType::Write), 0, b"/secret\0v")),
        [ev(g, "/secret", "root")]
    );
    assert_eq!(events(&h.raw(a, ty(MsgType::Write), 0, b"/\0v")), [ev(g, "/", "root")]);
    assert_eq!(
        h.read(g, 0, "/secret"),
        Err("EACCES".into()),
        "requests are still checked"
    );
    // perms-activate off: requests are not checked, and a watch fires
    // wherever there is a node to check.
    let (mut h, a, g) = with_guest(Config {
        perms_activate: false,
        ..Config::default()
    });
    h.watch(g, "/", "root");
    h.write(g, 0, "/secret", "v");
    assert_eq!(h.read(g, 0, "/tool/xenstored").unwrap(), "rxenstored");
    assert_eq!(
        h.err(g, MsgType::SetPerms, 0, b"/secret\0n5\0"),
        "EACCES",
        "the owner still cannot change"
    );
    assert_eq!(
        events(&h.raw(a, ty(MsgType::Write), 0, b"/secret\0w")),
        [ev(g, "/secret", "root")]
    );
    assert_eq!(events(&h.raw(a, ty(MsgType::Write), 0, b"/\0v")), []);
    // By default a change of the root fires nothing, even for domain 0.
    let (mut h, a, _) = with_guest(Config::default());
    h.watch(a, "/", "root");
    assert_eq!(events(&h.raw(a, ty(MsgType::Write), 0, b"/\0v")), []);
}

#[test]
fn unknown_transaction_is_eio() {
    let mut h = H::new();
    let a = h.core.open();
    let r = h.call(a, MsgType::Read, 42, b"/\0");
    assert_eq!((r.0, r.2, r.3), (ty(MsgType::Error), 42, b"EIO\0".to_vec()));
    let r = h.call(a, MsgType::TransactionEnd, 42, b"T\0");
    assert_eq!(r.3, b"EIO\0");
    // Watches ignore the transaction id, even an unknown one; the reply has 0.
    let out = h.raw(a, ty(MsgType::Watch), 42, b"/w\0t\0");
    assert_eq!(out[0].1, (ty(MsgType::Watch), h.req, 0, b"OK\0".to_vec()));
    let r = h.call(a, MsgType::Unwatch, 42, b"/w\0t\0");
    assert_eq!((r.0, r.2), (ty(MsgType::Unwatch), 0));
}

#[test]
fn reset_watches_drops_watches_and_transactions() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/a", "t");
    let tx = h.start(a);
    assert_eq!((h.core.watches(), h.core.transactions(a)), (1, 1));
    assert_eq!(h.ok(a, MsgType::ResetWatches, 0, b"\0"), b"OK\0");
    assert_eq!((h.core.watches(), h.core.transactions(a)), (0, 0));
    assert_eq!(h.call(a, MsgType::Read, tx, b"/\0").3, b"EIO\0");
    assert!(events(&h.raw(a, ty(MsgType::Write), 0, &wr("/a", "1"))).is_empty());
}

#[test]
fn replies_are_in_request_order_for_pipelined_requests() {
    let mut h = H::new();
    let a = h.core.open();
    let mut bytes = Vec::new();
    for i in 0..50u32 {
        let m = Message::new(MsgType::Write, i, 0, wr(&format!("/p/{i}"), "x")).unwrap();
        m.encode_into(&mut bytes);
    }
    // Byte by byte.
    for b in &bytes {
        h.core.feed(a, std::slice::from_ref(b));
    }
    assert_eq!(h.core.process(a, 10), Status::More, "budget");
    assert_eq!(h.core.process(a, 100), Status::Idle);
    let out = h.drain();
    let ids: Vec<u32> = out.iter().map(|(_, m)| m.1).collect();
    assert_eq!(ids, (0..50).collect::<Vec<_>>());
    assert_eq!(h.ls(a, 0, "/p").len(), 50);
}

#[test]
fn oversized_request_kills_the_connection() {
    let mut h = H::new();
    let a = h.core.open();
    let mut bytes = Vec::new();
    write_header(&mut bytes, 2, 1, 0, 4097);
    h.core.feed(a, &bytes);
    assert_eq!(h.core.process(a, 10), Status::Closed);
    assert!(!h.core.wants_input(a));
    let mut dead = Vec::new();
    h.core.take_dead(&mut dead);
    assert_eq!(dead, [(a, GaveUp::Protocol)]);
    h.core.close(a);
    assert_eq!(h.core.connections(), 0);
    assert_eq!(h.core.process(a, 10), Status::Closed);
    h.core.feed(a, b"x");
    h.core.consume(a, 1);
    assert!(h.core.output(a).is_empty());
}

#[test]
fn large_replies_are_not_truncated_on_sockets() {
    let mut h = H::new();
    let a = h.core.open();
    for i in 0..400 {
        h.write(a, 0, &format!("/big/child-number-{i:05}"), "");
    }
    let r = h.one(a, MsgType::Directory, "/big");
    assert!(r.len() > 4096);
    assert_eq!(r.split(|c| *c == 0).filter(|s| !s.is_empty()).count(), 400);
}

// ---------------------------------------------------------------- watches

#[test]
fn watch_fires_once_on_registration() {
    let mut h = H::new();
    let a = h.core.open();
    assert_eq!(h.watch(a, "/nonexistent/x", "tok"), [ev(a, "/nonexistent/x", "tok")]);
    assert_eq!(h.watch(a, "rel/x", "tok"), [ev(a, "rel/x", "tok")]);
    assert_eq!(h.watch(a, "@introduceDomain", ""), [ev(a, "@introduceDomain", "")]);
    assert_eq!(h.watch(a, "@releaseDomain", "r"), [ev(a, "@releaseDomain", "r")]);
    assert_eq!(h.core.watches(), 4);
}

#[test]
fn watch_errors() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/a", "t");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"/a\0t\0"), "EEXIST");
    h.watch(a, "/local/domain/0/r", "t");
    h.watch(a, "/a", "u");
    // Relative and absolute spellings of the same path are one watch.
    assert_eq!(h.err(a, MsgType::Watch, 0, b"r\0t\0"), "EEXIST");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"/a\0t"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"/a\0t\0x\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"\0t\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"/a/\0t\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Watch, 0, b"/a b\0t\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Unwatch, 0, b"/a\0nope\0"), "ENOENT");
    assert_eq!(h.err(a, MsgType::Unwatch, 0, b"/zz\0t\0"), "ENOENT");
    assert_eq!(h.err(a, MsgType::Unwatch, 0, b"\0t\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Unwatch, 0, b"/a\0t"), "EINVAL");
    assert_eq!(
        h.ok(a, MsgType::Unwatch, 0, b"/local/domain/0/r\0t\0"),
        b"OK\0",
        "absolute spelling of a relative watch"
    );
    assert_eq!(h.ok(a, MsgType::Unwatch, 0, b"/a\0t\0"), b"OK\0");
    assert_eq!(h.err(a, MsgType::Unwatch, 0, b"/a\0t\0"), "ENOENT");
    // Another connection may use the same path and token.
    let b = h.core.open();
    h.watch(b, "/a", "u");
    assert_eq!(h.core.watches(), 2);
}

#[test]
fn write_fires_watches_on_the_node_and_its_ancestors() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(a, "/", "root");
    h.watch(a, "/x", "x");
    h.watch(b, "/x/y", "xy");
    h.watch(b, "/x/y/z", "deeper");
    h.watch(b, "/other", "other");
    let out = h.raw(a, ty(MsgType::Write), 0, &wr("/x/y", "1"));
    // The writer's reply comes before its events.
    assert_eq!(out[0], (a, (ty(MsgType::Write), h.req, 0, b"OK\0".to_vec())));
    assert_eq!(
        events(&out),
        [ev(a, "/x/y", "root"), ev(a, "/x/y", "x"), ev(b, "/x/y", "xy")]
    );
    // Events for implicitly created parents: only the written path.
    let out = h.raw(a, ty(MsgType::Write), 0, &wr("/x/p/q/r", "1"));
    assert_eq!(events(&out), [ev(a, "/x/p/q/r", "root"), ev(a, "/x/p/q/r", "x")]);
}

#[test]
fn every_kind_of_change_fires() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/w", "t");
    let e = |h: &mut H, t: MsgType, p: &[u8]| events(&h.raw(a, ty(t), 0, p));
    assert_eq!(e(&mut h, MsgType::Mkdir, b"/w/d\0"), [ev(a, "/w/d", "t")]);
    assert_eq!(e(&mut h, MsgType::Mkdir, b"/w/d\0"), [], "existing: nothing");
    assert_eq!(e(&mut h, MsgType::Write, b"/w/d\0v"), [ev(a, "/w/d", "t")]);
    assert_eq!(
        e(&mut h, MsgType::Write, b"/w/d\0v"),
        [ev(a, "/w/d", "t")],
        "same value fires too"
    );
    assert_eq!(e(&mut h, MsgType::SetPerms, b"/w/d\0n0\0"), [ev(a, "/w/d", "t")]);
    assert_eq!(e(&mut h, MsgType::Rm, b"/w/d\0"), [ev(a, "/w/d", "t")]);
    assert_eq!(e(&mut h, MsgType::Rm, b"/w/d\0"), [], "absent: nothing");
    assert_eq!(e(&mut h, MsgType::Read, b"/w\0"), []);
    assert_eq!(
        e(&mut h, MsgType::Write, &wr("/w/big", &"x".repeat(3000))),
        [],
        "failed write"
    );
}

#[test]
fn rm_fires_watches_below_with_their_own_path() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.write(a, 0, "/vm/1/a/b", "1");
    h.watch(a, "/vm/1/a/b", "ab");
    h.watch(b, "/vm/1/a/b/c/d", "deep-missing-parent");
    h.watch(b, "/vm/1/a/missing", "missing-leaf");
    h.watch(b, "/vm", "vm");
    h.watch(b, "/vm/2", "sibling");
    let out = h.raw(a, ty(MsgType::Rm), 0, b"/vm/1\0");
    assert_eq!(
        events(&out),
        [
            ev(a, "/vm/1/a/b", "ab"),
            ev(b, "/vm/1", "vm"),
            ev(b, "/vm/1/a/missing", "missing-leaf")
        ],
        "a watch whose parent did not exist does not fire (`ox/connection.ml:317-324`)"
    );
}

#[test]
fn rm_of_the_root_fires_watches_below_only() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/", "root");
    h.watch(a, "/local", "local");
    h.watch(a, "/local/x", "x");
    let out = h.raw(a, ty(MsgType::Rm), 0, b"/\0");
    assert_eq!(events(&out), [ev(a, "/local", "local"), ev(a, "/local/x", "x")]);
    // Changes to the root itself fire nothing.
    assert!(events(&h.raw(a, ty(MsgType::Write), 0, b"/\0v")).is_empty());
    assert!(events(&h.raw(a, ty(MsgType::Mkdir), 0, b"/\0")).is_empty());
    assert!(events(&h.raw(a, ty(MsgType::SetPerms), 0, b"/\0n0\0")).is_empty());
}

#[test]
fn relative_watches_get_relative_paths() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "device", "rel");
    h.watch(a, "/local/domain/0/device", "abs");
    let out = h.raw(a, ty(MsgType::Write), 0, &wr("device/vif/0", "1"));
    assert_eq!(
        events(&out),
        [
            ev(a, "/local/domain/0/device/vif/0", "abs"),
            ev(a, "device/vif/0", "rel")
        ]
    );
    h.watch(a, "device/vif", "relchild");
    let out = h.raw(a, ty(MsgType::Rm), 0, b"device\0");
    assert_eq!(
        events(&out),
        [
            ev(a, "/local/domain/0/device", "abs"),
            ev(a, "device", "rel"),
            ev(a, "device/vif", "relchild")
        ]
    );
}

#[test]
fn unwatch_stops_events_and_special_watches_ignore_the_tree() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/u", "t");
    h.watch(a, "@releaseDomain", "s");
    h.ok(a, MsgType::Unwatch, 0, b"/u\0t\0");
    assert!(events(&h.raw(a, ty(MsgType::Write), 0, &wr("/u", "1"))).is_empty());
    // Writing the special node fires watches on "/", not the special watch.
    assert!(events(&h.raw(a, ty(MsgType::Write), 0, b"@releaseDomain\0")).is_empty());
    h.core.fire_special(b"@releaseDomain");
    assert_eq!(events(&h.drain()), [ev(a, "@releaseDomain", "s")]);
    h.core.fire_special(b"@introduceDomain");
    assert!(h.drain().is_empty());
}

#[test]
fn closing_a_connection_removes_its_watches_and_transactions() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(a, "/c", "a");
    h.watch(a, "@introduceDomain", "a");
    h.watch(b, "/c", "b");
    let tx = h.start(a);
    h.write(a, tx, "/c/x", "1");
    h.core.close(a);
    assert_eq!(h.core.watches(), 1);
    let out = h.raw(b, ty(MsgType::Write), 0, &wr("/c", "1"));
    assert_eq!(events(&out), [ev(b, "/c", "b")]);
    assert_eq!(
        h.read(b, 0, "/c/x"),
        Err("ENOENT".into()),
        "the transaction was dropped"
    );
    assert_eq!(h.core.connections(), 1);
}

#[test]
fn a_closed_connection_is_forgotten() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(b, "/x", "t");
    h.write(a, 0, "/x", "1");
    // Output queued for a connection that is closed before it is collected.
    h.core.feed(a, &{
        let mut m = Vec::new();
        write_header(&mut m, ty(MsgType::Write), 1, 0, 4);
        m.extend_from_slice(b"/x\x002");
        m
    });
    assert_eq!(h.core.process(a, 10), Status::Idle);
    h.core.close(b);
    let mut dirty = Vec::new();
    h.core.take_dirty(&mut dirty);
    assert_eq!(dirty, [a]);
    assert_eq!(h.core.output(b), b"");
    h.core.consume(b, 10);
    // Closing again, or feeding it, does nothing.
    h.core.close(b);
    h.core.feed(b, b"junk");
    assert_eq!(h.core.process(b, 10), Status::Closed);
    assert!(!h.core.wants_input(b));
    assert_eq!(h.core.connections(), 1);
}

#[test]
fn a_special_watch_survives_the_removal_of_its_node() {
    // Then only the root's permissions are left to check.
    let mut h = H::new();
    let a = h.core.open();
    let g = h.core.open_domain(5);
    h.watch(a, "@releaseDomain", "a");
    h.watch(g, "@releaseDomain", "g");
    h.one(a, MsgType::Rm, "@releaseDomain");
    h.drain();
    h.core.fire_special(b"@releaseDomain");
    assert_eq!(events(&h.drain()), [ev(a, "@releaseDomain", "a")]);
    h.ok(a, MsgType::SetPerms, 0, b"/\0n0\0r5\0");
    h.drain();
    h.core.fire_special(b"@releaseDomain");
    assert_eq!(
        events(&h.drain()),
        [ev(a, "@releaseDomain", "a"), ev(g, "@releaseDomain", "g")]
    );
}

#[test]
fn watch_index_cleans_up_on_close() {
    let mut h = H::new();
    let a = h.core.open();
    for i in 0..100 {
        h.watch(a, &format!("/x/{i}/y"), "t");
    }
    h.core.close(a);
    assert_eq!(h.core.index.trie_size(), 1);
}

// ---------------------------------------------------------------- transactions

#[test]
fn transaction_isolation() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.write(a, 0, "/t/v", "0");
    let tx = h.start(a);
    assert_eq!(tx, 1);
    h.write(a, tx, "/t/v", "1");
    h.write(a, tx, "/t/new", "n");
    assert_eq!(h.read(a, tx, "/t/v").unwrap(), "1");
    assert_eq!(h.ls(a, tx, "/t"), ["new", "v"]);
    assert_eq!(h.read(b, 0, "/t/v").unwrap(), "0", "not visible outside");
    assert_eq!(h.read(a, 0, "/t/new"), Err("ENOENT".into()));
    h.end(a, tx, true).unwrap();
    assert_eq!(h.read(b, 0, "/t/v").unwrap(), "1");
    assert_eq!(h.ls(b, 0, "/t"), ["new", "v"]);
    // Changes made outside after the start are not visible inside.
    let tx = h.start(a);
    h.write(b, 0, "/t/outside", "o");
    h.write(b, 0, "/t/v", "2");
    assert_eq!(h.read(a, tx, "/t/outside"), Err("ENOENT".into()));
    assert_eq!(h.read(a, tx, "/t/v").unwrap(), "1");
    assert_eq!(h.ls(a, tx, "/t"), ["new", "v"]);
    h.end(a, tx, false).unwrap();
}

#[test]
fn abort_discards() {
    let mut h = H::new();
    let a = h.core.open();
    let tx = h.start(a);
    h.write(a, tx, "/gone", "1");
    h.end(a, tx, false).unwrap();
    assert_eq!(h.read(a, 0, "/gone"), Err("ENOENT".into()));
    assert_eq!(h.end(a, tx, true), Err("EIO".into()), "the id is no longer valid");
}

#[test]
fn transaction_end_errors() {
    let mut h = H::new();
    let a = h.core.open();
    let tx = h.start(a);
    assert_eq!(h.err(a, MsgType::TransactionEnd, tx, b"X\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::TransactionEnd, tx, b""), "EINVAL");
    assert_eq!(h.core.transactions(a), 1, "a malformed end leaves the transaction open");
    assert_eq!(h.err(a, MsgType::TransactionEnd, 0, b"T\0"), "ENOENT");
    assert_eq!(
        h.ok(a, MsgType::TransactionEnd, tx, b"T"),
        b"OK\0",
        "the NUL is optional"
    );
    let tx = h.start(a);
    assert_eq!(h.err(a, MsgType::TransactionStart, tx, b"\0"), "EBUSY");
}

#[test]
fn transaction_ids_are_per_connection_and_skip_open_ones() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    assert_eq!(h.start(a), 1);
    assert_eq!(h.start(a), 2);
    assert_eq!(h.start(b), 1);
    h.end(a, 1, false).unwrap();
    assert_eq!(h.start(a), 3);
    h.core.conns.map.get_mut(&a).unwrap().next_tid = 0x3fff_ffff;
    assert_eq!(h.start(a), 1, "wraps and reuses a free id");
    assert_eq!(h.start(a), 4, "skips the open ones");
}

#[test]
fn conflicting_commit_gets_eagain() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.write(a, 0, "/c/v", "0");
    let tx = h.start(a);
    assert_eq!(h.read(a, tx, "/c/v").unwrap(), "0");
    h.write(a, tx, "/c/w", "1");
    h.write(b, 0, "/c/v", "changed");
    assert_eq!(h.end(a, tx, true), Err("EAGAIN".into()));
    assert_eq!(h.read(a, 0, "/c/w"), Err("ENOENT".into()), "nothing applied");
    assert_eq!(h.core.transactions(a), 0, "the transaction is gone");
}

#[test]
fn conflicts_are_detected_for_every_kind_of_read() {
    type Setup = fn(&mut H, ConnId, u32);
    let cases: [(&str, Setup, Setup); 6] = [
        (
            "directory",
            |h, a, t| drop(h.ls(a, t, "/c")),
            |h, b, _| h.write(b, 0, "/c/new", ""),
        ),
        (
            "getperms",
            |h, a, t| drop(h.ok(a, MsgType::GetPerms, t, b"/c\0")),
            |h, b, _| drop(h.ok(b, MsgType::SetPerms, 0, b"/c\0r0\0")),
        ),
        (
            "read of absent",
            |h, a, t| assert!(h.read(a, t, "/c/none").is_err()),
            |h, b, _| h.write(b, 0, "/c/none", ""),
        ),
        (
            "read then removed",
            |h, a, t| drop(h.read(a, t, "/c")),
            |h, b, _| drop(h.one(b, MsgType::Rm, "/c")),
        ),
        (
            "rm whose parent disappears",
            |h, a, t| drop(h.ok(a, MsgType::Rm, t, b"/c/x\0")),
            |h, b, _| drop(h.one(b, MsgType::Rm, "/c")),
        ),
        (
            "setperms on a node that disappears",
            |h, a, t| drop(h.ok(a, MsgType::SetPerms, t, b"/c\0b0\0")),
            |h, b, _| drop(h.one(b, MsgType::Rm, "/c")),
        ),
    ];
    for (name, inside, outside) in cases {
        let mut h = H::new();
        let (a, b) = (h.core.open(), h.core.open());
        h.write(a, 0, "/c", "");
        let tx = h.start(a);
        inside(&mut h, a, tx);
        h.write(a, tx, "/elsewhere", "x");
        outside(&mut h, b, tx);
        assert_eq!(h.end(a, tx, true), Err("EAGAIN".into()), "{name}");
    }
}

#[test]
fn disjoint_transactions_both_commit() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/local/domain/1", "");
    h.write(a, 0, "/local/domain/2", "");
    let t1 = h.start(a);
    let t2 = h.start(a);
    // Same parent, different children; reads of unrelated nodes.
    h.write(a, t1, "/local/domain/1/name", "one");
    assert_eq!(h.read(a, t1, "/local/domain/1/name").unwrap(), "one");
    h.write(a, t1, "/vm/u1/name", "one");
    h.write(a, t2, "/local/domain/2/name", "two");
    h.write(a, t2, "/vm/u2/name", "two");
    h.ok(a, MsgType::Mkdir, t2, b"/local/domain/3\0");
    h.end(a, t1, true).unwrap();
    // Meanwhile a direct write elsewhere.
    h.write(a, 0, "/local/domain/1/other", "x");
    h.end(a, t2, true).unwrap();
    assert_eq!(h.ls(a, 0, "/vm"), ["u1", "u2"]);
    assert_eq!(h.ls(a, 0, "/local/domain"), ["1", "2", "3"]);
    assert_eq!(h.read(a, 0, "/local/domain/2/name").unwrap(), "two");
}

#[test]
fn blind_writes_to_the_same_node_do_not_conflict() {
    // As in oxenstored, whose replay compares replies: a write always answers OK.
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    let tx = h.start(a);
    h.write(a, tx, "/s", "inside");
    h.write(b, 0, "/s", "outside");
    h.end(a, tx, true).unwrap();
    assert_eq!(h.read(a, 0, "/s").unwrap(), "inside");
}

#[test]
fn rereading_own_writes_after_a_concurrent_commit() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    let tx = h.start(a);
    h.write(a, tx, "/o/x", "mine");
    assert_eq!(h.read(a, tx, "/o/x").unwrap(), "mine");
    assert_eq!(h.ls(a, tx, "/o"), ["x"]);
    h.write(b, 0, "/unrelated", "1");
    h.end(a, tx, true).unwrap();
    // But a concurrent sibling makes the directory listing differ.
    let tx = h.start(a);
    h.write(a, tx, "/o/y", "mine");
    assert_eq!(h.ls(a, tx, "/o"), ["x", "y"]);
    h.write(b, 0, "/o/z", "theirs");
    assert_eq!(h.end(a, tx, true), Err("EAGAIN".into()));
}

#[test]
fn read_only_transactions_always_succeed() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.write(a, 0, "/r", "0");
    let tx = h.start(a);
    h.read(a, tx, "/r").unwrap();
    h.write(b, 0, "/r", "1");
    h.end(a, tx, true).unwrap();
    // Requests that change nothing make a transaction read-only too.
    let tx = h.start(a);
    h.read(a, tx, "/r").unwrap();
    h.ok(a, MsgType::Rm, tx, b"/absent\0");
    h.ok(a, MsgType::Mkdir, tx, b"/r\0");
    h.write(b, 0, "/r", "2");
    h.end(a, tx, true).unwrap();
    // A failed oversized write creates parents only in the transaction's
    // copy, which is then discarded.
    let tx = h.start(a);
    assert_eq!(h.err(a, MsgType::Write, tx, &wr("/p/q/r", &"x".repeat(3000))), "E2BIG");
    assert_eq!(h.ls(a, tx, "/p"), ["q"]);
    h.end(a, tx, true).unwrap();
    assert_eq!(h.read(a, 0, "/p"), Err("ENOENT".into()));
}

#[test]
fn errors_inside_a_transaction_are_part_of_it() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    let tx = h.start(a);
    assert_eq!(h.err(a, MsgType::Rm, tx, b"/m/x/y\0"), "ENOENT");
    assert_eq!(h.err(a, MsgType::Read, tx, b"/bad path\0"), "EINVAL");
    h.write(a, tx, "/k", "1");
    h.write(b, 0, "/m/x", "");
    assert_eq!(h.end(a, tx, true), Err("EAGAIN".into()), "the rm would now succeed");
}

#[test]
fn transaction_events_fire_at_commit_only() {
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(b, "/e", "t");
    let tx = h.start(a);
    let out = h.raw(a, ty(MsgType::Write), tx, &wr("/e/1", "x"));
    assert!(events(&out).is_empty());
    let out = h.raw(a, ty(MsgType::Rm), tx, b"/e/1\0");
    assert!(events(&out).is_empty());
    h.write(a, tx, "/e/2", "x");
    h.ok(a, MsgType::SetPerms, tx, b"/e/2\0b0\0");
    let out = h.raw(a, ty(MsgType::TransactionEnd), tx, b"T\0");
    // The removal is checked against the store before the transaction,
    // where /e/1 and /e are not: it fires nothing (`4.17 ox/process.ml:60-72`,
    // `ox/connection.ml:319-326`).
    assert_eq!(
        events(&out),
        [ev(b, "/e/1", "t"), ev(b, "/e/2", "t"), ev(b, "/e/2", "t")]
    );
    // Same through the re-execution path.
    let tx = h.start(a);
    h.write(a, tx, "/e/3", "x");
    h.write(a, 0, "/other", "1");
    let out = h.raw(a, ty(MsgType::TransactionEnd), tx, b"T\0");
    assert_eq!(events(&out), [ev(b, "/e/3", "t")]);
    // An aborted or failed transaction fires nothing.
    let tx = h.start(a);
    h.write(a, tx, "/e/4", "x");
    assert!(events(&h.raw(a, ty(MsgType::TransactionEnd), tx, b"F\0")).is_empty());
}

#[test]
fn commit_events_come_before_the_reply() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "/o", "t");
    let tx = h.start(a);
    h.write(a, tx, "/o", "x");
    let out = h.raw(a, ty(MsgType::TransactionEnd), tx, b"T\0");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].1 .0, ty(MsgType::WatchEvent));
    assert_eq!(out[1].1 .0, ty(MsgType::TransactionEnd));
}

#[test]
fn one_change_fires_a_connection_s_watches_root_first_each_path_s_newest_first() {
    // `ox/connections.ml:138, 165`, `ox/trie.ml:129-137`.
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(a, "/x/y", "node-old");
    h.watch(b, "/x/y", "other");
    h.watch(a, "/x", "parent");
    h.watch(a, "/x/y", "node-new");
    h.watch(a, "/", "root");
    h.watch(a, "/x/y/z", "below");
    let out = h.raw(b, ty(MsgType::Write), 0, &wr("/x/y", "1"));
    assert_eq!(tokens_of(&out, a), ["root", "parent", "node-new", "node-old"]);
    assert_eq!(tokens_of(&out, b), ["other"]);
    // A watch registered again is the newest.
    h.ok(a, MsgType::Unwatch, 0, b"/x/y\0node-old\0");
    h.watch(a, "/x/y", "node-old");
    let out = h.raw(b, ty(MsgType::Write), 0, &wr("/x/y", "2"));
    assert_eq!(tokens_of(&out, a), ["root", "parent", "node-old", "node-new"]);
    // So are a removal's, and a relative watch's.
    h.watch(a, "/local/domain/0/r", "abs");
    h.watch(a, "r", "rel");
    let out = h.raw(b, ty(MsgType::Rm), 0, b"/x\0");
    assert_eq!(tokens_of(&out, a), ["root", "parent", "node-old", "node-new", "below"]);
    let out = h.raw(b, ty(MsgType::Write), 0, &wr("/local/domain/0/r/s", "1"));
    assert_eq!(
        events_of(&out, a),
        [
            ("/local/domain/0/r/s".to_string(), "root".to_string()),
            ("r/s".to_string(), "rel".to_string()),
            ("/local/domain/0/r/s".to_string(), "abs".to_string())
        ]
    );
}

#[test]
fn an_rm_fires_the_watches_below_by_name_each_node_before_what_is_below_it() {
    // `ox/connections.ml:167`, `ox/trie.ml:73-78`: names in byte order.
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    for p in ["/s/b", "/s/B", "/s/10", "/s/9", "/s/a-", "/s/a/x"] {
        h.write(a, 0, p, "v");
    }
    for (p, t) in [
        ("/s/b", "b"),
        ("/s/a/x", "a/x"),
        ("/s/B", "B"),
        ("/s/a-", "a-"),
        ("/s/9", "9"),
        ("/s/a", "a"),
        ("/s/10", "10"),
        ("/s/a", "a-new"),
        ("/s/q/r/s/t", "missing parent"),
        ("/s/q/r/u", "missing parent too"),
        ("/s/q", "q"),
        ("/s", "s"),
    ] {
        h.watch(a, p, t);
    }
    h.watch(b, "/s/a/x", "other");
    let order = ["s", "10", "9", "B", "a-new", "a", "a/x", "a-", "b", "q"];
    let out = h.raw(b, ty(MsgType::Rm), 0, b"/s\0");
    assert_eq!(tokens_of(&out, a), order);
    assert_eq!(tokens_of(&out, b), ["other"]);
    // The same at a commit, after the events of the requests before (a
    // WRITE below the node it then removes: checked against the store
    // after the commit, where its parent is gone, it fires nothing).
    for p in ["/s/b", "/s/B", "/s/10", "/s/9", "/s/a-", "/s/a/x"] {
        h.write(a, 0, p, "v");
    }
    let tx = h.start(b);
    h.write(b, tx, "/s/9", "w");
    h.write(b, tx, "/s/10/y", "w");
    h.ok(b, MsgType::Rm, tx, b"/s/10/y\0");
    h.ok(b, MsgType::Rm, tx, b"/s\0");
    let out = h.raw(b, ty(MsgType::TransactionEnd), tx, b"T\0");
    assert_eq!(tokens_of(&out, a)[..2], ["s", "10"], "the RM of /s/10/y");
    assert_eq!(tokens_of(&out, a)[2..], order);
}

#[test]
fn a_commit_fires_for_each_request_that_changed_the_transaction_when_it_ran() {
    // `ox/process.ml:60-72, 567`: the paths the transaction recorded as its
    // requests ran (`ox/transaction.ml:147`), whatever running them again
    // at the commit changes.
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.write(a, 0, "/e/old", "v");
    h.write(a, 0, "/e/there", "v");
    h.watch(b, "/e", "t");
    let tx = h.start(a);
    h.ok(a, MsgType::Mkdir, tx, b"/e/made\0");
    h.ok(a, MsgType::Rm, tx, b"/e/old\0");
    // Changes nothing: no event, now or at the commit.
    h.ok(a, MsgType::Mkdir, tx, b"/e/there\0");
    h.ok(a, MsgType::Rm, tx, b"/e/never\0");
    // Twice, the same value: twice.
    h.write(a, tx, "/e/w", "1");
    h.write(a, tx, "/e/w", "1");
    // Meanwhile another connection makes what the MKDIR made, removes
    // what the RM removed and what the other MKDIR found: run again, the
    // first two change nothing and the third makes its node.
    h.write(b, 0, "/e/made", "v");
    h.ok(b, MsgType::Rm, 0, b"/e/old\0");
    h.ok(b, MsgType::Rm, 0, b"/e/there\0");
    h.drain();
    let out = h.raw(a, ty(MsgType::TransactionEnd), tx, b"T\0");
    assert_eq!(out.last().unwrap().1 .3, b"OK\0");
    let paths: Vec<String> = events_of(&out, b).into_iter().map(|e| e.0).collect();
    assert_eq!(paths, ["/e/made", "/e/old", "/e/w", "/e/w"]);
    assert_eq!(h.read(a, 0, "/e/there"), Ok(String::new()), "made again, unannounced");
}

#[test]
fn the_watches_of_a_special_path_fire_newest_first() {
    // `ox/connections.ml:174-177`, `ox/connection.ml:287`.
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    h.watch(a, "@releaseDomain", "old");
    h.watch(b, "@releaseDomain", "other");
    h.watch(a, "@releaseDomain", "new");
    h.drain();
    h.core.fire_special(b"@releaseDomain");
    let out = h.drain();
    assert_eq!(tokens_of(&out, a), ["new", "old"]);
    assert_eq!(tokens_of(&out, b), ["other"]);
}

#[test]
fn a_commit_fires_at_most_one_change_per_request_and_holds_its_source_as_one_request() {
    // A guest's commit of n requests fires at most n changes, each the
    // watches on its path and its ancestors (and, for an RM, below): a
    // guest watcher gets twice `watch_event_max` events, the rest are
    // dropped; domain 0 gets every one; the guest is held until both read.
    let (mut h, tool, g) = with_guest(Config {
        watch_event_max: 4,
        request_max: Some(50),
        ..Config::default()
    });
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0");
    let sink = h.core.open_domain(6);
    h.watch(sink, "/local/domain/5/data", "w");
    h.watch(tool, "/local/domain/5/data", "t");
    h.drain();
    let tx = h.start(g);
    // 49 requests, and the TRANSACTION_END: `request_max`.
    for i in 0..49 {
        h.write(g, tx, "data/x", &i.to_string());
    }
    // Run again at the commit: the events are the requests' all the same.
    h.write(tool, 0, "/elsewhere", "v");
    h.drain();
    h.push(g, ty(MsgType::TransactionEnd), tx, b"T\0");
    assert_eq!(h.core.process(g, 10), Status::Blocked);
    assert_eq!(h.core.conns.map[&sink].out.events, 8);
    assert_eq!(h.core.conns.map[&tool].out.events, 49);
    assert_eq!(h.core.conns.dropped, 41);
    assert_eq!(h.core.conns.map[&g].holds, 2);
    h.drain_one(sink);
    assert!(!h.core.wants_input(g), "one to go");
    h.drain_one(tool);
    assert!(h.core.wants_input(g));
}

#[test]
fn transaction_start_is_constant_time() {
    // Many open transactions on a large store: each start only takes a pointer.
    let mut h = H::new();
    let a = h.core.open();
    for i in 0..2000 {
        h.write(a, 0, &format!("/n/{i}"), "v");
    }
    let before = Arc::strong_count(&h.core.root);
    for _ in 0..100 {
        h.start(a);
    }
    assert_eq!(Arc::strong_count(&h.core.root), before + 200);
}

// ---------------------------------------------------------------- output limits

#[test]
fn a_slow_reader_stops_its_own_requests_then_a_guest_is_dropped_and_domain_0_is_not() {
    for guest in [true, false] {
        let (mut h, writer, g) = with_guest(Config {
            output_soft_limit: 1000,
            output_hard_limit: 5000,
            ..Config::default()
        });
        // A guest, or a socket (domain 0), that watches and never reads.
        let slow = if guest { g } else { h.core.open() };
        h.raw(slow, ty(MsgType::Watch), 0, b"/local/domain/5/s\0t\0");
        // The writer (a socket: domain 0, never held) is drained.
        let mut dirty = Vec::new();
        for i in 0..300 {
            let mut bytes = Vec::new();
            write_header(&mut bytes, ty(MsgType::Write), i, 0, 20);
            bytes.extend_from_slice(b"/local/domain/5/s\0vv");
            h.core.feed(writer, &bytes);
            assert_eq!(h.core.process(writer, 10), Status::Idle, "the writer is never blocked");
            let n = h.core.output(writer).len();
            h.core.consume(writer, n);
            h.core.take_dirty(&mut dirty);
            if i == 30 {
                assert!(!h.core.wants_input(slow), "above the soft limit");
                let mut d = Vec::new();
                h.core.take_dead(&mut d);
                assert!(d.is_empty());
            }
        }
        let mut bytes = Vec::new();
        write_header(&mut bytes, ty(MsgType::Read), 1, 0, 2);
        bytes.extend_from_slice(b"s\0");
        h.core.feed(slow, &bytes);
        let mut dead = Vec::new();
        h.core.take_dead(&mut dead);
        if guest {
            assert_eq!(dead, [(slow, GaveUp::Overflow)], "over the hard limit");
            assert_eq!(h.core.process(slow, 10), Status::Closed);
            assert!(h.core.output(slow).len() <= 5000);
        } else {
            // Domain 0 is never given up on for what it is owed
            // (oxenstored closes none of its connections): it is only
            // stopped from asking for more until it reads.
            assert_eq!(dead, [], "domain 0");
            assert!(h.core.output(slow).len() > 5000);
            assert_eq!(h.core.process(slow, 10), Status::Blocked);
            let n = h.core.output(slow).len();
            h.core.consume(slow, n);
            assert_eq!(h.core.process(slow, 10), Status::Idle);
            assert_eq!(h.drain_one(slow).len(), 1, "the READ is answered");
        }
        h.core.audit().unwrap();
    }
}

#[test]
fn soft_limit_blocks_until_drained() {
    let mut h = H::with(Config {
        output_soft_limit: 100,
        ..Config::default()
    });
    let a = h.core.open();
    let mut bytes = Vec::new();
    for i in 0..20 {
        write_header(&mut bytes, ty(MsgType::Read), i, 0, 15);
        bytes.extend_from_slice(b"/tool/xenstored\0"[..15].as_ref());
    }
    h.core.feed(a, &bytes);
    assert_eq!(h.core.process(a, 100), Status::Blocked);
    assert!(!h.core.wants_input(a));
    let n = h.core.output(a).len();
    assert!((100..200).contains(&n));
    h.core.consume(a, n);
    assert!(h.core.wants_input(a));
    let mut total = 0;
    loop {
        let st = h.core.process(a, 100);
        let n = h.core.output(a).len();
        total += n;
        h.core.consume(a, n);
        if st == Status::Idle {
            break;
        }
    }
    assert!(total > 0);
}

#[test]
fn output_buffer_compacts() {
    let mut b = OutBuf::default();
    b.buf.extend(std::iter::repeat_n(1u8, 200 << 10));
    b.consume(100 << 10);
    assert_eq!(b.len(), 100 << 10);
    b.consume(1 << 10);
    assert_eq!(b.pos, 0, "compacted");
    assert_eq!(b.len(), 99 << 10);
    b.consume(usize::MAX / 2);
    assert_eq!(b.len(), 0);
    let mut big = OutBuf::default();
    big.buf.extend(std::iter::repeat_n(1u8, 2 << 20));
    big.consume(2 << 20);
    assert!(big.buf.capacity() <= 1 << 20);
    assert!(big.buf.capacity() >= 64 << 10, "64 KiB are kept");
}

#[test]
fn output_buffer_thresholds() {
    // Compaction needs more than 64 KiB sent...
    let mut b = OutBuf::default();
    b.buf.extend(std::iter::repeat_n(1u8, 1000));
    b.consume(600);
    assert_eq!((b.pos, b.len()), (600, 400), "a small buffer is not moved");
    let mut b = OutBuf::default();
    b.buf.extend(std::iter::repeat_n(1u8, 100 << 10));
    b.consume(64 << 10);
    assert_eq!((b.pos, b.len()), (64 << 10, 36 << 10), "64 KiB exactly: not yet");
    b.consume(1);
    assert_eq!((b.pos, b.len()), (0, (36 << 10) - 1));
    // ... and an emptied buffer keeps up to 1 MiB.
    let mut b = OutBuf {
        buf: Vec::with_capacity(1 << 20),
        ..OutBuf::default()
    };
    b.buf.extend(std::iter::repeat_n(1u8, 1 << 20));
    assert_eq!(b.buf.capacity(), 1 << 20);
    b.consume(1 << 20);
    assert_eq!((b.pos, b.len(), b.buf.capacity()), (0, 0, 1 << 20));
}

#[test]
fn output_limits_are_exact() {
    // The reply to a READ of 100 bytes is 116 bytes.
    let (mut h, a, g) = with_guest(Config {
        output_soft_limit: 116,
        output_hard_limit: 116,
        ..Config::default()
    });
    // Its home is the guest's: `v` is `/local/domain/5/v` for both.
    h.core.conns.map.get_mut(&a).unwrap().home = Arc::from(&b"/local/domain/5/"[..]);
    let mut read = Vec::new();
    write_header(&mut read, ty(MsgType::Read), 1, 0, 2);
    read.extend_from_slice(b"v\0");
    h.write(a, 0, "/local/domain/5/v", &"x".repeat(100));
    h.core.feed(g, &read);
    h.core.process(g, 10);
    assert_eq!(h.core.output(g).len(), 116, "the hard limit can be reached");
    assert!(!h.core.wants_input(g), "at the soft limit");
    h.core.consume(g, 1);
    assert!(h.core.wants_input(g), "below it");
    h.core.consume(g, 115);
    let mut dead = Vec::new();
    h.core.take_dead(&mut dead);
    assert!(dead.is_empty());
    // One byte more: a guest is given up on, domain 0 is not.
    h.write(a, 0, "/local/domain/5/v", &"x".repeat(101));
    for c in [a, g] {
        let len = h.core.output(c).len();
        h.core.consume(c, len);
        h.core.feed(c, &read);
        h.core.process(c, 10);
    }
    h.core.take_dead(&mut dead);
    assert_eq!(dead, [(g, GaveUp::Overflow)], "over the hard limit");
    assert!(h.core.output(g).is_empty());
    assert_eq!(h.core.output(a).len(), 117);
}

#[test]
fn parse_absolute_helper() {
    assert_eq!(parse_absolute("/a/b").unwrap().len(), 2);
    assert!(parse_absolute("a").is_err());
}

// ---------------------------------------------------------------- domains

#[test]
fn introduce_creates_a_guest_connection_confined_by_permissions() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "@introduceDomain", "i");
    h.one(a, MsgType::Mkdir, "/local/domain/5");
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0");
    let out = h.raw(a, ty(MsgType::Introduce), 0, b"5\x00123\x009\0");
    // Fired by the request, before its reply is queued (`ox/process.ml:383-388, 602-607`).
    assert_eq!(
        out,
        [
            (a, (ty(MsgType::WatchEvent), 0, 0, b"@introduceDomain\0i\0".to_vec())),
            (a, (ty(MsgType::Introduce), h.req, 0, b"OK\0".to_vec()))
        ]
    );
    let g = h.core.domain_conn(5).unwrap();
    assert_eq!(g, ConnId(a.0 + 1));
    assert_eq!(
        h.calls(),
        [Call::Connect(g, 5, 123, 9)],
        "with the id the connection got"
    );
    assert_eq!(h.core.domains().collect::<Vec<_>>(), [(5, g)]);
    // A guest: its home and its own nodes, nothing else.
    h.write(g, 0, "data/x", "1");
    assert_eq!(h.read(a, 0, "/local/domain/5/data/x").unwrap(), "1");
    assert_eq!(h.one(g, MsgType::GetPerms, "data/x"), b"n5\0");
    assert_eq!(h.read(g, 0, "/tool/xenstored"), Err("EACCES".into()));
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("/local/domain/0/x", "1")), "EACCES");
    // None of the domain requests, whatever the payload (`ox/process.ml:338-340, 585-587, 612-614, 628-630`).
    let domain_requests = [
        MsgType::Introduce,
        MsgType::Release,
        MsgType::IsDomainIntroduced,
        MsgType::Resume,
        MsgType::SetTarget,
    ];
    for t in domain_requests {
        assert_eq!(h.err(g, t, 0, b"6\x001\x001\0"), "EACCES", "{t:?}");
        assert_eq!(h.err(g, t, 0, b"junk"), "EACCES", "{t:?}");
    }
    assert!(h.calls().is_empty());
    // Its watch on @introduceDomain fires only if it may read the node.
    h.watch(g, "@introduceDomain", "g");
    assert_eq!(
        events(&h.raw(a, ty(MsgType::Introduce), 0, b"6\x001\x001\0")),
        [ev(a, "@introduceDomain", "i")]
    );
    h.ok(a, MsgType::SetPerms, 0, b"@introduceDomain\0n0\0r5\0");
    assert_eq!(
        events(&h.raw(a, ty(MsgType::Introduce), 0, b"7\x001\x001\0")),
        [ev(a, "@introduceDomain", "i"), ev(g, "@introduceDomain", "g")]
    );
}

#[test]
fn introduce_reads_its_numbers_as_oxenstored() {
    let mut h = H::new();
    let a = h.core.open();
    for (p, want) in [
        (&b""[..], "EINVAL"),
        (b"5\x001\0", "EINVAL"),
        (b"5\x001\0x\0", "EINVAL"),
        // `Nativeint.of_string` fails with its own message, which escapes
        // the error mapping (`ox/process.ml:588-593, 737-740`).
        (b"5\0x\x001\0", "EIO"),
        (b"5\x0099999999999999999999\x001\0", "EIO"),
        // The tuple is evaluated right to left: port, frame, domid.
        (b"5\0x\0y\0", "EINVAL"),
        (b"z\0x\x001\0", "EIO"),
        (b"z\x001\x001\0", "EINVAL"),
        // Numbers that are no domid, or no port, cannot be mapped or bound.
        (b"-1\x001\x001\0", "EINVAL"),
        (b"4294967296\x001\x001\0", "EINVAL"),
        (b"5\x001\0-1\0", "EINVAL"),
        (b"5\x001\x004294967296\0", "EINVAL"),
    ] {
        assert_eq!(h.err(a, MsgType::Introduce, 0, p), want, "{p:?}");
    }
    assert!(h.calls().is_empty(), "the machine is not asked");
    assert_eq!((h.core.connections(), h.core.domains().count()), (1, 0));
    // OCaml's syntax; no final NUL needed, extra fields ignored; the frame
    // is a nativeint.
    assert_eq!(h.ok(a, MsgType::Introduce, 0, b"0x5\x000x1_0\0+3"), b"OK\0");
    assert_eq!(h.calls(), [Call::Connect(h.core.domain_conn(5).unwrap(), 5, 16, 3)]);
    assert_eq!(h.ok(a, MsgType::Introduce, 0, b"6\0-1\x004\0junk\0"), b"OK\0");
    assert_eq!(
        h.calls(),
        [Call::Connect(h.core.domain_conn(6).unwrap(), 6, u64::MAX, 4)]
    );
}

#[test]
fn a_failed_introduce_creates_nothing() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "@introduceDomain", "i");
    h.machine.fail = Some(Errno::ENOMEM);
    let out = h.raw(a, ty(MsgType::Introduce), 0, b"5\x001\x002\0");
    assert_eq!(
        out,
        [(a, (ty(MsgType::Error), h.req, 0, b"ENOMEM\0".to_vec()))],
        "and fires nothing"
    );
    let tried = ConnId(a.0 + 1);
    assert_eq!(h.calls(), [Call::Connect(tried, 5, 1, 2)]);
    assert_eq!((h.core.connections(), h.core.domain_conn(5)), (1, None));
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"5\0"), b"F\0");
    // The id was not used up.
    h.machine.fail = None;
    assert_eq!(h.introduce(a, 5, 1, 2), tried);
    assert_eq!(h.core.open(), ConnId(tried.0 + 1));
}

#[test]
fn without_a_machine_introduce_fails_as_when_oxenstored_cannot_map_or_bind() {
    let mut h = H::new();
    let a = h.core.open();
    let g = h.core.open_domain(5);
    let req = |h: &mut H, t: MsgType, p: &[u8]| {
        let mut b = Vec::new();
        write_header(&mut b, ty(t), 1, 0, p.len() as u32);
        b.extend_from_slice(p);
        h.core.feed(a, &b);
        assert_eq!(h.core.process(a, 10), Status::Idle);
        h.drain().pop().unwrap().1 .3
    };
    assert_eq!(
        req(&mut h, MsgType::Introduce, b"6\x001\x001\0"),
        b"EINVAL\0",
        "mapping"
    );
    assert_eq!(
        req(&mut h, MsgType::Introduce, b"5\x000\x001\0"),
        b"EIO\0",
        "binding again"
    );
    assert_eq!(
        req(&mut h, MsgType::Introduce, b"5\x007\x001\0"),
        b"EINVAL\0",
        "another ring"
    );
    assert_eq!(req(&mut h, MsgType::Release, b"5\0"), b"OK\0");
    assert_eq!(h.core.connections(), 1);
    assert_eq!(h.core.process(g, 1), Status::Closed);
}

#[test]
fn introducing_a_known_domain_binds_its_event_channel_again() {
    let mut h = H::new();
    let a = h.core.open();
    let g = h.introduce(a, 5, 123, 9);
    h.watch(a, "@introduceDomain", "i");
    // Same ring: bound again, every time, to the port given; nothing fires
    // (`ox/process.ml:595-601`).
    let out = h.raw(a, ty(MsgType::Introduce), 0, b"5\x00123\x0010\0");
    assert_eq!(out, [(a, (ty(MsgType::Introduce), h.req, 0, b"OK\0".to_vec()))]);
    assert_eq!(h.calls(), [Call::Rebind(g, 5, 10)]);
    assert_eq!(h.ok(a, MsgType::Introduce, 0, b"5\x00123\x0010\0"), b"OK\0");
    assert_eq!(h.calls(), [Call::Rebind(g, 5, 10)]);
    assert_eq!((h.core.connections(), h.core.domain_conn(5)), (2, Some(g)));
    // Another ring: nothing is done, and it does not match (`ox/process.ml:609-610`).
    assert_eq!(h.err(a, MsgType::Introduce, 0, b"5\x00124\x0010\0"), "EINVAL");
    assert_eq!(h.err(a, MsgType::Introduce, 0, b"5\x00124\0-1\0"), "EINVAL");
    // A port that is none fails to bind, an error that escapes the mapping.
    assert_eq!(h.err(a, MsgType::Introduce, 0, b"5\x00123\0-1\0"), "EIO");
    assert!(h.calls().is_empty());
    // A failed bind is the request's error, and leaves the port as it was.
    h.machine.fail = Some(Errno::EBUSY);
    assert_eq!(h.err(a, MsgType::Introduce, 0, b"5\x00123\x0011\0"), "EBUSY");
    assert_eq!(h.calls(), [Call::Rebind(g, 5, 11)]);
    h.machine.fail = None;
    // A domain acting for domain 0 that introduces itself binds nothing,
    // and must give its ring and port.
    h.ok(a, MsgType::SetTarget, 0, b"5\x000\0");
    assert_eq!(h.ok(g, MsgType::Introduce, 0, b"5\x00123\x0010\0"), b"OK\0");
    assert_eq!(h.err(g, MsgType::Introduce, 0, b"5\x00123\x0011\0"), "EINVAL");
    assert_eq!(h.err(g, MsgType::Introduce, 0, b"5\x00124\x0010\0"), "EINVAL");
    assert!(h.calls().is_empty());
    // Domain 0's own ring is known, at frame 0.
    let d0 = h.core.open_domain(0);
    assert_eq!(h.ok(a, MsgType::Introduce, 0, b"0\x000\x007\0"), b"OK\0");
    assert_eq!(h.calls(), [Call::Rebind(d0, 0, 7)]);
}

#[test]
fn release_closes_the_domain_s_connection_and_fires_release_domain() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "@releaseDomain", "r");
    h.one(a, MsgType::Mkdir, "/local/domain/5");
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0");
    h.write(a, 0, "/shared", "");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0r5\0w7\0");
    let g = h.introduce(a, 5, 1, 2);
    h.watch(g, "data", "w");
    h.start(g);
    h.write(g, 0, "data/x", "1");
    for bad in [&b""[..], b"5", b"5\0\0", b"5\0x", b"x\0", b"-\0"] {
        assert_eq!(h.err(a, MsgType::Release, 0, bad), "EINVAL", "{bad:?}");
    }
    assert!(h.calls().is_empty());
    let out = h.raw(a, ty(MsgType::Release), 0, b"5\0");
    // Fired by the request, before its reply (`ox/process.ml:622-626`).
    assert_eq!(
        out,
        [
            (a, (ty(MsgType::WatchEvent), 0, 0, b"@releaseDomain\0r\0".to_vec())),
            (a, (ty(MsgType::Release), h.req, 0, b"OK\0".to_vec()))
        ]
    );
    assert_eq!(h.calls(), [Call::Disconnect(g, 5)]);
    assert_eq!(
        (h.core.connections(), h.core.watches(), h.core.domain_conn(5)),
        (1, 1, None)
    );
    // Its nodes are gone, without an event, and so are its ACL entries
    // (`ox/process.ml:620`, `ox/store.ml:459-469`).
    assert_eq!(h.read(a, 0, "/local/domain/5"), Err("ENOENT".into()));
    assert_eq!(h.one(a, MsgType::GetPerms, "/shared"), b"n0\0w7\0");
    // The old connection id: nothing is processed, nothing sent.
    assert_eq!(h.send(g, ty(MsgType::Read), 0, b"/\0"), Status::Closed);
    assert_eq!((h.core.output(g), h.core.transactions(g)), (&b""[..], 0));
    assert!(h.drain().is_empty());
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"5\0"), b"F\0");
    // A second release: unknown, nothing fires.
    let out = h.raw(a, ty(MsgType::Release), 0, b"5\0");
    assert_eq!(out, [(a, (ty(MsgType::Error), h.req, 0, b"EINVAL\0".to_vec()))]);
    assert!(h.calls().is_empty());
}

#[test]
fn release_of_an_unknown_domain_still_cleans_its_permissions() {
    // The store is cleaned before the domain is found unknown (`ox/process.ml:618-626`).
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/owned/x", "");
    h.ok(a, MsgType::SetPerms, 0, b"/owned\0n9\0");
    h.write(a, 0, "/acl", "");
    h.ok(a, MsgType::SetPerms, 0, b"/acl\0n0\0r9\0r8\0");
    h.watch(a, "/", "all");
    let out = h.raw(a, ty(MsgType::Release), 0, b"9\0");
    assert_eq!(
        out,
        [(a, (ty(MsgType::Error), h.req, 0, b"EINVAL\0".to_vec()))],
        "the removal fires nothing"
    );
    assert_eq!(
        h.ls(a, 0, "/"),
        ["@introduceDomain", "@releaseDomain", "acl", "local", "tool"]
    );
    assert_eq!(h.one(a, MsgType::GetPerms, "/acl"), b"n0\0r8\0");
    assert_eq!(h.err(a, MsgType::Release, 0, b"-8\0"), "EINVAL");
    assert_eq!(
        h.one(a, MsgType::GetPerms, "/acl"),
        b"n0\0r8\0",
        "no domid, nothing to clean"
    );
}

#[test]
fn release_in_a_transaction_cleans_the_transaction_s_store() {
    // `Transaction.get_store t` (`ox/process.ml:620`): the transaction's
    // copy, published with it if it is committed at all.
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/acl", "");
    h.ok(a, MsgType::SetPerms, 0, b"/acl\0n0\0r5\0");
    h.introduce(a, 5, 1, 1);
    let t = h.start(a);
    let r = h.call(a, MsgType::Release, t, b"5\0");
    assert_eq!((r.0, r.2, r.3), (ty(MsgType::Release), t, b"OK\0".to_vec()));
    assert_eq!(h.calls().len(), 1, "the domain itself goes at once");
    assert_eq!(h.ok(a, MsgType::GetPerms, t, b"/acl\0"), b"n0\0");
    assert_eq!(h.one(a, MsgType::GetPerms, "/acl"), b"n0\0r5\0");
    h.end(a, t, true).unwrap();
    assert_eq!(
        h.one(a, MsgType::GetPerms, "/acl"),
        b"n0\0r5\0",
        "a transaction that wrote nothing is not committed"
    );
    h.introduce(a, 5, 1, 1);
    let t = h.start(a);
    h.ok(a, MsgType::Release, t, b"5\0");
    h.write(a, t, "/w", "");
    h.end(a, t, true).unwrap();
    assert_eq!(h.one(a, MsgType::GetPerms, "/acl"), b"n0\0");
}

#[test]
fn is_domain_introduced_and_resume() {
    let mut h = H::new();
    let a = h.core.open();
    let q = |h: &mut H, p: &[u8]| h.ok(a, MsgType::IsDomainIntroduced, 0, p);
    assert_eq!(q(&mut h, b"5\0"), b"F\0");
    assert_eq!(h.err(a, MsgType::Resume, 0, b"5\0"), "EINVAL", "unknown");
    h.introduce(a, 5, 1, 1);
    assert_eq!(q(&mut h, b"5\0"), b"T\0");
    assert_eq!(q(&mut h, b"5"), b"T\0", "the first field is enough");
    assert_eq!(q(&mut h, b"0x5\0junk\0"), b"T\0");
    assert_eq!(q(&mut h, b"32752\0"), b"T\0", "DOMID_SELF (`ox/process.ml:346`)");
    for no in [&b"0\0"[..], b"6\0", b"-1\0", b"4294967296\0", b"32751\0"] {
        assert_eq!(q(&mut h, no), b"F\0", "{no:?}");
    }
    for bad in [&b""[..], b"\0", b"x\0"] {
        assert_eq!(h.err(a, MsgType::IsDomainIntroduced, 0, bad), "EINVAL", "{bad:?}");
        assert_eq!(h.err(a, MsgType::Resume, 0, bad), "EINVAL", "{bad:?}");
    }
    // RESUME of a known domain does nothing (`ox/domains.ml:150-151`).
    assert_eq!(h.ok(a, MsgType::Resume, 0, b"5\0"), b"OK\0");
    assert_eq!(h.ok(a, MsgType::Resume, 0, b"5"), b"OK\0");
    assert_eq!(h.err(a, MsgType::Resume, 0, b"-1\0"), "EINVAL");
    assert_eq!(
        h.err(a, MsgType::Resume, 0, b"32752\0"),
        "EINVAL",
        "DOMID_SELF is no domain"
    );
    let d0 = h.core.open_domain(0);
    assert_eq!(q(&mut h, b"0\0"), b"T\0");
    assert_eq!(h.ok(d0, MsgType::Resume, 0, b"0\0"), b"OK\0", "domain 0's ring may");
    assert!(h.calls().is_empty());
}

#[test]
fn a_dead_domain_loses_its_connection_nodes_and_acl_entries_and_release_domain_fires_once() {
    let mut h = H::new();
    let a = h.core.open();
    let d0 = h.core.open_domain(0);
    h.watch(a, "@releaseDomain", "a");
    h.watch(d0, "@releaseDomain", "d0");
    let mut g = Vec::new();
    for d in 1..=4u32 {
        h.one(a, MsgType::Mkdir, &format!("/local/domain/{d}"));
        h.ok(a, MsgType::SetPerms, 0, format!("/local/domain/{d}\0n{d}\0").as_bytes());
        g.push(h.introduce(a, d, d as u64, d));
    }
    // Domains 2 and 3 may see @releaseDomain.
    h.ok(a, MsgType::SetPerms, 0, b"@releaseDomain\0n0\0r2\0r3\0");
    h.watch(g[1], "@releaseDomain", "2");
    h.watch(g[2], "@releaseDomain", "3");
    h.watch(g[2], "data", "3d");
    let t = h.start(g[2]);
    h.write(g[2], t, "data/inside", "");
    // An event for domain 3, which it does not read before it dies.
    h.send(a, ty(MsgType::Write), 0, &wr("/local/domain/3/data/x", "1"));
    assert!(!h.core.output(g[2]).is_empty());
    let watches = h.core.watches();
    let asked = h.dom_exc(&[
        (2, DomainState::Shutdown),
        (3, DomainState::Dead),
        (4, DomainState::Dead),
    ]);
    assert_eq!(
        asked,
        [1, 2, 3, 4],
        "in order, and not domain 0 (`ox/domains.ml:124-125`)"
    );
    assert_eq!(h.calls(), [Call::Disconnect(g[2], 3), Call::Disconnect(g[3], 4)]);
    // One event per watcher however many domains changed; domain 3's
    // watch went with it, its ACL entry from @releaseDomain too.
    let fired = [
        ev(a, "@releaseDomain", "a"),
        ev(d0, "@releaseDomain", "d0"),
        ev(g[1], "@releaseDomain", "2"),
    ];
    assert_eq!(events(&h.drain()), fired);
    assert_eq!(h.core.watches(), watches - 2);
    assert_eq!(
        (h.core.output(g[2]), h.core.transactions(g[2])),
        (&b""[..], 0),
        "its queued event is dropped"
    );
    assert_eq!(h.send(g[2], ty(MsgType::Read), 0, b"/\0"), Status::Closed);
    let mut doms: Vec<_> = h.core.domains().map(|d| d.0).collect();
    doms.sort();
    assert_eq!(doms, [0, 1, 2]);
    assert_eq!(
        h.ls(a, 0, "/local/domain"),
        ["1", "2"],
        "their nodes went, firing nothing"
    );
    assert_eq!(h.one(a, MsgType::GetPerms, "@releaseDomain"), b"n0\0r2\0");
    // Level-triggered: while domain 2 stays shut down, every VIRQ fires
    // again (`ox/domains.ml:129-133`, `ox/xenstored.ml:493-496`).
    assert_eq!(h.dom_exc(&[(2, DomainState::Shutdown)]), [1, 2]);
    assert_eq!(events(&h.drain()), fired);
    assert!(h.calls().is_empty());
    assert_eq!(h.dom_exc(&[]), [1, 2]);
    assert!(h.drain().is_empty(), "nothing shut down or dead: nothing fires");
    h.dom_exc(&[(1, DomainState::Dead)]);
    assert_eq!(events(&h.drain()), fired);
    assert_eq!(h.calls(), [Call::Disconnect(g[0], 1)]);
}

#[test]
fn without_domains_a_virq_asks_nothing_and_fires_nothing() {
    let mut h = H::new();
    let a = h.core.open();
    h.watch(a, "@releaseDomain", "a");
    assert_eq!(h.dom_exc(&[(0, DomainState::Dead)]), Vec::<u32>::new());
    h.core.open_domain(0);
    assert_eq!(h.dom_exc(&[(0, DomainState::Dead)]), Vec::<u32>::new());
    assert!(h.drain().is_empty());
    assert!(h.calls().is_empty());
}

#[test]
fn reconnect_drops_what_the_ring_held_and_keeps_the_connection() {
    let mut h = H::new();
    let a = h.core.open();
    h.one(a, MsgType::Mkdir, "/local/domain/5");
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0");
    h.write(a, 0, "/for7", "s");
    h.ok(a, MsgType::SetPerms, 0, b"/for7\0n7\0");
    let g = h.introduce(a, 5, 1, 1);
    h.ok(a, MsgType::SetTarget, 0, b"5\x007\0");
    h.watch(g, "data", "w");
    assert_eq!(h.start(g), 1);
    assert_eq!(h.start(g), 2);
    // Unsent output, and half a request.
    h.send(a, ty(MsgType::Write), 0, &wr("/local/domain/5/data", ""));
    h.core.feed(g, &[ty(MsgType::Read) as u8, 0, 0]);
    assert!(!h.core.output(g).is_empty());
    h.core.reconnect(g);
    assert_eq!(
        (h.core.output(g), h.core.transactions(g), h.core.watches()),
        (&b""[..], 0, 0)
    );
    h.drain();
    // The same connection: its domain, home and target; transaction ids from 1.
    assert_eq!(h.core.domain_conn(5), Some(g));
    assert!(
        events(&h.raw(g, ty(MsgType::Write), 0, &wr("data/x", "1"))).is_empty(),
        "the watch is gone"
    );
    assert_eq!(h.read(a, 0, "/local/domain/5/data/x").unwrap(), "1");
    assert_eq!(h.read(g, 0, "/for7").unwrap(), "s");
    assert_eq!(h.start(g), 1);
    assert!(h.calls().is_empty());
    h.core.reconnect(ConnId(999));
}

#[test]
fn a_ring_gets_e2big_for_what_does_not_fit_a_payload() {
    // `ox/connection.ml:242-246`; a socket gets anything.
    let (mut h, a, g) = with_guest(Config::default());
    // 128 names of 31 bytes: a listing of exactly a payload.
    for i in 0..128 {
        h.write(a, 0, &format!("/local/domain/5/d/{i:031}"), "");
    }
    assert_eq!(h.ls(g, 0, "d").len(), 128);
    h.write(a, 0, "/local/domain/5/d/x", "");
    let r = h.call(g, MsgType::Directory, 0, b"d\0");
    assert_eq!((r.0, r.2, r.3), (ty(MsgType::Error), 0, b"E2BIG\0".to_vec()));
    assert_eq!(h.ls(a, 0, "/local/domain/5/d").len(), 129);
    // Watch events too: a relative watch whose events are longer than its request.
    let token = "t".repeat(PAYLOAD_MAX - 4);
    assert_eq!(h.watch(g, "d", &token), [ev(g, "d", &token)]);
    let out = h.raw(a, ty(MsgType::Write), 0, &wr("/local/domain/5/d/x", ""));
    assert_eq!(out[1], (g, (ty(MsgType::Error), 0, 0, b"E2BIG\0".to_vec())));
}

#[test]
fn control_answers_as_oxenstored_4_17() {
    let mut h = H::new();
    let a = h.core.open();
    let d0 = h.core.open_domain(0);
    let g = h.introduce(a, 5, 123, 1);
    h.introduce(a, 6, u64::MAX, 1);
    h.watch(a, "rel", "ta");
    h.watch(d0, "/abs", "t0");
    h.watch(g, "@releaseDomain", "tg");
    let c = |h: &mut H, who: ConnId, p: &[u8]| h.ok(who, MsgType::Control, 0, p);
    // Domains, then sockets; each watch as its client gave it.
    let list = b"watch D0: /abs t0\nwatch D5: @releaseDomain tg\nwatch A1: rel ta\n\0";
    assert_eq!(c(&mut h, a, b"watches\0"), list);
    assert_eq!(c(&mut h, d0, b"watches"), list);
    // Others get OK and nothing else (`ox/process.ml:222-223`).
    assert_eq!(c(&mut h, g, b"watches\0"), b"OK\0");
    // A domain's ring, as `%nd`.
    assert_eq!(c(&mut h, a, b"mfn\x005\0"), b"123\0");
    assert_eq!(c(&mut h, a, b"mfn\x006\0"), b"-1\0");
    assert_eq!(c(&mut h, a, b"mfn\x000\0"), b"0\0");
    // What only logs, what is unknown, and what fails inside: OK
    // (`4.17 ox/process.ml:221-257`; `compact` is master's).
    for p in [
        &b"mfn\x009\0"[..],
        b"mfn\0x\0",
        b"mfn",
        b"print\0hello\0",
        b"print",
        b"",
        b"\0",
        b"compact\0",
        b"live-update",
        b"quota",
        b"quota\0x\0",
        b"xenbus\0",
        b"xenbus\x009\0",
    ] {
        assert_eq!(c(&mut h, a, p), b"OK\0", "{p:?}");
    }
    // What needs what the core does not have.
    for p in [&b"live-update\0-s\0"[..], b"xenbus\x005\0"] {
        assert_eq!(h.err(a, MsgType::Control, 0, p), "ENOSYS", "{p:?}");
    }
}

/// The children of `p` read with DIRECTORY_PART as libxenstore does
/// (`tools/libs/store/xs.c:783-830`), and the generation of every part.
fn directory_parts(h: &mut H, c: ConnId, tx: u32, p: &str) -> (Vec<u8>, String) {
    let (mut list, mut gen) = (Vec::new(), None);
    loop {
        assert!(list.len() < 1 << 20, "no end");
        let r = h.ok(
            c,
            MsgType::DirectoryPart,
            tx,
            format!("{p}\0{}\0", list.len()).as_bytes(),
        );
        assert!(r.len() <= PAYLOAD_MAX);
        let nul = r.iter().position(|c| *c == 0).unwrap();
        let g = String::from_utf8(r[..nul].to_vec()).unwrap();
        assert_eq!(*gen.get_or_insert(g.clone()), g, "one generation");
        let rest = &r[nul + 1..];
        if rest == b"\0" || rest.ends_with(b"\0\0") {
            list.extend_from_slice(&rest[..rest.len() - 1]);
            return (list, g);
        }
        assert!(!rest.is_empty(), "no progress");
        list.extend_from_slice(rest);
    }
}

#[test]
fn directory_part_lists_a_long_directory_on_a_ring() {
    let (mut h, a, g) = with_guest(Config::default());
    for i in 0..500 {
        h.write(a, 0, &format!("/local/domain/5/big/child-number-{i:05}"), "");
    }
    let all = h.one(a, MsgType::Directory, "/local/domain/5/big");
    assert!(all.len() > 2 * PAYLOAD_MAX);
    assert_eq!(h.err(g, MsgType::Directory, 0, b"big\0"), "E2BIG");
    let (parts, gen) = directory_parts(&mut h, g, 0, "big");
    assert_eq!(parts, all);
    // The generation is that of the set of children.
    h.write(a, 0, "/local/domain/5/big/child-number-00000", "v");
    assert_eq!(directory_parts(&mut h, g, 0, "big").1, gen);
    h.write(a, 0, "/local/domain/5/big/new", "");
    assert_ne!(directory_parts(&mut h, g, 0, "big").1, gen);
    // Small directories, and offsets anywhere.
    h.write(a, 0, "/local/domain/5/s/a", "");
    h.write(a, 0, "/local/domain/5/s/bb", "");
    let gen = directory_parts(&mut h, g, 0, "s").1;
    let part = |h: &mut H, off: &str| {
        let r = h.ok(g, MsgType::DirectoryPart, 0, format!("s\0{off}\0").as_bytes());
        String::from_utf8(r[gen.len() + 1..].to_vec()).unwrap()
    };
    for (off, want) in [
        ("0", "a\0bb\0\0"),
        ("2", "bb\0\0"),
        ("1", "\0bb\0\0"),
        ("5", "\0"),
        ("6", "\0"),
        (" \t2", "bb\0\0"),
        ("+2", "bb\0\0"),
        ("-1", "\0"),
        ("x", "a\0bb\0\0"),
        ("", "a\0bb\0\0"),
    ] {
        assert_eq!(part(&mut h, off), want, "{off:?}");
    }
    assert_eq!(directory_parts(&mut h, g, 0, "s/a").0, b"", "no children");
    // As DIRECTORY: checked, and errors.
    assert_eq!(h.err(g, MsgType::DirectoryPart, 0, b"/tool\x000\0"), "EACCES");
    assert_eq!(h.err(g, MsgType::DirectoryPart, 0, b"none\x000\0"), "ENOENT");
    for bad in [&b"s\0"[..], b"s\x000", b"s\x000\0\0", b"", b"s/\x000\0"] {
        assert_eq!(h.err(g, MsgType::DirectoryPart, 0, bad), "EINVAL", "{bad:?}");
    }
    assert_eq!(
        h.ok(g, MsgType::DirectoryPart, 0, b"s\x002\0junk").len(),
        gen.len() + 1 + 4,
        "two strings, then anything"
    );
}

#[test]
fn directory_part_in_a_transaction_is_a_directory_listing() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/d/a", "");
    let t = h.start(a);
    h.write(a, t, "/d/b", "");
    assert_eq!(directory_parts(&mut h, a, t, "/d").0, b"a\0b\0");
    h.write(a, 0, "/d/c", "");
    assert_eq!(h.end(a, t, true), Err("EAGAIN".into()), "the listing would differ");
}

#[test]
fn directory_part_fills_a_payload_exactly() {
    // `while (len + strlen(child) < maxlen)` (`cx/core.c:1304`): with a
    // 2-byte generation, 177 names of 22 bytes leave the 178th exactly at
    // the limit, which is out.
    let node = Node::new(Arc::new(Perms::default0()), Bytes::EMPTY, 0);
    let mut m = pmap::PMap::new();
    for i in 0..178 {
        m.insert(Name::from(format!("{i:022}").as_bytes()), node.clone());
    }
    let first = part_reply(7, &m, 0);
    assert_eq!(first.len(), 2 + 177 * 23);
    assert!(first.starts_with(b"7\x000000"));
    assert_eq!(
        part_reply(7, &m, 177 * 23),
        [&b"7\0"[..], format!("{:022}\0\0", 177).as_bytes()].concat()
    );
    m.remove(&b"0000000000000000000177"[..]);
    assert_eq!(
        part_reply(7, &m, 0).len(),
        2 + 177 * 23 + 1,
        "the whole list, and its end"
    );
    assert_eq!(part_reply(7, &m, 177 * 23), b"7\0\0");
}

#[test]
fn c_offsets() {
    assert_eq!(c_offset(b"12"), 12);
    assert_eq!(c_offset(b"\n\x0b\x0c\r 3x"), 3);
    assert_eq!(c_offset(b"-0"), 0);
    assert_eq!(c_offset(b"-1"), u32::MAX as usize);
    assert_eq!(c_offset(b"--1"), 0);
    assert_eq!(c_offset(b"4294967297"), 1, "an int wraps");
}

// ---------------------------------------------------------------- quotas

/// CONTROL `quota <domid>` on `c`, without its NUL.
fn quota(h: &mut H, c: ConnId, tx: u32, domid: &str) -> String {
    let r = h.ok(c, MsgType::Control, tx, format!("quota\0{domid}\0").as_bytes());
    String::from_utf8(r).unwrap().strip_suffix('\0').unwrap().to_string()
}

/// A guest, domain 5, with its home, owned by it, and at most `n` nodes.
fn guest_with_quota(n: usize) -> (H, ConnId, ConnId) {
    with_guest(Config {
        entity_max: n,
        ..Config::default()
    })
}

/// The home of domain `d`, owned by it.
fn home(h: &mut H, a: ConnId, d: u32) {
    h.one(a, MsgType::Mkdir, &format!("/local/domain/{d}"));
    h.ok(a, MsgType::SetPerms, 0, format!("/local/domain/{d}\0n{d}\0").as_bytes());
}

#[test]
fn control_quota_reports_the_nodes_a_domain_owns_as_oxenstored_4_17() {
    // `ox/process.ml:231-234`, `ox/quota.ml:39-44`.
    let mut h = H::new();
    let a = h.core.open();
    // The two special nodes, /local, /tool and /tool/xenstored; never the root.
    assert_eq!(quota(&mut h, a, 0, "0"), "dom0 quota: 5/1000");
    assert_eq!(quota(&mut h, a, 0, "0x0"), "dom0 quota: 5/1000", "int_of_string");
    for d in ["5", "-3", "99999999999", "-1"] {
        assert_eq!(quota(&mut h, a, 0, d), format!("dom{d} quota: not set"));
    }
    home(&mut h, a, 5);
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 1/1000");
    assert_eq!(quota(&mut h, a, 0, "0"), "dom0 quota: 6/1000", "and /local/domain");
    // In a transaction, the transaction's store.
    let t = h.start(a);
    h.write(a, t, "/local/domain/5/x", "");
    assert_eq!(quota(&mut h, a, t, "5"), "dom5 quota: 2/1000");
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 1/1000");
    // The root's lost owner is -1 there.
    h.ok(a, MsgType::SetPerms, 0, b"/\0n7\0");
    h.write(a, 0, "/mine", "");
    assert_eq!(quota(&mut h, a, 0, "7"), "dom7 quota: 1/1000");
    assert_eq!(h.err(a, MsgType::Release, 0, b"7\0"), "EINVAL", "unknown, but cleaned");
    h.ok(a, MsgType::SetPerms, 0, b"/\0n0\0").clear();
    h.write(a, 0, "/mine", "");
    assert_eq!(quota(&mut h, a, 0, "7"), "dom7 quota: not set");
    let mut h2 = H::new();
    let a2 = h2.core.open();
    h2.ok(a2, MsgType::SetPerms, 0, b"/\0n7\0");
    h2.err(a2, MsgType::Release, 0, b"7\0");
    h2.write(a2, 0, "/orphan", "");
    assert_eq!(quota(&mut h2, a2, 0, "-1"), "dom-1 quota: 1/1000");
    assert_eq!(
        quota(&mut h2, a2, 0, "0x7fffffffffffffff"),
        "dom-1 quota: 1/1000",
        "an OCaml int"
    );
    assert_eq!(
        quota(&mut h2, a2, 0, "0x4000000000000000"),
        "dom-4611686018427387904 quota: not set"
    );
    assert_eq!(quota(&mut h2, a2, 0, "4294967295"), "dom4294967295 quota: not set");
    h2.write(a2, 0, "/big", "");
    h2.ok(a2, MsgType::SetPerms, 0, b"/big\0n4294967295\0");
    assert_eq!(quota(&mut h2, a2, 0, "4294967295"), "dom4294967295 quota: 1/1000");
    assert_eq!(quota(&mut h2, a2, 0, "-1"), "dom-1 quota: 1/1000");
    // Only for domain 0; nothing for what is no number.
    let g = h.core.open_domain(5);
    assert_eq!(h.ok(g, MsgType::Control, 0, b"quota\x005\0"), b"OK\0");
    assert_eq!(h.ok(a, MsgType::Control, 0, b"quota\0five\0"), b"OK\0");
}

#[test]
fn control_quota_in_a_transaction_counts_the_store_it_started_from_with_its_changes() {
    // `Store.get_quota t.Transaction.store` (`ox/process.ml:231-234`): the
    // transaction's copy, taken at TRANSACTION_START (`ox/transaction.ml:127`).
    let mut h = H::new();
    let (a, b) = (h.core.open(), h.core.open());
    home(&mut h, a, 5);
    let t = h.start(a);
    h.write(b, 0, "/local/domain/5/x/y", "");
    h.one(b, MsgType::Rm, "/local/domain/5");
    h.write(b, 0, "/other", "");
    assert_eq!(
        quota(&mut h, a, t, "5"),
        "dom5 quota: 1/1000",
        "the others' changes unseen"
    );
    assert_eq!(quota(&mut h, a, t, "0"), "dom0 quota: 6/1000");
    h.write(a, t, "/local/domain/5/z", "");
    h.ok(a, MsgType::Rm, t, b"/tool/xenstored\0");
    assert_eq!(quota(&mut h, a, t, "5"), "dom5 quota: 2/1000", "its own changes seen");
    assert_eq!(quota(&mut h, a, t, "0"), "dom0 quota: 5/1000");
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: not set");
    assert_eq!(quota(&mut h, a, 0, "0"), "dom0 quota: 7/1000");
}

/// oxenstored checks the node quota in a transaction against the counts
/// copied at TRANSACTION_START, changed by the transaction's own requests
/// (`ox/transaction.ml:127`, `ox/store.ml:415-444`, `ox/quota.ml:52-64`).
/// Here the counts are the store's of now plus the transaction's changes,
/// held at 0 (`quota.rs`, `txn_count`): when others removed nodes the
/// transaction removed too, the hold gives the guest more room in its
/// transaction than oxenstored's, and more with one node per request than
/// with several in one (the room of a request is taken once, `Missing`).
/// The commit runs the requests again on the store of then, so what it
/// publishes keeps to the quota either way. Found by `core_vs_model`
/// in its second night; the model now does as the core.
#[test]
#[ignore = "differs from oxenstored: a transaction's node counts are the store's of now plus its changes"]
fn in_a_transaction_the_node_quota_counts_from_the_store_it_started_from() {
    let (mut h, a, g) = with_guest(Config {
        entity_max: 4,
        profile: Profile::Oxenstored,
        ..Config::default()
    });
    // Domain 5 owns its home and two nodes below it: 3.
    h.one(a, MsgType::Mkdir, "/local/domain/5/r1");
    h.one(a, MsgType::Mkdir, "/local/domain/5/r2");
    let t = h.start(g);
    h.ok(g, MsgType::Rm, t, b"r1\0");
    h.ok(g, MsgType::Rm, t, b"r2\0");
    // oxenstored's count in the transaction: 3 - 2 = 1. Others remove the
    // same two nodes: the store's count is 1, the transaction's changes -2.
    h.ok(a, MsgType::Rm, 0, b"/local/domain/5/r1\0");
    h.ok(a, MsgType::Rm, 0, b"/local/domain/5/r2\0");
    // One request that makes four nodes: three fit (1 to 4), as in
    // oxenstored, whose missing parents are MKDIRs of their own.
    assert_eq!(h.err(g, MsgType::Mkdir, t, b"m/a/b/c\0"), "EQUOTA");
    assert_eq!(h.err(g, MsgType::Mkdir, t, b"n\0"), "EQUOTA", "at 4 of 4");
    h.end(g, t, false).unwrap();
    // One node per request: three, then the quota.
    h.one(a, MsgType::Mkdir, "/local/domain/5/r1");
    h.one(a, MsgType::Mkdir, "/local/domain/5/r2");
    let t = h.start(g);
    h.ok(g, MsgType::Rm, t, b"r1\0");
    h.ok(g, MsgType::Rm, t, b"r2\0");
    h.ok(a, MsgType::Rm, 0, b"/local/domain/5/r1\0");
    h.ok(a, MsgType::Rm, 0, b"/local/domain/5/r2\0");
    for n in ["n1", "n2", "n3"] {
        h.ok(g, MsgType::Mkdir, t, format!("{n}\0").as_bytes());
    }
    assert_eq!(h.err(g, MsgType::Mkdir, t, b"n4\0"), "EQUOTA", "at 4 of 4");
}

#[test]
fn xsa_272_every_way_of_creating_a_node_counts() {
    // `73392c7fd1`: one write path skipped the count. Each request below
    // is checked by the auditor after it runs (`H::send`).
    let (mut h, a, g) = guest_with_quota(10);
    let q = |h: &mut H| quota(h, a, 0, "5");
    assert_eq!(q(&mut h), "dom5 quota: 1/10", "its home");
    h.write(g, 0, "leaf", "");
    assert_eq!(q(&mut h), "dom5 quota: 2/10");
    h.write(g, 0, "a/b/c", "");
    assert_eq!(q(&mut h), "dom5 quota: 5/10", "three nodes");
    h.ok(g, MsgType::Mkdir, 0, b"m\0");
    assert_eq!(q(&mut h), "dom5 quota: 6/10");
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("p/q", &"v".repeat(2049))), "E2BIG");
    // The parent made before the size check stays and counts; in the
    // native profile the request makes nothing.
    let kept = usize::from(!rules().all_or_nothing);
    assert_eq!(q(&mut h), format!("dom5 quota: {}/10", 6 + kept));
    let t = h.start(g);
    h.write(g, t, "t1", "");
    h.end(g, t, true).unwrap();
    assert_eq!(q(&mut h), format!("dom5 quota: {}/10", 7 + kept), "a commit as it is");
    let t = h.start(g);
    h.write(g, t, "t2", "");
    h.write(a, 0, "/elsewhere", "");
    h.end(g, t, true).unwrap();
    assert_eq!(
        q(&mut h),
        format!("dom5 quota: {}/10", 8 + kept),
        "a commit re-executed"
    );
    h.write(g, 0, "last", "");
    if kept == 0 {
        h.write(g, 0, "last-but-one", "");
    }
    // The one that would make 11 changes nothing.
    let before = h.ls(a, 0, "/local/domain/5");
    for (t, p) in [
        (MsgType::Write, wr("over", "")),
        (MsgType::Mkdir, b"over\0".to_vec()),
        (MsgType::Write, wr("o/v", "")),
    ] {
        assert_eq!(h.err(g, t, 0, &p), quota_error());
    }
    assert_eq!(h.ls(a, 0, "/local/domain/5"), before);
    assert_eq!(q(&mut h), "dom5 quota: 10/10");
    let t = h.start(g);
    assert_eq!(
        h.err(g, MsgType::Write, t, &wr("over", "")),
        quota_error(),
        "in a transaction too"
    );
}

#[test]
fn xsa_414_what_a_failed_creation_leaves_and_counts() {
    // As oxenstored, whose missing parents are MKDIRs of their own
    // (`ox/process.ml:74-87`): those that fit are made and stay, and
    // count; the request fails at the first that does not. In the native
    // profile a request that fails makes nothing, in a transaction too;
    // its answer is the same.
    let keeps = !rules().all_or_nothing;
    let big = "v".repeat(2049);
    let (mut h, a, g) = guest_with_quota(5);
    h.watch(a, "/local/domain/5", "w");
    for p in ["x", "y", "z"] {
        h.write(g, 0, p, "");
    }
    h.drain();
    let root = h.core.root.clone();
    let out = h.raw(g, ty(MsgType::Write), 0, &wr("a/b/c", "v"));
    assert_eq!(
        out,
        [(
            g,
            (
                ty(MsgType::Error),
                h.req,
                0,
                format!("{}\0", quota_error()).into_bytes()
            )
        )],
        "and it fires nothing"
    );
    let children = |h: &mut H| h.ls(a, 0, "/local/domain/5");
    if keeps {
        assert_eq!(
            h.ls(a, 0, "/local/domain/5/a"),
            Vec::<String>::new(),
            "a was made, b was not"
        );
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 5/5");
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("w", "")), "EQUOTA");
        h.ok(g, MsgType::Rm, 0, b"a\0");
    } else {
        assert!(Arc::ptr_eq(&root, &h.core.root), "the store is not even copied");
        assert_eq!(children(&mut h), ["x", "y", "z"]);
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 4/5");
    }
    // Room for the parents but not the value: E2BIG after them.
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("p/q", &big)), "E2BIG");
    assert_eq!(children(&mut h).contains(&"p".to_string()), keeps);
    h.ok(g, MsgType::Rm, 0, b"p\0");
    let t = h.start(g);
    assert_eq!(
        h.err(g, MsgType::Write, t, &wr("s/u", &big)),
        "E2BIG",
        "in a transaction"
    );
    assert_eq!(h.read(g, t, "s").is_ok(), keeps, "in its store");
    h.end(g, t, false).unwrap();
    // A MKDIR with room for one of its two nodes.
    assert_eq!(h.err(g, MsgType::Mkdir, 0, b"m/n\0"), quota_error());
    assert_eq!(children(&mut h).contains(&"m".to_string()), keeps);
    h.ok(g, MsgType::Rm, 0, b"m\0");
    // No room for them: the quota first.
    h.write(g, 0, "r", "");
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("p/q", &big)), quota_error());
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 5/5");
}

#[test]
fn the_quota_comes_after_the_size_and_before_the_access() {
    // `Store.write`: `Quota.check` (size, then entries), then the
    // permissions (`ox/store.ml:415-427`); each missing parent's quota
    // before its parent's permissions (`ox/store.ml:429-436`).
    let (mut h, a, g) = guest_with_quota(1);
    h.write(a, 0, "/six", "");
    h.ok(a, MsgType::SetPerms, 0, b"/six\0n6\0");
    assert_eq!(
        h.err(g, MsgType::Write, 0, &wr("/six/x", "")),
        "EQUOTA",
        "not EACCES: domain 6 is full"
    );
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("/six/x/y", "")), "EQUOTA");
    assert_eq!(h.err(g, MsgType::Mkdir, 0, b"/six/x\0"), "EQUOTA");
    assert_eq!(
        h.err(g, MsgType::Write, 0, &wr("/six", "")),
        "EACCES",
        "an existing node needs no quota"
    );
    assert_eq!(h.err(g, MsgType::Mkdir, 0, b"/six\0"), "EACCES");
    // Its own home holds its one node.
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("x", &"v".repeat(2049))), "E2BIG");
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("x", "v")), "EQUOTA");
    h.ok(g, MsgType::Mkdir, 0, b"/local/domain/5\0");
    // Domain 0 owns /local: unlimited, but closed.
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("/local/x", "")), "EACCES");
}

#[test]
fn xsa_419_who_owns_and_pays_for_a_node_a_guest_creates() {
    // A node gets its parent's permissions, so its owner, and counts for
    // it (`ox/store.ml:415-436`); domain 0 is never held (`ox/quota.ml:58`,
    // `id > 0`): below a node domain 0 owns, a guest's nodes are domain
    // 0's. In the native profile the guest owns what it creates, the rest
    // of the ACL its parent's, is counted for it and loses it when it dies.
    let owns = rules().creator_owns;
    let (mut h, a, g) = guest_with_quota(10);
    h.write(a, 0, "/drop", "");
    h.ok(a, MsgType::SetPerms, 0, b"/drop\0n0\0w5\0");
    for i in 0..100 {
        let r = h.call(g, MsgType::Write, 0, &wr(&format!("/drop/{i}"), ""));
        assert_eq!(r.0 == ty(MsgType::Error), owns && i >= 9, "{i}");
    }
    if owns {
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("/drop/x", "")), quota_error());
        assert_eq!(h.err(g, MsgType::Mkdir, 0, b"/drop/x\0"), quota_error());
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 10/10");
        assert_eq!(h.one(a, MsgType::GetPerms, "/drop/0"), b"n5\0w5\0");
        h.dom_exc(&[(5, DomainState::Dead)]);
        assert_eq!(h.ls(a, 0, "/drop"), Vec::<String>::new(), "gone with it");
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: not set");
    } else {
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 1/10");
        assert_eq!(h.one(a, MsgType::GetPerms, "/drop/0"), b"n0\0w5\0");
    }
    // A guest writing in another's tree fills the other's quota, and
    // what it made stays the other's when it dies; in the native profile
    // it fills its own, and what it made goes.
    let mut h = H::with(Config {
        entity_max: 10,
        ..Config::default()
    });
    let a = h.core.open();
    home(&mut h, a, 6);
    for round in 0..5 {
        // Given again each time: the entry goes with domain 5.
        h.ok(a, MsgType::SetPerms, 0, b"/local/domain/6\0n6\0w5\0");
        home(&mut h, a, 5);
        let g = h.introduce(a, 5, 1, 1);
        for i in 0..12 {
            let p = format!("/local/domain/6/{round}-{i}");
            let r = h.call(g, MsgType::Write, 0, &wr(&p, ""));
            let full = if owns { i >= 9 } else { round > 0 || i >= 9 };
            assert_eq!(r.3 == format!("{}\0", quota_error()).as_bytes(), full, "{p}");
        }
        let (five, six) = if owns { (10, 1) } else { (1, 10) };
        assert_eq!(quota(&mut h, a, 0, "5"), format!("dom5 quota: {five}/10"));
        assert_eq!(quota(&mut h, a, 0, "6"), format!("dom6 quota: {six}/10"));
        h.dom_exc(&[(5, DomainState::Dead)]);
        h.calls();
    }
    assert_eq!(h.ls(a, 0, "/local/domain/6").len(), if owns { 0 } else { 9 });
    h.introduce(a, 6, 2, 2);
    h.dom_exc(&[(6, DomainState::Dead)]);
    assert_eq!(quota(&mut h, a, 0, "6"), "dom6 quota: not set");
}

#[test]
fn set_perms_moves_a_node_to_its_new_owner_whatever_its_quota() {
    // `ox/store.ml:446-457`: no check, a count moved.
    let (mut h, a, g) = guest_with_quota(1);
    h.write(a, 0, "/p/x", "");
    h.ok(a, MsgType::SetPerms, 0, b"/p/x\0n5\0");
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 2/1");
    // Its owner may change its permissions, not its owner.
    h.ok(g, MsgType::SetPerms, 0, b"/p/x\0n5\0r6\0");
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 2/1");
    h.ok(a, MsgType::SetPerms, 0, b"/p/x\0n6\0");
    assert_eq!(
        (quota(&mut h, a, 0, "5"), quota(&mut h, a, 0, "6")),
        ("dom5 quota: 1/1".into(), "dom6 quota: 1/1".into())
    );
    // The root does not count (oxenstored moves a count it never made).
    let zero = quota(&mut h, a, 0, "0");
    h.ok(a, MsgType::SetPerms, 0, b"/\0n7\0");
    assert_eq!(
        (quota(&mut h, a, 0, "0"), quota(&mut h, a, 0, "7")),
        (zero, "dom7 quota: not set".into())
    );
}

#[test]
fn rm_uncounts_every_node_below_whoever_owns_it() {
    // `ox/store.ml:438-444`.
    let (mut h, a, g) = guest_with_quota(10);
    h.write(a, 0, "/local/domain/5/a/b/c", "");
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5/a/b\0n7\0b5\0");
    assert_eq!(
        (quota(&mut h, a, 0, "5"), quota(&mut h, a, 0, "7")),
        ("dom5 quota: 3/10".into(), "dom7 quota: 1/10".into())
    );
    h.ok(g, MsgType::Rm, 0, b"a\0");
    assert_eq!(
        (quota(&mut h, a, 0, "5"), quota(&mut h, a, 0, "7")),
        ("dom5 quota: 1/10".into(), "dom7 quota: not set".into())
    );
    h.ok(a, MsgType::Rm, 0, b"/\0");
    for d in ["0", "5"] {
        assert_eq!(quota(&mut h, a, 0, d), format!("dom{d} quota: not set"));
    }
}

#[test]
fn xsa_483_a_dead_or_released_domain_starts_again_from_nothing() {
    // `af9e77f5ff`. What others owned in its subtree is uncounted too;
    // oxenstored forgets the dead domain's count only (`ox/store.ml:459-470`).
    let mut h = H::with(Config {
        entity_max: 10,
        ..Config::default()
    });
    let a = h.core.open();
    type End = fn(&mut H, ConnId);
    let ends: [End; 4] = [
        |h, _| drop(h.dom_exc(&[(5, DomainState::Dead)])),
        |h, a| drop(h.ok(a, MsgType::Release, 0, b"5\0")),
        |h, a| {
            let t = h.start(a);
            h.ok(a, MsgType::Release, t, b"5\0");
            h.write(a, t, "/w", "");
            h.end(a, t, true).unwrap();
        },
        |h, a| {
            // Aborted: the store keeps the nodes, and their counts.
            let t = h.start(a);
            h.ok(a, MsgType::Release, t, b"5\0");
            h.end(a, t, false).unwrap();
            assert_eq!(quota(h, a, 0, "5"), "dom5 quota: 10/10");
            h.ok(a, MsgType::Rm, 0, b"/local/domain/5\0");
        },
    ];
    for end in ends {
        home(&mut h, a, 5);
        let g = h.introduce(a, 5, 1, 1);
        for i in 0..9 {
            h.write(g, 0, &format!("n{i}"), "");
        }
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("n9", "")), quota_error());
        h.write(a, 0, "/local/domain/5/n0/other", "");
        h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5/n0/other\0n7\0");
        end(&mut h, a);
        h.calls();
        assert_eq!(
            (quota(&mut h, a, 0, "5"), quota(&mut h, a, 0, "7")),
            ("dom5 quota: not set".into(), "dom7 quota: not set".into())
        );
    }
}

#[test]
fn xsa_421_create_then_delete_in_one_transaction_counts_nothing() {
    let (mut h, a, g) = guest_with_quota(12);
    for round in 0..100 {
        let t = h.start(g);
        for c in 'a'..='j' {
            h.write(g, t, &format!("x/{c}"), "");
        }
        h.ok(g, MsgType::Rm, t, b"x\0");
        if round % 2 == 1 {
            h.write(a, 0, "/elsewhere", "");
        }
        h.end(g, t, true).unwrap();
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 1/12");
    }
    for c in 'a'..='j' {
        h.write(g, 0, &format!("{c}"), "");
    }
}

#[test]
fn xsa_440_two_transactions_removing_the_same_nodes_count_once() {
    // `c4e05c97f5`: the second commit's fix-up went negative.
    let (mut h, a, g) = guest_with_quota(100);
    for i in 0..50 {
        h.write(g, 0, &format!("n{i}"), "");
    }
    let (t1, t2) = (h.start(g), h.start(g));
    for t in [t1, t2] {
        for i in 0..50 {
            h.ok(g, MsgType::Rm, t, format!("n{i}\0").as_bytes());
        }
    }
    h.end(g, t1, true).unwrap();
    // Re-executed: removing what is gone is no error.
    h.end(g, t2, true).unwrap();
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 1/100");
    for i in 0..50 {
        h.write(g, 0, &format!("n{i}"), "");
    }
    let (t1, t2) = (h.start(g), h.start(g));
    h.ok(g, MsgType::Rm, t1, b"n0\0");
    h.ok(g, MsgType::Rm, t2, b"n0\0");
    h.end(g, t2, false).unwrap();
    h.end(g, t1, true).unwrap();
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 50/100");
}

/// `transaction_bytes_max`: a guest's open transactions, together, keep
/// at most about that many bytes; a request in any of them is refused
/// with EQUOTA, before it runs, once they do. Ending one gives its bytes
/// back. Domain 0 and sockets are not held to it, nor anybody without
/// `quota-activate`.
#[test]
fn a_guest_s_transactions_keep_at_most_their_quota_of_bytes() {
    let cfg = Config {
        transaction_bytes_max: Some(4096),
        ..Config::default()
    };
    let (mut h, a, g) = with_guest(cfg.clone());
    let value = "v".repeat(100);
    let (t, t2) = (h.start(g), h.start(g));
    let mut accepted = 0;
    let refused = loop {
        let r = h.call(g, MsgType::Write, t, &wr("x", &format!("{accepted}{value}")));
        if r.0 != ty(MsgType::Write) {
            break r;
        }
        accepted += 1;
    };
    assert_eq!(refused.3, b"EQUOTA\0");
    let kept = h.core.transaction_bytes(g);
    assert!(
        (4096..4096 + 512).contains(&kept),
        "{kept} bytes after {accepted} writes"
    );
    assert!(accepted > 5, "{accepted}");
    // All its transactions, every request, are refused; the refused one
    // did not run.
    assert_eq!(h.err(g, MsgType::Read, t2, b"x\0"), "EQUOTA");
    assert_eq!(h.err(g, MsgType::Read, t, b"x\0"), "EQUOTA");
    assert_eq!(h.core.transaction_bytes(g), kept);
    h.core.audit().unwrap();
    // Outside a transaction, it is not held.
    h.write(g, 0, "y", "1");
    // Ending a transaction gives its bytes back.
    assert_eq!(h.end(g, t2, false), Ok(()));
    assert_eq!(h.core.transaction_bytes(g), kept);
    assert_eq!(h.end(g, t, true), Ok(()));
    assert_eq!(h.core.transaction_bytes(g), 0);
    assert_eq!(
        h.read(a, 0, "/local/domain/5/x").unwrap(),
        format!("{}{value}", accepted - 1)
    );
    let t = h.start(g);
    h.write(g, t, "x", "again");
    assert!(h.core.transaction_bytes(g) < 1024);
    // Domain 0, without the quota, and without `quota-activate`.
    let no_limit = Config {
        transaction_bytes_max: None,
        ..cfg.clone()
    };
    let no_quotas = Config {
        quota_activate: false,
        ..cfg.clone()
    };
    for (cfg, guest) in [(cfg.clone(), false), (no_limit, true), (no_quotas, true)] {
        let (mut h, a, g) = with_guest(cfg);
        let c = if guest { g } else { a };
        let t = h.start(c);
        for i in 0..100 {
            h.write(c, t, "/local/domain/5/x", &format!("{i}{value}"));
        }
        assert!(h.core.transaction_bytes(c) > 4096 * 2);
        assert_eq!(h.end(c, t, true), Ok(()));
    }
}

#[test]
fn what_a_transaction_keeps_is_counted_once_per_listing_and_value() {
    // A listing seen again is kept once, and counted once; a long path,
    // a value and permissions that are not inline are counted.
    let (mut h, a, g) = with_guest(Config::default());
    for i in 0..50 {
        h.write(a, 0, &format!("/local/domain/5/d/name-number-{i:04}-long"), "");
    }
    let t = h.start(g);
    let cost = |h: &mut H, req: &dyn Fn(&mut H)| {
        let before = h.core.transaction_bytes(g);
        req(h);
        h.core.transaction_bytes(g) - before
    };
    let first = cost(&mut h, &|h| _ = h.ok(g, MsgType::Directory, t, b"d\0"));
    let again = cost(&mut h, &|h| _ = h.ok(g, MsgType::Directory, t, b"d\0"));
    let entry = cost(&mut h, &|h| _ = h.ok(g, MsgType::Read, t, b"d\0"));
    assert!(first > again + 50 * 22, "{first} {again}");
    assert_eq!(again, entry, "a listing seen again costs its entry only");
    let long = "l".repeat(40);
    let path = cost(&mut h, &|h| {
        _ = h.err(g, MsgType::Read, t, format!("{long}\0").as_bytes())
    });
    assert_eq!(path, entry + 40 + "/local/domain/5/".len() + 16);
    let value = cost(&mut h, &|h| h.write(g, t, "d", &"v".repeat(100)));
    assert_eq!(value, entry + 100 + 16);
    let read = cost(&mut h, &|h| _ = h.ok(g, MsgType::Read, t, b"d\0"));
    assert_eq!(read, entry + 100 + 16, "the value, shared until the store changes it");
    let acl = cost(&mut h, &|h| _ = h.ok(g, MsgType::SetPerms, t, b"d\0n5\0r6\0r7\0"));
    assert!(acl > entry + 16, "{acl}");
    let perms = cost(&mut h, &|h| _ = h.ok(g, MsgType::GetPerms, t, b"d\0"));
    assert_eq!(perms, entry, "permissions are shared");
    h.core.audit().unwrap();
}

#[test]
fn transactions_cannot_together_exceed_a_quota() {
    // Each sees the store's count and its own nodes; a commit that must be
    // re-executed is checked again, and fails if the room is gone: quotas
    // are re-checked at commit, across all of the guest's open transactions.
    let (mut h, a, g) = guest_with_quota(4);
    let (t1, t2) = (h.start(g), h.start(g));
    for t in [t1, t2] {
        for p in ["x", "y", "z"] {
            h.write(g, t, &format!("{p}{t}"), "");
        }
        assert_eq!(h.err(g, MsgType::Write, t, &wr("w", "")), "EQUOTA");
    }
    h.end(g, t1, true).unwrap();
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 4/4");
    assert_eq!(h.end(g, t2, true), Err("EAGAIN".into()));
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 4/4");
    // What others remove meanwhile makes room: the store's count now.
    let t = h.start(g);
    h.ok(a, MsgType::Rm, 0, format!("/local/domain/5/x{t1}\0").as_bytes());
    h.write(g, t, "new", "");
    assert_eq!(h.err(g, MsgType::Write, t, &wr("new2", "")), "EQUOTA");
    h.end(g, t, true).unwrap();
}

#[test]
fn quota_activate_off_lifts_sizes_nodes_watches_and_acls_only() {
    // `ox/quota.ml:58-60`, `ox/connection.ml:278`; the transaction and
    // request quotas do not look at it (`ox/connection.ml:383`, `ox/transaction.ml:151`).
    let cfg = Config {
        quota_activate: false,
        entity_max: 1,
        watch_max: Some(0),
        acl_max: 0,
        transaction_max: Some(0),
        request_max: Some(2),
        ..Config::default()
    };
    let (mut h, a, g) = with_guest(cfg);
    h.write(g, 0, "big", &"v".repeat(4000));
    h.write(g, 0, "a/b/c", "");
    h.watch(g, "a", "1");
    h.watch(g, "b", "2");
    h.ok(g, MsgType::SetPerms, 0, b"a\0n5\0r1\0r2\0");
    assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 5/1", "still counted");
    let t = h.start(g);
    assert_eq!(h.err(g, MsgType::TransactionStart, 0, b"\0"), "EQUOTA");
    h.read(g, t, "a").unwrap();
    h.read(g, t, "a").unwrap();
    assert_eq!(h.err(g, MsgType::Read, t, b"a\0"), "EQUOTA");
}

#[test]
fn domain_0_and_a_domain_acting_for_it_are_not_held_and_a_stub_domain_shares_its_guest_s_quota() {
    let cfg = Config {
        entity_max: 2,
        watch_max: Some(0),
        transaction_max: Some(0),
        request_max: Some(1),
        acl_max: 0,
        ..Config::default()
    };
    let (mut h, a, g) = with_guest(cfg);
    let stub = h.core.open_domain(7);
    let d0 = h.core.open_domain(0);
    h.ok(a, MsgType::SetTarget, 0, b"7\x000\0");
    for c in [a, d0, stub] {
        for i in 0..3 {
            h.write(c, 0, &format!("/local/domain/5/{}-{i}", c.0), "");
            h.watch(c, &format!("/w{i}"), "t");
        }
        h.ok(c, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0r1\0");
        let t = h.start(c);
        h.start(c);
        h.read(c, t, "/local").unwrap();
        h.read(c, t, "/local").unwrap();
    }
    // Acting for domain 5: held, to domain 5's quota.
    h.ok(a, MsgType::SetTarget, 0, b"7\x005\0");
    assert_eq!(h.err(stub, MsgType::Write, 0, &wr("/local/domain/5/s", "")), "EQUOTA");
    assert_eq!(h.err(g, MsgType::Write, 0, &wr("s", "")), "EQUOTA");
    h.ok(stub, MsgType::ResetWatches, 0, b"\0");
    h.watch(stub, "/s", "t");
    assert_eq!(h.err(stub, MsgType::Watch, 0, b"/s2\0t\0"), "EQUOTA");
}

#[test]
fn xsa_326d_a_guest_s_watches_are_bounded_by_quota_maxwatch() {
    // `con.nb_watches > !Define.maxwatch` (`ox/connection.ml:277-280`):
    // one more than the quota; exactly the quota in the native profile.
    // Checked after the path, before EEXIST. Tokens as long as a payload
    // allows cost what the quota bounds.
    let (mut h, a, g) = with_guest(Config {
        watch_max: Some(3),
        ..Config::default()
    });
    let allowed = if rules().exact_counts { 3 } else { 4 };
    let token = "t".repeat(PAYLOAD_MAX - 30);
    h.watch(g, "/nowhere/1", &token);
    h.watch(g, "/nowhere/1", "other token");
    if allowed == 4 {
        h.watch(g, "@releaseDomain", "s");
    }
    h.watch(g, "rel", "r");
    assert_eq!(h.core.conns.map[&g].watches, allowed);
    for p in [&b"/nowhere/2\0t\0"[..], b"/nowhere/1\0other token\0"] {
        assert_eq!(h.err(g, MsgType::Watch, 0, p), quota_error());
    }
    assert_eq!(h.err(g, MsgType::Watch, 0, b"/bad path\0t\0"), "EINVAL");
    h.ok(g, MsgType::Unwatch, 0, b"rel\0r\0");
    h.watch(g, "/n", "t");
    assert_eq!(h.err(g, MsgType::Watch, 0, b"/n2\0t\0"), quota_error());
    h.ok(g, MsgType::ResetWatches, 0, b"\0");
    for i in 0..allowed {
        h.watch(g, &format!("/n{i}"), "t");
    }
    assert_eq!(h.err(g, MsgType::Watch, 0, b"/n9\0t\0"), quota_error());
    h.core.reconnect(g);
    h.drain();
    h.watch(g, "/again", "t");
    // A watch on a path no node may have is refused (oxenstored takes it).
    let long = format!("{}\0t\0", "x".repeat(2049));
    assert_eq!(h.err(g, MsgType::Watch, 0, format!("/{long}").as_bytes()), "EINVAL");
    assert_eq!(
        h.err(g, MsgType::Watch, 0, long.as_bytes()),
        "EINVAL",
        "relative: the part after the home"
    );
    assert_eq!(h.err(g, MsgType::Watch, 0, format!("@{long}").as_bytes()), "EINVAL");
    h.watch(g, &"x".repeat(2048), "t");
    h.watch(a, &format!("/{}", "x".repeat(2049)), "t");
    for i in 0..10 {
        h.watch(a, &format!("/a{i}"), "t");
    }
}

#[test]
fn xsa_326e_a_guest_s_open_transactions_are_bounded_by_quota_transaction() {
    // `Hashtbl.length con.transactions > !Define.maxtransaction`
    // (`ox/connection.ml:382-385`): one more than the quota; exactly the
    // quota in the native profile. After EBUSY.
    let (mut h, a, g) = with_guest(Config {
        transaction_max: Some(2),
        ..Config::default()
    });
    let allowed = if rules().exact_counts { 2 } else { 3 };
    let ts: Vec<u32> = (0..allowed).map(|_| h.start(g)).collect();
    assert_eq!(h.err(g, MsgType::TransactionStart, 0, b"\0"), quota_error());
    assert_eq!(h.err(g, MsgType::TransactionStart, ts[0], b"\0"), "EBUSY");
    h.end(g, ts[1], false).unwrap();
    h.start(g);
    assert_eq!(h.err(g, MsgType::TransactionStart, 0, b"\0"), quota_error());
    h.ok(g, MsgType::ResetWatches, 0, b"\0");
    h.start(g);
    // Domain 0 is not held.
    for _ in 0..10 {
        h.start(a);
    }
}

#[test]
fn xsa_326e_a_transaction_takes_maxrequests_requests_then_nothing_not_even_its_end() {
    // `ox/transaction.ml:150-157`, checked first (`ox/process.ml:416`)
    // and counted only if it passed (`ox/process.ml:708-713`): every
    // request in the transaction counts, whatever it is or answers.
    let (mut h, a, g) = with_guest(Config {
        request_max: Some(4),
        ..Config::default()
    });
    let t = h.start(g);
    h.write(g, t, "x", "");
    assert_eq!(h.err(g, MsgType::Read, t, b"/tool\0"), "EACCES");
    h.ok(g, MsgType::GetDomainPath, t, b"5\0");
    // Watches ignore the transaction.
    let out = h.raw(g, ty(MsgType::Watch), t, b"w\0t\0");
    assert_eq!(out[0].1 .3, b"OK\0");
    assert_eq!(h.err(g, MsgType::Read, t, b"bad path\0"), "EINVAL");
    for (ty, p) in [
        (MsgType::Read, &b"x\0"[..]),
        (MsgType::Write, b"y\0"),
        (MsgType::TransactionStart, b"\0"),
        (MsgType::TransactionEnd, b"T\0"),
        (MsgType::TransactionEnd, b"F\0"),
    ] {
        assert_eq!(h.err(g, ty, t, p), quota_error(), "{ty:?}");
    }
    // The log did not grow; the transaction stays open until reset.
    assert_eq!(h.core.conns.map[&g].txns[&t].log.len(), 2);
    assert_eq!(h.core.transactions(g), 1);
    assert_eq!(
        h.call(g, MsgType::Read, 77, b"x\0").3,
        b"EIO\0",
        "an unknown transaction is still EIO"
    );
    h.read(g, 0, "/local/domain/5").unwrap();
    h.ok(g, MsgType::ResetWatches, 0, b"\0");
    assert_eq!(h.core.transactions(g), 0);
    // Domain 0 is not held.
    let t = h.start(a);
    for _ in 0..10 {
        h.read(a, t, "/").unwrap();
    }
    // With 0, a guest gets nothing done at all.
    let (mut h, _, g) = with_guest(Config {
        request_max: Some(0),
        ..Config::default()
    });
    assert_eq!(h.err(g, MsgType::Read, 0, b"/local/domain/5\0"), quota_error());
    assert_eq!(h.err(g, MsgType::Watch, 0, b"w\0t\0"), quota_error());
    // Without a limit.
    let (mut h, _, g) = with_guest(Config {
        request_max: None,
        ..Config::default()
    });
    let t = h.start(g);
    for _ in 0..2000 {
        h.read(g, t, "/local/domain/5").unwrap();
    }
}

#[test]
fn xsa_326a_a_guest_that_does_not_read_its_replies_has_at_most_maxoutstanding() {
    // `xb/xb.ml:246-248`: a request is read only if its reply has room.
    let (mut h, _, g) = with_guest(Config::default());
    h.write(g, 0, "x", "v");
    for _ in 0..2000 {
        h.push(g, ty(MsgType::Read), 0, b"x\0");
    }
    let first = h.req - 1999;
    let mut got = Vec::new();
    for round in 0.. {
        assert!(round < 10, "it never ends");
        let st = h.core.process(g, 5000);
        h.core.audit().unwrap();
        let out = h.drain_one(g);
        assert!(out.len() <= 1024);
        got.extend(out);
        match st {
            Status::Blocked => assert!(!h.core.wants_input(g) || h.core.output(g).is_empty()),
            Status::Idle => break,
            s => panic!("{s:?}"),
        }
    }
    let ids: Vec<u32> = got.iter().map(|m| m.1).collect();
    assert_eq!(ids, (first..first + 2000).collect::<Vec<_>>(), "all, in order");
}

#[test]
fn a_reply_begun_is_no_longer_outstanding() {
    // oxenstored takes a packet off the queue as it starts writing it (`xb/xb.ml:227-244`).
    let (mut h, a, _) = with_guest(Config {
        outstanding_max: 2,
        ..Config::default()
    });
    for _ in 0..3 {
        h.push(a, ty(MsgType::Read), 0, b"/tool/xenstored\0");
    }
    assert_eq!(h.core.process(a, 10), Status::Blocked, "sockets too");
    assert!(!h.core.wants_input(a));
    h.core.consume(a, 0);
    assert!(!h.core.wants_input(a));
    h.core.consume(a, 1);
    assert!(h.core.wants_input(a));
    assert_eq!(h.core.process(a, 10), Status::Blocked, "two again");
    assert_eq!(h.core.output(a).len(), 3 * 26 - 1);
}

/// Writes `p` on `g` until its requests stop being processed (at most
/// `max` times), reading what `g` gets; how many it made.
fn flood(h: &mut H, g: ConnId, p: &str, max: usize) -> usize {
    for i in 1..=max {
        h.push(g, ty(MsgType::Write), 0, &wr(p, "v"));
        let st = h.core.process(g, 10);
        h.drain_one(g);
        if st == Status::Blocked {
            h.core.audit().unwrap();
            return i;
        }
    }
    max
}

#[test]
fn xsa_326b_a_guest_flooding_a_socket_that_does_not_read_is_held_and_the_socket_kept() {
    // oxenstored holds the source of events the watcher cannot take
    // (`ox/connection.ml:329-339, 409`); the watcher is never dropped.
    let (mut h, tool, g) = with_guest(Config::default());
    h.watch(tool, "/local/domain/5/data", "w");
    h.drain();
    // (However long the flood, the guest is held long before 2,000 writes.)
    let n = flood(&mut h, g, "data/x", 2000);
    assert_eq!(n, 1025, "the event that overflows is queued, then the guest waits");
    let event = 16 + "/local/domain/5/data/x\0w\0".len();
    assert_eq!(h.core.output(tool).len(), 1025 * event);
    let mut dead = Vec::new();
    h.core.take_dead(&mut dead);
    assert!(dead.is_empty());
    assert!(!h.core.wants_input(g));
    assert_eq!(h.core.process(g, 10), Status::Blocked);
    // The socket reads some: not enough, then enough.
    h.core.take_dirty(&mut Vec::new());
    h.core.consume(tool, event);
    assert!(!h.core.wants_input(g));
    let mut dirty = Vec::new();
    h.core.take_dirty(&mut dirty);
    assert!(!dirty.contains(&g));
    h.core.consume(tool, event);
    assert!(h.core.wants_input(g));
    h.core.take_dirty(&mut dirty);
    assert!(dirty.contains(&g), "reported, so that it gets a turn");
    assert_eq!(flood(&mut h, g, "data/x", 10), 2, "one under the limit, one over");
    assert_eq!(h.core.conns.dropped, 0, "a privileged watcher loses nothing");
}

#[test]
fn xsa_326c_a_guest_flooding_a_guest_that_does_not_read_is_held_and_domain_0_never() {
    let cfg = Config {
        watch_event_max: 8,
        ..Config::default()
    };
    let (mut h, a, g) = with_guest(cfg);
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0");
    let sink = h.core.open_domain(6);
    h.watch(sink, "/local/domain/5/data", "w");
    assert_eq!(flood(&mut h, g, "data/x", 1000), 9, "8 under the limit, 1 over");
    assert_eq!(h.core.conns.map[&sink].out.events, 9);
    // Domain 0's events are queued up to twice the limit, then dropped;
    // domain 0 never waits.
    for _ in 0..100 {
        assert_eq!(
            h.send(a, ty(MsgType::Write), 0, &wr("/local/domain/5/data/y", "v")),
            Status::Idle
        );
        h.drain_one(a);
    }
    assert_eq!(h.core.conns.map[&sink].out.events, 16);
    assert_eq!(h.core.conns.dropped, 93);
    let mut drops = Vec::new();
    h.core.take_drops(&mut drops);
    assert_eq!(drops, [Drops::Started(log::Who::Domain(6))], "once, not per event");
    // Reading nothing does not end the streak.
    h.core.consume(sink, 0);
    h.core.take_drops(&mut drops);
    assert_eq!(drops.len(), 1);
    // The sink reads: the guest goes on, and the streak ends with its count.
    h.drain_one(sink);
    assert!(h.core.wants_input(g));
    h.core.take_drops(&mut drops);
    assert_eq!(
        drops,
        [
            Drops::Started(log::Who::Domain(6)),
            Drops::Ended(log::Who::Domain(6), 93)
        ]
    );
    // The special watches fired by the daemon are never held either.
    h.watch(sink, "@releaseDomain", "r");
    h.ok(a, MsgType::SetPerms, 0, b"@releaseDomain\0n0\0r6\0");
    for _ in 0..20 {
        h.core.fire_special(b"@releaseDomain");
    }
    assert_eq!(h.core.conns.map[&sink].out.events, 16);
}

#[test]
fn a_watcher_that_lost_no_event_is_never_reported() {
    let cfg = Config {
        watch_event_max: 2,
        ..Config::default()
    };
    let (mut h, a, _) = with_guest(cfg);
    h.write(a, 0, "/w", "");
    h.ok(a, MsgType::SetPerms, 0, b"/w\0n0\0r6\0");
    let mut drops = Vec::new();
    for gone in ["closed", "ignored", "reconnected"] {
        let sink = h.core.open_domain(6);
        h.watch(sink, "/w", "w");
        h.drain();
        // Up to twice the limit unsent: kept, then read.
        for i in 0..4 {
            assert_eq!(
                h.send(a, ty(MsgType::Write), 0, &wr("/w", &i.to_string())),
                Status::Idle
            );
            h.drain_one(a);
        }
        assert_eq!(h.core.conns.map[&sink].out.events, 4, "{gone}");
        h.drain_one(sink);
        match gone {
            "closed" => h.core.close(sink),
            "ignored" => h.core.ignore(sink),
            _ => h.core.reconnect(sink),
        }
        h.core.close(sink);
        h.core.take_drops(&mut drops);
        assert_eq!(drops, [], "{gone}");
    }
}

#[test]
fn a_streak_of_dropped_events_ends_when_its_watcher_is_gone() {
    let cfg = Config {
        watch_event_max: 2,
        ..Config::default()
    };
    let (mut h, a, _) = with_guest(cfg);
    h.write(a, 0, "/w", "");
    h.ok(a, MsgType::SetPerms, 0, b"/w\0n0\0r6\0");
    let mut drops = Vec::new();
    for gone in ["closed", "ignored", "reconnected"] {
        let sink = h.core.open_domain(6);
        h.watch(sink, "/w", "w");
        h.drain();
        for i in 0..7 {
            assert_eq!(
                h.send(a, ty(MsgType::Write), 0, &wr("/w", &i.to_string())),
                Status::Idle
            );
            h.drain_one(a);
        }
        assert_eq!(h.core.conns.map[&sink].out.events, 4, "{gone}");
        match gone {
            "closed" => h.core.close(sink),
            "ignored" => h.core.ignore(sink),
            _ => h.core.reconnect(sink),
        }
        h.core.take_drops(&mut drops);
        let who = log::Who::Domain(6);
        assert_eq!(drops, [Drops::Started(who), Drops::Ended(who, 3)], "{gone}");
        drops.clear();
        // Ended once: nothing more when it goes for good.
        h.core.close(sink);
        h.core.take_drops(&mut drops);
        assert_eq!(drops, [], "{gone}");
    }
}

#[test]
fn xsa_326f_a_guest_removing_what_a_socket_watches_is_held_too() {
    let (mut h, tool, g) = with_guest(Config {
        watch_event_max: 16,
        ..Config::default()
    });
    for i in 0..100 {
        h.write(g, 0, &format!("data/{i}"), "");
    }
    h.watch(tool, "/local/domain/5/data", "w");
    for i in 0..100 {
        h.watch(tool, &format!("/local/domain/5/data/{i}"), "w");
    }
    h.drain();
    h.push(g, ty(MsgType::Rm), 0, b"data\0");
    assert_eq!(h.core.process(g, 10), Status::Blocked, "one removal fires 101 events");
    assert_eq!(h.core.conns.map[&tool].out.events, 101);
    h.drain_one(tool);
    assert!(h.core.wants_input(g));
}

#[test]
fn a_guest_s_own_events_hold_it_until_it_reads_them() {
    // Its own events have it as their source (`ox/process.ml:526-529`).
    let (mut h, _, g) = with_guest(Config {
        watch_event_max: 4,
        ..Config::default()
    });
    h.watch(g, "data", "w");
    for _ in 0..6 {
        h.push(g, ty(MsgType::Write), 0, &wr("data", "v"));
    }
    assert_eq!(h.core.process(g, 10), Status::Blocked, "4 events, then 1 over");
    assert_eq!(h.core.conns.map[&g].out.events, 5);
    assert_eq!(h.core.conns.map[&g].out.replies, 5);
    h.drain_one(g);
    assert_eq!(h.core.process(g, 10), Status::Idle, "the sixth");
    h.drain_one(g);
    // Registering a watch fires one too.
    for i in 0..5 {
        h.push(g, ty(MsgType::Watch), 0, format!("w{i}\0t\0").as_bytes());
    }
    assert_eq!(h.core.process(g, 10), Status::Blocked);
    assert_eq!(h.core.watches(), 6);
}

#[test]
fn closing_or_resetting_a_watcher_lets_those_it_held_go_and_a_held_one_stays_held() {
    let cfg = Config {
        watch_event_max: 2,
        ..Config::default()
    };
    let (mut h, a, g) = with_guest(cfg);
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0r7\0");
    let (s6, s7) = (h.core.open_domain(6), h.core.open_domain(7));
    h.watch(s6, "/local/domain/5/data", "w");
    h.watch(s7, "/local/domain/5/data", "w");
    assert_eq!(flood(&mut h, g, "data", 100), 3);
    assert_eq!(h.core.conns.map[&g].holds, 2, "two watchers, one wait each");
    // Its own reconnection does not free it.
    h.core.reconnect(g);
    assert!(!h.core.wants_input(g));
    h.core.reconnect(s6);
    assert!(!h.core.wants_input(g), "one to go");
    let mut dirty = Vec::new();
    h.core.take_dirty(&mut dirty);
    h.core.close(s7);
    h.core.take_dirty(&mut dirty);
    assert!(h.core.wants_input(g) && dirty.contains(&g));
    // Closing the held one, then the watcher reads.
    h.watch(s6, "/local/domain/5/data", "w");
    assert_eq!(flood(&mut h, g, "data", 100), 3);
    h.core.close(g);
    h.drain_one(s6);
    h.core.reconnect(a);
    h.core.audit().unwrap();
}

#[test]
fn one_request_holds_its_source_once_per_watcher() {
    let (mut h, _, g) = with_guest(Config {
        watch_event_max: 1,
        ..Config::default()
    });
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0");
    let w = h.core.open_domain(6);
    for t in ["1", "2", "3"] {
        h.watch(w, "/local/domain/5/data", t);
    }
    h.push(g, ty(MsgType::Write), 0, &wr("data", "v"));
    assert_eq!(h.core.process(g, 10), Status::Blocked);
    assert_eq!((h.core.conns.map[&w].waiters.len(), h.core.conns.map[&g].holds), (1, 1));
    h.core.audit().unwrap();
}

#[test]
fn a_guest_s_acl_has_at_most_acl_max_entries() {
    // oxenstored takes what fits in a payload: an ACL ~5 times dearer
    // than a value.
    let (mut h, a, g) = with_guest(Config {
        acl_max: 3,
        ..Config::default()
    });
    h.ok(g, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0r1\0r2\0r3\0");
    assert_eq!(
        h.err(g, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0r1\0r2\0r3\0r4\0"),
        "EQUOTA"
    );
    h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5\0n5\0r1\0r2\0r3\0r4\0");
}

#[test]
fn a_ring_s_long_listing_stops_where_it_cannot_be_sent() {
    let node = Node::new(Arc::new(Perms::default0()), Bytes::EMPTY, 0);
    let mut m = pmap::PMap::new();
    for i in 0..10 {
        m.insert(Name::from(format!("{i:010}").as_bytes()), node.clone());
    }
    assert_eq!(names(&m, 21).len(), 22, "two names: past the limit");
    assert_eq!(names(&m, 22).len(), 33);
    assert_eq!(names(&m, usize::MAX).len(), 110);
}

#[test]
fn a_partial_request_waits_and_an_oversized_one_ends_the_ring() {
    let (mut h, _, g) = with_guest(Config::default());
    let mut bytes = Vec::new();
    write_header(&mut bytes, ty(MsgType::Write), 1, 0, 4096);
    bytes.extend_from_slice(b"data\0");
    h.core.feed(g, &bytes);
    assert_eq!(h.core.process(g, 10), Status::Idle);
    h.core.feed(g, &[b'v'; 4091]);
    assert_eq!(h.core.process(g, 10), Status::Idle);
    assert_eq!(h.drain_one(g)[0].3, b"E2BIG\0");
    let mut bytes = Vec::new();
    write_header(&mut bytes, ty(MsgType::Write), 1, 0, 4097);
    h.core.feed(g, &bytes);
    assert_eq!(h.core.process(g, 10), Status::Closed);
}

#[test]
fn the_auditor_finds_every_miscount() {
    let (mut h, a, g) = with_guest(Config::default());
    let t = h.start(a);
    h.write(a, t, "/x", "");
    h.watch(g, "w", "t");
    assert_eq!(h.core.audit(), Ok(()));
    type Spoil = fn(&mut Core, ConnId, ConnId, u32);
    let spoils: [(Spoil, &str); 13] = [
        (|c, _, _, _| Acct::Store(&mut c.entries).add(9, 1), "store"),
        (
            |c, a, _, t| {
                Acct::Txn(
                    &Entries::default(),
                    &mut c.conns.map.get_mut(&a).unwrap().txns.get_mut(&t).unwrap().delta,
                )
                .add(0, 1)
            },
            "transaction",
        ),
        (|c, _, g, _| c.conns.map.get_mut(&g).unwrap().watches += 1, "watches"),
        (|c, _, g, _| c.conns.map.get_mut(&g).unwrap().out.events += 1, "watches"),
        (
            |c, _, g, _| c.conns.map.get_mut(&g).unwrap().out.replies += 1,
            "watches",
        ),
        (|c, _, g, _| c.conns.map.get_mut(&g).unwrap().holds += 1, "holds"),
        (
            |c, a, _, t| c.conns.map.get_mut(&a).unwrap().txns.get_mut(&t).unwrap().bytes += 1,
            "bytes counted",
        ),
        (
            |c, _, g, _| _ = c.conns.map.get_mut(&g).unwrap().out.from.insert(ConnId(99), 1),
            "events by source counted {ConnId(99): 1}, are {}",
        ),
        (
            |c, _, g, _| c.conns.map.get_mut(&g).unwrap().credit = 3.0,
            "credit 3, queued 0 paused and 0 penalised",
        ),
        (|c, a, _, _| c.conns.map.get_mut(&a).unwrap().credit = 3.0, "credit 3"),
        (|c, _, _, _| c.conflicts.open += 1, "2 transactions counted open, 1 are"),
        (
            |c, _, _, _| _ = c.conflicts.ended.insert(99),
            "transaction 99 ended, not young",
        ),
        (
            |c, a, _, _| c.conflicts.paused.push_back(a),
            "queued, not open or not blamable",
        ),
    ];
    for (spoil, what) in spoils {
        let (mut h, a, g) = with_guest(Config::default());
        let t = h.start(a);
        h.write(a, t, "/x", "");
        h.watch(g, "w", "t");
        spoil(&mut h.core, a, g, t);
        let e = h.core.audit().unwrap_err();
        assert!(e.contains(what), "{e}");
    }
    let (mut h, _, _) = with_guest(Config {
        conflict_rate_limit_is_aggregate: false,
        ..Config::default()
    });
    h.core.conflicts.n_paused += 1;
    assert!(h.core.audit().unwrap_err().contains("1 counted paused, 0 are"));
    let (mut h, _, g) = with_guest(Config {
        conflict_rate_limit_is_aggregate: false,
        ..Config::default()
    });
    h.core.conns.map.get_mut(&g).unwrap().credit = 3.0;
    assert!(h
        .core
        .audit()
        .unwrap_err()
        .contains("credit 3, queued 0 paused and 0 penalised"));
}

#[test]
fn a_watcher_its_own_commit_overflows_gets_no_reply() {
    // The events come first (`ox/process.ml:567-569`); past the hard
    // limit the connection gets nothing more.
    // Domain 0 is never given up on: it gets its events and its reply.
    for guest in [true, false] {
        let (mut h, a, g) = with_guest(Config {
            output_hard_limit: 100,
            ..Config::default()
        });
        let c = if guest { g } else { a };
        h.watch(c, "/local/domain/5/o", "t");
        let t = h.start(c);
        for _ in 0..10 {
            h.write(c, t, "/local/domain/5/o", "v");
        }
        h.push(c, ty(MsgType::TransactionEnd), t, b"T\0");
        let mut dead = Vec::new();
        let out = if guest {
            assert_eq!(h.core.process(c, 10), Status::Closed);
            h.core.take_dead(&mut dead);
            assert_eq!(dead, [(c, GaveUp::Overflow)]);
            h.drain_one(c)
        } else {
            assert_eq!(h.core.process(c, 10), Status::Idle);
            h.core.take_dead(&mut dead);
            assert_eq!(dead, []);
            h.drain_one(c)
        };
        let replies = out.iter().filter(|m| m.0 != ty(MsgType::WatchEvent)).count();
        assert_eq!(replies, usize::from(!guest), "guest {guest}");
    }
}

// ---------------------------------------------------------------- XSA-206

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn credit(h: &H, c: ConnId) -> f64 {
    h.core.conns.map[&c].credit
}

/// One round of the starvation test: a socket's transaction reads a node of
/// domain 5 and writes elsewhere; `g` rewrites the node; then the commit.
fn starve(h: &mut H, a: ConnId, g: ConnId, i: usize) -> (Result<(), String>, Status) {
    let t = h.start(a);
    h.read(a, t, "/local/domain/5/data/x").unwrap();
    h.write(a, t, "/local/domain/0/y", &i.to_string());
    let st = h.send(g, ty(MsgType::Write), 0, &wr("data/x", &i.to_string()));
    (h.end(a, t, true), st)
}

#[test]
fn xsa_206_a_guest_that_keeps_failing_a_transaction_is_held_until_credit_comes_back() {
    let (mut h, a, g) = with_guest(Config::default());
    h.write(a, 0, "/local/domain/5/data/x", "");
    let rounds: Vec<_> = (0..50).map(|i| starve(&mut h, a, g, i)).collect();
    let again = (Err("EAGAIN".to_string()), Status::Idle);
    // `conflict-burst-limit` conflicts, then its requests wait: the commit goes through.
    assert_eq!(
        rounds[..5],
        [again.clone(), again.clone(), again.clone(), again.clone(), again]
    );
    assert!(
        rounds[5..].iter().all(|r| *r == (Ok(()), Status::Blocked)),
        "{rounds:?}"
    );
    assert_eq!(credit(&h, g), 0.0);
    // Held, not refused: once a period has gone it gets a point, and its
    // 45 writes are answered without anything new from it.
    assert_eq!(h.core.next_tick(), Some(ms(50)), "a period after the first pause");
    h.core.tick(ms(49));
    assert!(!h.core.wants_input(g));
    h.core.tick(ms(50));
    let mut dirty = Vec::new();
    h.core.take_dirty(&mut dirty);
    assert_eq!(dirty, [g]);
    assert_eq!(h.core.process(g, 1000), Status::Idle);
    let out = h.drain_one(g);
    assert_eq!(out.len(), 45);
    assert!(out.iter().all(|m| m.3 == b"OK\0"));
    assert_eq!(h.read(a, 0, "/local/domain/5/data/x").unwrap(), "49");
    // One point: one more conflict and it waits again.
    assert_eq!((credit(&h, g), h.core.next_tick()), (1.0, Some(ms(100))));
    assert_eq!(starve(&mut h, a, g, 50).0, Err("EAGAIN".into()));
    assert_eq!(starve(&mut h, a, g, 51), (Ok(()), Status::Blocked));
}

#[test]
fn xsa_206_a_domain_0_transaction_commits_while_a_guest_hammers_what_it_read() {
    // One point per period: one failure per period once the burst is spent.
    let (mut h, a, g) = with_guest(Config::default());
    h.write(a, 0, "/local/domain/5/data/x", "");
    let (mut run, mut longest, mut commits) = (0, 0, 0);
    for i in 0..400 {
        h.core.tick(ms(10 * i as u64));
        h.core.process(g, 1000);
        h.drain_one(g);
        match starve(&mut h, a, g, i).0 {
            Ok(()) => (commits, run) = (commits + 1, 0),
            Err(_) => run += 1,
        }
        longest = longest.max(run);
    }
    assert_eq!(longest, 5, "the burst");
    assert!(commits > 300, "{commits} commits");
}

/// Blame that skips the records a transaction cannot see blames whom blame
/// that judges every record blames (`Conflicts::culprits` with `same`
/// never true: the reference), in the same order,
/// on random histories: four guests writing, creating and removing nodes
/// they share, of their own and below each other, in and out of
/// transactions, a socket writing too, and every commit's culprits
/// computed both ways first.
#[test]
fn xsa_206_blame_that_skips_what_a_transaction_cannot_see_blames_the_same() {
    let seeds: u64 = std::env::var("XS_BLAME_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    let (mut judged, mut blamed, mut skipped, mut commits) = (0usize, 0usize, 0usize, 0usize);
    for seed in 0..seeds {
        let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        let (mut h, a, g5) = with_guest(Config::default());
        let mut guests = vec![(5u32, g5)];
        for d in 6..9 {
            home(&mut h, a, d);
            guests.push((d, h.core.open_domain(d)));
        }
        // Shared nodes every guest may read and write, and one node of
        // each guest that the others may read.
        for s in ["a", "b", "c/d", "e/f/g"] {
            h.write(a, 0, &format!("/s/{s}"), "0");
        }
        h.ok(a, MsgType::SetPerms, 0, b"/s\0n0\0b5\0b6\0b7\0b8\0");
        for s in ["a", "b", "c", "c/d", "e", "e/f", "e/f/g"] {
            let p = format!("/s/{s}\0n0\0b5\0b6\0b7\0b8\0");
            h.ok(a, MsgType::SetPerms, 0, p.as_bytes());
        }
        for &(d, g) in &guests {
            h.write(g, 0, "x", "0");
            h.ok(g, MsgType::SetPerms, 0, format!("x\0n{d}\0r5\0r6\0r7\0r8\0").as_bytes());
        }
        let paths = |next: &mut dyn FnMut(u64) -> u64| -> String {
            match next(9) {
                0 => "/s/a".into(),
                1 => "/s/b".into(),
                2 => "/s/c/d".into(),
                3 => "/s/e/f/g".into(),
                4 => "/s/c".into(),
                5 => format!("/local/domain/{}/x", 5 + next(4)),
                6 => format!("/local/domain/{}/y/z", 5 + next(4)),
                7 => "/s".into(),
                _ => "/s/new".into(),
            }
        };
        let mut open: Vec<(ConnId, u32)> = Vec::new();
        for step in 0..120 {
            let (_, g) = guests[next(4) as usize];
            let p = paths(&mut next);
            let v = step.to_string();
            match next(10) {
                // Outside a transaction: recorded for a guest, not for the socket.
                0..=2 => {
                    h.call(g, MsgType::Write, 0, &wr(&p, &v));
                }
                3 => {
                    h.call(g, MsgType::Rm, 0, format!("{p}\0").as_bytes());
                }
                4 => {
                    h.call(a, MsgType::Write, 0, &wr(&p, &v));
                }
                5 if open.len() < 4 => open.push((g, h.start(g))),
                5..=7 if !open.is_empty() => {
                    let (c, t) = open[next(open.len() as u64) as usize];
                    let msg = match next(5) {
                        0 => MsgType::Read,
                        1 => MsgType::Directory,
                        2 => MsgType::Rm,
                        3 => MsgType::GetPerms,
                        _ => MsgType::Write,
                    };
                    let payload = if msg == MsgType::Write {
                        wr(&p, &v)
                    } else {
                        format!("{p}\0").into_bytes()
                    };
                    h.call(c, msg, t, &payload);
                }
                _ if !open.is_empty() => {
                    let (c, t) = open.swap_remove(next(open.len() as u64) as usize);
                    // Both ways, on the state the commit will meet.
                    let txn = h.core.conns.map.get_mut(&c).unwrap().txns.remove(&t).unwrap();
                    let ctx = h.core.ctx(h.core.conns.map[&c].caller);
                    let reference = h.core.culprits(c, &txn.log, txn.started, &ctx, false);
                    let skipping = h.core.culprits(c, &txn.log, txn.started, &ctx, true);
                    assert_eq!(skipping, reference, "seed {seed}, step {step}");
                    let footprint = txlog::Footprint::of(&txn.log);
                    let same = h
                        .core
                        .conflicts
                        .versions()
                        .filter(|(b, a)| footprint.same(b, a))
                        .count();
                    (judged, skipped) = (judged + h.core.conflicts.records(), skipped + same);
                    blamed += reference.len();
                    h.core.conns.map.get_mut(&c).unwrap().txns.insert(t, txn);
                    commits += usize::from(h.end(c, t, true).is_ok());
                }
                _ => {}
            }
            h.core.audit().unwrap();
        }
    }
    println!("{commits} commits, {judged} records looked at, {skipped} skippable, {blamed} blamed");
    // Both outcomes of a judgment, and both of the skip, are exercised.
    if seeds >= 150 {
        assert!(blamed > 50 && commits > 300, "{blamed} blamed, {commits} commits");
        assert!(skipped > 1000 && skipped < judged, "{skipped} of {judged}");
    }
}

#[test]
fn xsa_206_domain_0_and_sockets_are_never_held() {
    // They are never recorded, so never blamed (`ox/history.ml:46-50`).
    let (mut h, a, g) = with_guest(Config::default());
    let d0 = h.core.open_domain(0);
    h.write(a, 0, "/local/domain/5/x", "");
    for i in 0..20 {
        let t = h.start(g);
        h.read(g, t, "x").unwrap();
        h.write(g, t, "y", "");
        h.write(if i % 2 == 0 { a } else { d0 }, 0, "/local/domain/5/x", &i.to_string());
        assert_eq!(h.core.conflicts.records(), 0);
        assert_eq!(h.end(g, t, true), Err("EAGAIN".into()));
    }
    // Nor is the victim.
    for c in [a, d0, g] {
        assert!(h.core.wants_input(c));
    }
    assert_eq!(
        (credit(&h, a), credit(&h, d0), credit(&h, g)),
        (f64::INFINITY, f64::INFINITY, 5.0)
    );
    assert_eq!((h.core.next_tick(), h.core.conflicts.records()), (None, 0));
}

#[test]
fn xsa_206_an_innocent_guest_is_not_blamed_for_the_conflicts_of_others() {
    let (mut h, a, g5) = with_guest(Config::default());
    home(&mut h, a, 6);
    let g6 = h.core.open_domain(6);
    h.write(a, 0, "/local/domain/5/data/x", "");
    for i in 0..3 {
        // Domain 6 keeps changing its own nodes, in a transaction too,
        // whose commit comes after domain 5's change. (oxenstored 4.17
        // records a commit as the store when the transaction started and
        // the live store, `ox/process.ml:555`, `ox/transaction.ml:122`, and
        // would blame it; here it is the change the commit made.)
        let t6 = h.start(g6);
        h.write(g6, t6, "data/z", &i.to_string());
        let t = h.start(a);
        h.read(a, t, "/local/domain/5/data/x").unwrap();
        h.write(a, t, "/y", "");
        h.write(g6, 0, "data/y", &i.to_string());
        h.write(g5, 0, "data/x", &i.to_string());
        h.write(g6, 0, "data/y", "again");
        h.end(g6, t6, true).unwrap();
        // Domain 5's later change does not count twice.
        h.write(g5, 0, "data/x", &format!("again {i}"));
        assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
    }
    assert_eq!((credit(&h, g5), credit(&h, g6)), (2.0, 5.0));
    // A change made before the transaction started is no cause, even one
    // that would be.
    h.write(a, 0, "/local/domain/5/data/x", "early");
    let hold = h.start(a);
    h.write(g5, 0, "data/x", "1");
    h.write(a, 0, "/local/domain/5/data/x", "early");
    let t = h.start(a);
    h.read(a, t, "/local/domain/5/data/x").unwrap();
    h.write(a, t, "/y", "");
    h.write(a, 0, "/local/domain/5/data/x", "socket");
    assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
    assert_eq!(credit(&h, g5), 2.0);
    h.end(a, hold, false).unwrap();
    // Two guests conflicting with each other: the writer pays, and domain
    // 0 commits meanwhile.
    h.write(a, 0, "/shared", "");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0b5\0b6\0");
    for i in 0..5 {
        let t = h.start(g5);
        h.read(g5, t, "/shared").unwrap();
        h.write(g5, t, "data/w", "");
        h.write(g6, 0, "/shared", &i.to_string());
        assert_eq!(h.end(g5, t, true), Err("EAGAIN".into()));
    }
    assert_eq!((credit(&h, g5), credit(&h, g6)), (2.0, 0.0));
    let t = h.start(a);
    h.read(a, t, "/shared").unwrap();
    h.write(a, t, "/shared", "dom0");
    assert_eq!(
        h.send(g6, ty(MsgType::Write), 0, &wr("/shared", "held")),
        Status::Blocked
    );
    assert_eq!(h.end(a, t, true), Ok(()));
    // A transaction that fails because of its own connection's changes blames nobody.
    let t = h.start(g5);
    h.read(g5, t, "data/x").unwrap();
    h.write(g5, t, "data/w", "");
    h.write(g5, 0, "data/x", "self");
    assert_eq!(h.end(g5, t, true), Err("EAGAIN".into()));
    assert_eq!(credit(&h, g5), 2.0);
}

#[test]
fn xsa_206_a_commit_is_recorded_and_blamed_as_a_change() {
    let (mut h, a, g) = with_guest(Config::default());
    h.write(a, 0, "/local/domain/5/data/x", "");
    let t = h.start(a);
    h.read(a, t, "/local/domain/5/data/x").unwrap();
    h.write(a, t, "/y", "");
    let tg = h.start(g);
    h.write(g, tg, "data/x", "1");
    h.end(g, tg, true).unwrap();
    // A read-only or aborted transaction changes nothing.
    for commit in [true, false] {
        let tg = h.start(g);
        h.read(g, tg, "data/x").unwrap();
        h.end(g, tg, commit).unwrap();
    }
    assert_eq!(h.core.conflicts.records(), 1);
    assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
    assert_eq!(credit(&h, g), 4.0);
}

#[test]
fn xsa_206_history_is_kept_only_for_young_transactions() {
    let (mut h, a, g) = with_guest(Config::default());
    let records = |h: &H| h.core.conflicts.records();
    h.write(g, 0, "data/x", "0");
    assert_eq!(records(&h), 0, "no transaction open: none could need it");
    let t = h.start(a);
    h.read(a, t, "/local/domain/5/data/x").unwrap();
    h.write(a, t, "/y", "");
    h.read(g, 0, "data/x").unwrap();
    h.err(g, MsgType::Write, 0, &wr("/tool/x", ""));
    assert_eq!(records(&h), 0, "nothing changed");
    h.write(g, 0, "data/x", "1");
    h.write(g, 0, "data/x", "2");
    assert_eq!(records(&h), 2);
    // The transaction started at 0 is young until 50 ms; it is trimmed at
    // the first tick due after that.
    h.core.tick(ms(50));
    h.core.tick(ms(99));
    assert_eq!(records(&h), 2);
    h.core.tick(ms(100));
    assert_eq!(records(&h), 0);
    h.write(g, 0, "data/x", "3");
    assert_eq!(records(&h), 1, "kept until the next trim");
    assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
    assert_eq!(credit(&h, g), 5.0, "what made it fail was dropped");
    assert_eq!(records(&h), 0, "the end trims");
    // The oldest young transaction keeps what came after it.
    let t1 = h.start(a);
    h.write(g, 0, "data/x", "4");
    h.core.tick(ms(130));
    let t2 = h.start(a);
    h.write(g, 0, "data/x", "5");
    h.end(a, t1, false).unwrap();
    assert_eq!(records(&h), 1, "what came after the second");
    let b = h.core.open();
    h.start(b);
    h.end(a, t2, false).unwrap();
    assert_eq!(records(&h), 0);
    h.write(g, 0, "data/x", "6");
    // A transaction dropped with its connection stays young until it
    // expires (`ox/transaction.ml:111-119`), but is no longer open.
    h.core.close(b);
    h.write(g, 0, "data/x", "7");
    assert_eq!(records(&h), 1, "no transaction open");
    h.core.tick(ms(150));
    assert_eq!(records(&h), 1);
    // Expired at 180, not trimmed by a tick until 200; a reconnection trims.
    h.core.tick(ms(185));
    assert_eq!(records(&h), 1);
    h.core.reconnect(g);
    assert_eq!(records(&h), 0);
}

#[test]
fn xsa_206_credit_comes_back_a_point_a_period_to_one_domain_or_to_each() {
    for aggregate in [true, false] {
        let cfg = Config {
            conflict_burst_limit: 2.0,
            conflict_rate_limit_is_aggregate: aggregate,
            ..Config::default()
        };
        let (mut h, a, g5) = with_guest(cfg);
        home(&mut h, a, 6);
        home(&mut h, a, 7);
        let (g6, g7) = (h.core.open_domain(6), h.core.open_domain(7));
        // `n` transactions read the homes of `gs`, which then write them:
        // each commit fails and blames each of them once.
        let conflict = |h: &mut H, n: usize, gs: &[(ConnId, u32)]| {
            let ts: Vec<u32> = (0..n)
                .map(|_| {
                    let t = h.start(a);
                    for (_, d) in gs {
                        h.read(a, t, &format!("/local/domain/{d}")).unwrap();
                    }
                    h.write(a, t, "/y", "");
                    t
                })
                .collect();
            for (g, d) in gs {
                h.write(*g, 0, &format!("/local/domain/{d}"), &h.req.to_string());
            }
            for t in ts {
                assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
            }
        };
        h.core.tick(ms(1000));
        conflict(&mut h, 1, &[(g6, 6)]);
        assert_eq!(
            h.core.next_tick(),
            Some(ms(1050)),
            "penalised, not paused: the usual tick"
        );
        h.core.tick(ms(1050));
        assert_eq!((credit(&h, g6), h.core.next_tick()), (2.0, None));
        h.core.tick(ms(1070));
        // 6 down to the floor, then 7 a point, then 5 paused.
        conflict(&mut h, 4, &[(g6, 6)]);
        conflict(&mut h, 1, &[(g7, 7)]);
        h.core.tick(ms(1080));
        conflict(&mut h, 2, &[(g5, 5)]);
        assert_eq!((credit(&h, g5), credit(&h, g6), credit(&h, g7)), (0.0, -1.0, 1.0));
        assert_eq!(h.core.next_tick(), Some(ms(1120)), "a period after the first pause");
        for g in [g5, g6] {
            h.push(g, ty(MsgType::Write), 0, &wr("w", ""));
            assert_eq!(h.core.process(g, 10), Status::Blocked);
        }
        h.drain();
        let mut seen = Vec::new();
        for t in [1119, 1120, 1150, 1170, 1220, 1270, 1320, 1370] {
            h.core.tick(ms(t));
            let mut dirty = Vec::new();
            h.core.take_dirty(&mut dirty);
            seen.push((t, credit(&h, g5), credit(&h, g6), credit(&h, g7), dirty));
        }
        let want = if aggregate {
            // Paused ones first, in the order they were paused, then the
            // penalised in theirs: a point per period in all.
            [
                (1119, 0.0, -1.0, 1.0, vec![]),
                (1120, 0.0, 0.0, 1.0, vec![]),
                (1150, 0.0, 0.0, 1.0, vec![]),
                (1170, 1.0, 0.0, 1.0, vec![g5]),
                (1220, 1.0, 1.0, 1.0, vec![g6]),
                (1270, 1.0, 2.0, 1.0, vec![]),
                (1320, 1.0, 2.0, 2.0, vec![]),
                (1370, 2.0, 2.0, 2.0, vec![]),
            ]
        } else {
            [
                (1119, 0.0, -1.0, 1.0, vec![]),
                (1120, 1.0, 0.0, 2.0, vec![g5]),
                (1150, 1.0, 0.0, 2.0, vec![]),
                (1170, 2.0, 1.0, 2.0, vec![g6]),
                (1220, 2.0, 2.0, 2.0, vec![]),
                (1270, 2.0, 2.0, 2.0, vec![]),
                (1320, 2.0, 2.0, 2.0, vec![]),
                (1370, 2.0, 2.0, 2.0, vec![]),
            ]
        };
        assert_eq!(seen, want, "aggregate {aggregate}");
        assert_eq!(h.core.next_tick(), None);
        // What they asked meanwhile is done.
        for g in [g5, g6] {
            assert_eq!(h.core.process(g, 10), Status::Idle);
            assert_eq!(h.drain_one(g).last().unwrap().3, b"OK\0");
        }
        // A domain that goes while penalised or paused leaves the queues,
        // and only it.
        conflict(&mut h, 2, &[(g5, 5), (g6, 6)]);
        conflict(&mut h, 1, &[(g7, 7)]);
        for g in [g5, g6] {
            h.core.close(g);
            h.core.audit().unwrap();
        }
        assert_eq!(credit(&h, g7), 1.0);
        h.core.tick(ms(2000));
        assert_eq!(h.core.next_tick(), None);
    }
}

#[test]
fn xsa_206_a_point_at_a_time_up_to_the_limit_and_nothing_for_who_is_gone() {
    let (mut h, a, g) = with_guest(Config {
        conflict_burst_limit: 3.0,
        ..Config::default()
    });
    h.write(a, 0, "/local/domain/5/data/x", "");
    for i in 0..2 {
        assert_eq!(starve(&mut h, a, g, i).0, Err("EAGAIN".into()));
    }
    let mut seen = Vec::new();
    for t in [50, 100, 150] {
        h.core.tick(ms(t));
        seen.push(credit(&h, g));
    }
    assert_eq!(seen, [2.0, 3.0, 3.0]);
    // A connection blamed once it is gone: nothing to take credit from.
    let t = h.start(a);
    h.read(a, t, "/local/domain/5/data/x").unwrap();
    h.write(a, t, "/y", "");
    h.write(g, 0, "data/x", "gone");
    h.core.close(g);
    assert_eq!(h.end(a, t, true), Err("EAGAIN".into()));
    assert_eq!(h.core.next_tick(), None);
}

#[test]
fn xsa_206_with_an_infinite_limit_nothing_changes() {
    // Nor with NaN: oxenstored's comparisons with it are all false.
    for limit in [f64::INFINITY, f64::NAN] {
        let (mut h, a, g) = with_guest(Config {
            conflict_burst_limit: limit,
            ..Config::default()
        });
        h.write(a, 0, "/local/domain/5/data/x", "");
        for i in 0..50 {
            assert_eq!(starve(&mut h, a, g, i), (Err("EAGAIN".into()), Status::Idle));
        }
        assert_eq!((credit(&h, g), h.core.next_tick()), (f64::INFINITY, None));
    }
}

#[test]
fn xsa_206_with_no_credit_to_start_with_a_guest_is_never_served() {
    // `ox/domain.ml:107`, `ox/domain.ml:66`: as oxenstored, which never
    // gives such a domain a point either.
    for aggregate in [true, false] {
        let (mut h, a, g) = with_guest(Config {
            conflict_burst_limit: 0.0,
            conflict_rate_limit_is_aggregate: aggregate,
            ..Config::default()
        });
        assert_eq!(h.send(g, ty(MsgType::Read), 0, b"data\0"), Status::Blocked);
        h.core.tick(ms(1000));
        assert_eq!((h.core.wants_input(g), h.core.next_tick()), (false, None));
        assert!(h.core.wants_input(a));
        h.core.close(g);
        h.core.audit().unwrap();
    }
}

#[test]
fn xsa_206_with_a_limit_of_one_a_conflict_pauses_and_a_point_resumes() {
    for aggregate in [true, false] {
        let (mut h, a, g) = with_guest(Config {
            conflict_burst_limit: 1.0,
            conflict_rate_limit_is_aggregate: aggregate,
            ..Config::default()
        });
        h.write(a, 0, "/local/domain/5/data/x", "");
        assert_eq!(starve(&mut h, a, g, 0).0, Err("EAGAIN".into()));
        assert_eq!(starve(&mut h, a, g, 1), (Ok(()), Status::Blocked));
        h.core.tick(ms(50));
        assert_eq!((credit(&h, g), h.core.next_tick()), (1.0, None));
        assert_eq!(h.core.process(g, 10), Status::Idle);
    }
}

// ---------------------------------------------------------------- XSA-325

fn oversized(h: &mut H, c: ConnId, len: u32) -> Status {
    let mut bytes = Vec::new();
    write_header(&mut bytes, ty(MsgType::Write), 1, 0, len);
    h.core.feed(c, &bytes);
    h.core.process_on(c, 10, &mut h.machine)
}

#[test]
fn xsa_325_a_guest_that_breaks_the_protocol_is_ignored_and_its_domain_still_dies() {
    let mut h = H::with(Config {
        watch_event_max: 1,
        ..Config::default()
    });
    let a = h.core.open();
    h.write(a, 0, "/shared", "");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0r5\0w6\0");
    home(&mut h, a, 5);
    let g = h.introduce(a, 5, 1, 1);
    let g6 = h.core.open_domain(6);
    h.watch(a, "@releaseDomain", "r");
    // What its ring holds: a watch, a transaction, unsent events, and
    // domain 6, held until it reads them.
    h.watch(g, "/shared", "w");
    let t = h.start(g);
    h.write(g, t, "data/x", "");
    for _ in 0..2 {
        h.push(g6, ty(MsgType::Write), 0, &wr("/shared", "v"));
    }
    assert_eq!(h.core.process(g6, 10), Status::Blocked);
    assert_eq!(oversized(&mut h, g, 4097), Status::Closed);
    let mut dead = Vec::new();
    h.core.take_dead(&mut dead);
    assert_eq!(dead, [(g, GaveUp::Protocol)]);
    h.core.ignore(g);
    h.core.audit().unwrap();
    assert!(h.core.wants_input(g6), "what it held went with its events");
    assert_eq!(
        (h.core.output(g), h.core.transactions(g), h.core.index.of(g).count()),
        (&b""[..], 0, 0)
    );
    // Nothing it sends is read, nothing reaches it.
    h.push(g, ty(MsgType::Read), 0, b"data\0");
    assert_eq!(h.core.process(g, 10), Status::Closed);
    h.write(a, 0, "/shared", "again");
    h.core.fire_special(b"@introduceDomain");
    assert!(h.core.output(g).is_empty());
    // Its domain is as it was: known, with its nodes and ACL entries.
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"5\0"), b"T\0");
    assert_eq!(h.one(a, MsgType::GetPerms, "/shared"), b"n0\0r5\0w6\0");
    assert_eq!(h.read(a, 0, "/local/domain/5").unwrap(), "");
    // Until it dies: one @releaseDomain, its ring let go, its nodes and
    // ACL entries gone.
    h.dom_exc(&[(5, DomainState::Dead)]);
    assert_eq!(events(&h.drain()), [ev(a, "@releaseDomain", "r")]);
    assert_eq!(h.calls(), [Call::Disconnect(g, 5)]);
    assert_eq!(h.read(a, 0, "/local/domain/5"), Err("ENOENT".into()));
    assert_eq!(h.one(a, MsgType::GetPerms, "/shared"), b"n0\0w6\0");
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"5\0"), b"F\0");
    h.core.ignore(g);
    // Or until it is released.
    let g7 = h.introduce(a, 7, 1, 1);
    h.core.ignore(g7);
    assert_eq!(h.ok(a, MsgType::IsDomainIntroduced, 0, b"7\0"), b"T\0");
    let out = h.raw(a, ty(MsgType::Release), 0, b"7\0");
    assert_eq!(events(&out), [ev(a, "@releaseDomain", "r")]);
    assert_eq!(h.calls(), [Call::Disconnect(g7, 7)]);
}

#[test]
fn xsa_420_any_length_past_a_payload_ends_the_ring_once() {
    for len in [4097, 0x8000_0000, 0xFFFF_FFFF] {
        let (mut h, _, g) = with_guest(Config::default());
        assert_eq!(oversized(&mut h, g, len), Status::Closed);
        let mut dead = Vec::new();
        h.core.take_dead(&mut dead);
        assert_eq!(dead, [(g, GaveUp::Protocol)], "{len:#x}");
        // The bad packet is not looked at again.
        h.push(g, ty(MsgType::Read), 0, b"data\0");
        assert_eq!(h.core.process(g, 10), Status::Closed);
        h.core.take_dead(&mut dead);
        assert_eq!((dead.len(), h.core.output(g)), (1, &b""[..]));
    }
}

// ---------------------------------------------------------------- RELEASE of reserved domids

#[test]
fn release_of_domain_0_or_of_a_reserved_domid_touches_nothing() {
    let mut h = H::new();
    let a = h.core.open();
    let d0 = h.core.open_domain(0);
    h.watch(a, "@releaseDomain", "r");
    h.write(a, 0, "/vm/x", "");
    h.ok(a, MsgType::SetPerms, 0, b"/vm/x\0n0\0r32751\0r32752\0r4294967295\0");
    let store = h.core.root.clone();
    for c in [a, d0] {
        for d in ["0", "0x0", "32752", "32767", "65535", "4294967295"] {
            let out = h.raw(c, ty(MsgType::Release), 0, format!("{d}\0").as_bytes());
            assert_eq!(out, [(c, (ty(MsgType::Error), h.req, 0, b"EINVAL\0".to_vec()))], "{d}");
        }
    }
    assert!(Arc::ptr_eq(&store, &h.core.root), "not even copied");
    assert_eq!((h.core.domain_conn(0), h.calls()), (Some(d0), vec![]));
    assert_eq!(h.read(a, 0, "/tool/xenstored").unwrap(), "rxenstored");
    // A reserved domid cannot be introduced either; nothing is asked of
    // the machine.
    for d in ["32752", "32767", "65535"] {
        assert_eq!(
            h.err(a, MsgType::Introduce, 0, format!("{d}\x001\x001\0").as_bytes()),
            "EINVAL"
        );
    }
    assert!(h.calls().is_empty());
    // INTRODUCE of domain 0, which is known, binds its channel again, and
    // nothing else; its death is never asked about.
    assert_eq!(h.ok(a, MsgType::Introduce, 0, b"0\x000\x007\0"), b"OK\0");
    assert_eq!(h.calls(), [Call::Rebind(d0, 0, 7)]);
    assert_eq!(h.dom_exc(&[(0, DomainState::Dead)]), Vec::<u32>::new());
    assert_eq!(h.core.domain_conn(0), Some(d0));
    // The highest domid that is one is released as any other.
    assert_eq!(h.err(a, MsgType::Release, 0, b"32751\0"), "EINVAL");
    assert_eq!(h.one(a, MsgType::GetPerms, "/vm/x"), b"n0\0r32752\0r4294967295\0");
}

// ---------------------------------------------------------------- SET_TARGET and the target's end

#[test]
fn a_target_that_dies_or_is_released_is_no_longer_acted_for() {
    let (mut h, a, g) = with_guest(Config::default());
    home(&mut h, a, 6);
    let g6 = h.core.open_domain(6);
    let (stub5, stub6, stub0) = (h.core.open_domain(7), h.core.open_domain(8), h.core.open_domain(9));
    h.write(g, 0, "data/x", "5");
    h.write(g6, 0, "data/x", "6");
    for p in [&b"7\x005\0"[..], b"8\x006\0", b"9\x000\0"] {
        h.ok(a, MsgType::SetTarget, 0, p);
    }
    assert_eq!(h.read(stub5, 0, "/local/domain/5/data/x").unwrap(), "5");
    // Its guest dies; a new domain 5 is not the stub's.
    h.dom_exc(&[(5, DomainState::Dead)]);
    home(&mut h, a, 5);
    let g = h.core.open_domain(5);
    h.write(g, 0, "data/x", "new");
    assert_eq!(h.read(stub5, 0, "/local/domain/5/data/x"), Err("EACCES".into()));
    assert_eq!(h.core.conns.map[&stub5].caller, Caller { domid: 7, target: None });
    // Released, likewise; the others keep theirs.
    h.ok(a, MsgType::Release, 0, b"6\0");
    assert_eq!(h.core.conns.map[&stub6].caller.target, None);
    assert_eq!(h.read(stub0, 0, "/tool/xenstored").unwrap(), "rxenstored");
}

#[test]
fn set_target_numbers_past_32_bits_name_no_domain() {
    let (mut h, a, g) = with_guest(Config::default());
    let stub = h.core.open_domain(7);
    h.write(g, 0, "data/x", "5");
    // 2^32 + 7 and 2^32 + 5: not domains 7 and 5.
    assert_eq!(h.err(a, MsgType::SetTarget, 0, b"4294967303 5 "), "ENOENT");
    assert_eq!(h.core.conns.map[&stub].caller.target, None);
    h.ok(a, MsgType::SetTarget, 0, b"7 5 ");
    assert_eq!(h.read(stub, 0, "/local/domain/5/data/x").unwrap(), "5");
    // A target that is no domid replaces the one it had, and gives nothing.
    h.ok(a, MsgType::SetTarget, 0, b"7 4294967301 ");
    assert_eq!(h.core.conns.map[&stub].caller.target, None);
    assert_eq!(h.read(stub, 0, "/local/domain/5/data/x"), Err("EACCES".into()));
    // Past 63 bits the number wraps as an OCaml int: 2^63 + 5 is 5.
    h.ok(a, MsgType::SetTarget, 0, b"7 9223372036854775813 ");
    assert_eq!(h.core.conns.map[&stub].caller.target, Some(5));
}

#[test]
fn xsa_115_a_commit_s_events_are_checked_against_the_store_before_and_after_the_transaction() {
    // The WRITE is checked against the final store only, where /p/x is
    // closed to domain 5 (`4.17 ox/process.ml:60-72`).
    for concurrent in [false, true] {
        let (mut h, a, g) = with_guest(Config::default());
        for p in ["/p", "/q"] {
            h.write(a, 0, p, "");
            h.ok(a, MsgType::SetPerms, 0, format!("{p}\0n0\0r5\0").as_bytes());
            h.watch(g, p, "tok");
        }
        let t = h.start(a);
        h.write(a, t, "/p/x", "");
        h.ok(a, MsgType::SetPerms, t, b"/p/x\0n0\0");
        h.ok(a, MsgType::SetPerms, t, b"/p\0n0\0");
        // A removal is checked against the store before, where domain 5
        // could read /q, however the transaction changed it first.
        h.ok(a, MsgType::SetPerms, t, b"/q\0n0\0");
        h.ok(a, MsgType::Rm, t, b"/q\0");
        if concurrent {
            // Run again, on the store as it is now.
            h.write(a, 0, "/other", "");
        }
        let out = h.raw(a, ty(MsgType::TransactionEnd), t, b"T\0");
        let want = [
            ev(g, "/p", "tok"),
            ev(g, "/p/x", "tok"),
            ev(g, "/q", "tok"),
            ev(g, "/q", "tok"),
        ];
        assert_eq!(events(&out), want, "concurrent {concurrent}");
    }
}

// ---------------------------------------------------------------- what open transactions pin

/// Value bytes held by the store and by every transaction's versions,
/// each allocation counted once, and the nodes walked.
fn live_bytes(core: &Core) -> (usize, usize) {
    let mut seen = std::collections::HashSet::new();
    let (mut bytes, mut nodes) = (0, 0);
    let versions = std::iter::once(&core.root).chain(
        core.conns
            .map
            .values()
            .flat_map(|c| c.txns.values().flat_map(|t| [&t.snapshot, &t.tree])),
    );
    for root in versions {
        let mut stack = vec![&**root];
        while let Some(n) = stack.pop() {
            nodes += 1;
            if let Bytes::Shared(a) = &n.value {
                if seen.insert(Arc::as_ptr(a) as *const u8) {
                    bytes += a.len();
                }
            }
            stack.extend(n.children.iter().map(|(_, c)| c));
        }
    }
    (bytes, nodes)
}

/// A guest that fills a quota of `n` + 1 nodes (its home), then before each
/// of its 11 TRANSACTION_STARTs (`quota-transaction` 10) rewrites every
/// node with a 2048-byte value: each transaction keeps a version of all
/// of them. The value bytes then held, and after its reconnection.
fn pinned(n: usize) -> (usize, usize) {
    let (mut h, _, g) = with_guest(Config {
        entity_max: n + 1,
        ..Config::default()
    });
    for round in 0..12 {
        let v = vec![b'a' + round as u8; 2048];
        for i in 0..n {
            h.push(g, ty(MsgType::Write), 0, &[format!("{i}\0").as_bytes(), &v].concat());
            assert_eq!(h.core.process(g, 10), Status::Idle);
            let len = h.core.output(g).len();
            h.core.consume(g, len);
        }
        if round < 11 {
            h.start(g);
        }
    }
    assert_eq!(h.core.transactions(g), 11);
    h.core.audit().unwrap();
    let bytes = live_bytes(&h.core).0;
    h.core.reconnect(g);
    (bytes, live_bytes(&h.core).0)
}

#[test]
fn what_a_guest_s_open_transactions_can_pin_is_measured() {
    // 12 versions of every value; they go with the transactions.
    let n = 512;
    assert_eq!(pinned(n), (12 * n * 2048, n * 2048));
}

#[test]
#[ignore = "192 MiB and seconds: run with --ignored"]
fn what_a_guest_s_open_transactions_can_pin_at_xcp_ng_8_3_s_shipped_quotas() {
    // `quota-maxentity` 8192, as XCP-ng 8.3 ships it.
    let n = 8191;
    let (bytes, _) = pinned(n);
    assert_eq!(bytes, 12 * n * 2048);
    eprintln!("{bytes} value bytes ({} MiB) pinned by one guest", bytes >> 20);
}

// ---------------------------------------------------------------- more XSAs, and edge cases

#[test]
fn xsa_72_after_e2big_a_ring_goes_on_and_directory_part_lists_it_all() {
    let (mut h, a, g) = with_guest(Config::default());
    for i in 0..129 {
        h.write(a, 0, &format!("/local/domain/5/d/{i:031}"), "");
    }
    h.write(a, 0, "/local/domain/5/x", "1");
    let r = h.call(g, MsgType::Directory, 0, b"d\0");
    assert_eq!((r.0, r.3), (ty(MsgType::Error), b"E2BIG\0".to_vec()));
    assert_eq!(h.read(g, 0, "x").unwrap(), "1", "with its own req_id");
    let (list, _) = directory_parts(&mut h, g, 0, "d");
    assert_eq!(list.split(|c| *c == 0).filter(|n| !n.is_empty()).count(), 129);
}

#[test]
fn xsa_322_a_dead_domain_s_acl_entries_do_not_come_back_with_a_transaction() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/shared", "");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0r5\0");
    home(&mut h, a, 5);
    let g = h.introduce(a, 5, 1, 1);
    let t = h.start(a);
    h.write(a, t, "/shared/new", "");
    h.dom_exc(&[(5, DomainState::Dead)]);
    assert_eq!(h.calls(), [Call::Disconnect(g, 5)]);
    h.end(a, t, true).unwrap();
    assert_eq!(h.one(a, MsgType::GetPerms, "/shared/new"), b"n0\0");
    let g = h.introduce(a, 5, 1, 1);
    assert_eq!(h.read(g, 0, "/shared"), Err("EACCES".into()));
    assert_eq!(h.read(g, 0, "/shared/new"), Err("EACCES".into()));
}

#[test]
fn xsa_323_the_length_limit_is_on_the_part_after_the_domain_s_home() {
    let (mut h, a, g) = with_guest(Config::default());
    let name = "a".repeat(crate::path::PATH_MAX);
    h.write(g, 0, &name, "v");
    assert_eq!(h.read(a, 0, &format!("/local/domain/5/{name}")).unwrap(), "v");
    assert_eq!(h.ls(a, 0, "/local/domain/5"), std::slice::from_ref(&name));
    assert_eq!(h.err(g, MsgType::Write, 0, &wr(&format!("{name}a"), "v")), "EINVAL");
    assert_eq!(
        h.err(a, MsgType::Read, 0, format!("/local/domain/5/{name}a\0").as_bytes()),
        "EINVAL"
    );
}

#[test]
fn xsa_324_after_an_oversized_event_a_ring_goes_on() {
    let (mut h, a, g) = with_guest(Config::default());
    let token = "t".repeat(PAYLOAD_MAX - 4);
    h.watch(g, "d", &token);
    let out = h.raw(a, ty(MsgType::Write), 0, &wr("/local/domain/5/d/x", "1"));
    assert_eq!(out[1], (g, (ty(MsgType::Error), 0, 0, b"E2BIG\0".to_vec())));
    assert_eq!(h.read(g, 0, "d/x").unwrap(), "1", "with its own req_id");
}

#[test]
fn xsa_330_and_512_reset_and_reconnection_leave_no_watch_behind() {
    for reset in [true, false] {
        let (mut h, a, g) = with_guest(Config::default());
        for round in 0..100 {
            for i in 0..50 {
                h.watch(g, &format!("deep/{round}/{i}/x/y"), "t");
            }
            if reset {
                h.ok(g, MsgType::ResetWatches, 0, b"");
            } else {
                h.core.reconnect(g);
            }
            assert_eq!((h.core.watches(), h.core.index.trie_size()), (0, 1), "round {round}");
        }
        assert!(events(&h.raw(a, ty(MsgType::Write), 0, &wr("/local/domain/5/deep/1/1/x/y", ""))).is_empty());
    }
}

#[test]
fn xsa_352_a_guest_cannot_give_a_node_away_in_a_transaction_either() {
    let (mut h, a, g) = with_guest(Config::default());
    h.write(g, 0, "data", "");
    let t = h.start(g);
    assert_eq!(h.err(g, MsgType::SetPerms, t, b"data\0n0\0"), "EACCES");
    h.end(g, t, true).unwrap();
    assert_eq!(h.one(a, MsgType::GetPerms, "/local/domain/5/data"), b"n5\0");
}

#[test]
fn xsa_353_the_root_is_checked_as_any_node() {
    let (mut h, a, g) = with_guest(Config {
        perms_watch_activate: false,
        ..Config::default()
    });
    h.watch(a, "/", "root");
    let before = h.ls(a, 0, "/");
    let mut fired = Vec::new();
    for (t, p) in [
        (MsgType::Read, &b"/\0"[..]),
        (MsgType::Directory, b"/\0"),
        (MsgType::GetPerms, b"/\0"),
        (MsgType::Write, b"/\0v"),
        (MsgType::Rm, b"/\0"),
        (MsgType::SetPerms, b"/\0n0\0r5\0"),
        (MsgType::SetPerms, b"/\0n5\0"),
    ] {
        let out = h.raw(g, ty(t), 0, p);
        assert_eq!(out.iter().find(|m| m.0 == g).unwrap().1 .3, b"EACCES\0", "{t:?}");
        fired.extend(events(&out));
    }
    // MKDIR of the root checks nothing and changes nothing (`ox/store.ml:267-268`).
    let out = h.raw(g, ty(MsgType::Mkdir), 0, b"/\0");
    assert_eq!(out.iter().find(|m| m.0 == g).unwrap().1 .3, b"OK\0");
    fired.extend(events(&out));
    assert_eq!(fired, [ev(a, "/", "root")]);
    assert_eq!(h.ls(a, 0, "/"), before);
}

#[test]
fn xsa_416_a_ring_that_does_not_read_is_held_at_the_soft_limit() {
    let (mut h, a, g) = with_guest(Config::default());
    h.write(a, 0, "/local/domain/5/v", &"v".repeat(2048));
    for _ in 0..1000 {
        h.push(g, ty(MsgType::Read), 0, b"v\0");
    }
    assert_eq!(h.core.process(g, 2000), Status::Blocked);
    assert!(h.core.output(g).len() < Config::default().output_soft_limit + 16 + 2048);
}

#[test]
fn xsa_417_permissions_granted_before_a_domain_exists_end_with_it() {
    let mut h = H::new();
    let a = h.core.open();
    h.write(a, 0, "/shared", "s");
    h.ok(a, MsgType::SetPerms, 0, b"/shared\0n0\0r5\0");
    let g = h.introduce(a, 5, 1, 1);
    assert_eq!(h.read(g, 0, "/shared").unwrap(), "s");
    h.dom_exc(&[(5, DomainState::Dead)]);
    assert_eq!(h.calls(), [Call::Disconnect(g, 5)]);
    h.write(a, 0, "/shared", "again");
    let g = h.introduce(a, 5, 1, 1);
    assert_eq!(h.read(g, 0, "/shared"), Err("EACCES".into()));
    assert_eq!(h.one(a, MsgType::GetPerms, "/shared"), b"n0\0");
}

#[test]
fn xsa_418_the_deepest_paths_a_request_can_name_fit_in_the_stack() {
    // 2,047 components is the most a payload holds; the death of their
    // owner takes about 2 MiB of stack in a debug build.
    let t = std::thread::Builder::new().stack_size(4 << 20).spawn(|| {
        let (mut h, a, g) = with_guest(Config {
            path_max: 8192,
            entity_max: 10_000,
            ..Config::default()
        });
        let deep = |c: &str, n| vec![c; n].join("/");
        h.write(g, 0, &deep("a", 2047), "");
        h.write(a, 0, &format!("/{}", deep("b", 2047)), "");
        h.dom_exc(&[(5, DomainState::Dead)]);
        assert_eq!(h.read(a, 0, "/local/domain/5"), Err("ENOENT".into()));
        h.one(a, MsgType::Rm, "/b");
        // One more is a payload past the limit: the ring is given up.
        let g6 = h.core.open_domain(6);
        h.push(g6, ty(MsgType::Write), 0, &wr(&deep("a", 2048), "x"));
        assert_eq!(h.core.process(g6, 10), Status::Closed);
        h.write(a, 0, &format!("/{}", deep("c", 2047)), "");
        drop(h);
    });
    t.unwrap().join().unwrap();
}

#[test]
fn xsa_481_paths_in_the_domain_prefix_are_refused_or_looked_up_as_any() {
    let (mut h, a, g) = with_guest(Config::default());
    let types = [
        MsgType::Read,
        MsgType::Write,
        MsgType::Mkdir,
        MsgType::Rm,
        MsgType::Directory,
        MsgType::GetPerms,
        MsgType::SetPerms,
        MsgType::DirectoryPart,
        MsgType::Watch,
        MsgType::Unwatch,
    ];
    let payload = |t: MsgType, p: &str| match t {
        MsgType::Write => wr(p, "v"),
        MsgType::SetPerms => format!("{p}\0n0\0").into_bytes(),
        MsgType::DirectoryPart => format!("{p}\x000\0").into_bytes(),
        MsgType::Watch | MsgType::Unwatch => format!("{p}\0t\0").into_bytes(),
        _ => format!("{p}\0").into_bytes(),
    };
    for c in [a, g] {
        for p in ["/local/domain/", "/local/domain//x", "/local/domain/+"] {
            for t in types {
                // What cannot be watched is not watched (`ox/connection.ml:291-301`).
                let want = if t == MsgType::Unwatch { "ENOENT" } else { "EINVAL" };
                assert_eq!(h.err(c, t, 0, &payload(t, p)), want, "{c:?} {t:?} {p}");
            }
        }
        // Valid names, which name no domain; in the native profile a guest,
        // which may not read /local/domain, is told EACCES.
        let missing = if native() && c == g { "EACCES" } else { "ENOENT" };
        for p in ["/local/domain/-", "/local/domain/_/x"] {
            assert_eq!(h.err(c, MsgType::Read, 0, &payload(MsgType::Read, p)), missing, "{p}");
        }
        h.write(c, 0, "/local/domain/5/data", "");
    }
}

#[test]
fn xsa_484_reset_watches_in_a_transaction_ends_it() {
    for reconnect in [false, true] {
        let (mut h, _, g) = with_guest(Config::default());
        let t = h.start(g);
        h.write(g, t, "data/x", "");
        assert_eq!(
            h.call(g, MsgType::ResetWatches, t, b""),
            (ty(MsgType::ResetWatches), h.req, t, b"OK\0".to_vec())
        );
        assert_eq!(h.core.transactions(g), 0);
        assert_eq!(h.read(g, t, "data/x"), Err("EIO".into()));
        assert_eq!(h.end(g, t, true), Err("EIO".into()));
        assert_eq!(h.read(g, 0, "data/x"), Err("ENOENT".into()));
        if reconnect {
            h.core.reconnect(g);
        }
        let t = h.start(g);
        h.write(g, t, "data/x", "");
        h.end(g, t, true).unwrap();
        assert_eq!(h.read(g, 0, "data/x").unwrap(), "");
    }
}

#[test]
fn a_request_whose_connection_or_transaction_is_gone_fails_with_eio() {
    // Not reachable: `handle` runs for an open connection, and in a
    // transaction `count_request` found. Were it otherwise, the request
    // would fail, not panic, and change nothing.
    let mut core = Core::new(Config::default(), random_key());
    let a = core.open();
    let peer = core.conns.map.get(&a).unwrap().peer();
    let msg = |ty: MsgType, payload: &[u8]| Message::new(ty, 1, 0, payload.to_vec()).unwrap();
    let gone = ConnId(999);
    assert_eq!(
        core.watch(gone, &peer, &msg(MsgType::Watch, b"/a\0t\0")),
        Err(Errno::EIO)
    );
    assert_eq!(
        core.transaction_start(gone, &peer, &msg(MsgType::TransactionStart, b"\0"), 0),
        Err(Errno::EIO)
    );
    let mut machine = Rec::default();
    assert_eq!(
        core.introduce(a, &peer, &msg(MsgType::Introduce, b"5\x001\x002\x00"), 77, &mut machine),
        Err(Errno::EIO)
    );
    assert_eq!(machine.calls, [], "nothing connected");
    assert_eq!(
        core.release(a, &peer, &msg(MsgType::Release, b"5\0"), 77, &mut machine),
        Err(Errno::EIO)
    );
    core.run_op(a, &peer, &msg(MsgType::Read, b"/\0"), 77, Op::Read(Vec::new()), None);
    let mut expect = Vec::new();
    write_header(&mut expect, MsgType::Error as u32, 1, 77, 4);
    expect.extend_from_slice(b"EIO\0");
    assert_eq!(core.output(a), expect);
    assert_eq!(
        (core.watches(), core.transactions(a), core.domains().count()),
        (0, 0, 0)
    );
    core.audit().unwrap();
}

#[test]
fn a_value_of_the_size_limit_is_written_with_or_without_missing_parents() {
    for profile in PROFILES {
        let (mut h, a, g) = guest_in(profile, Config::default());
        let full = "v".repeat(store::VALUE_MAX);
        for (who, path) in [
            (g, "made/below/leaf"),
            (g, "made/leaf"),
            (a, "/top/made/leaf"),
            (a, "/top/leaf"),
        ] {
            h.write(who, 0, path, &full);
            assert_eq!(h.read(who, 0, path).unwrap(), full, "{profile:?} {path}");
        }
        let over = "v".repeat(store::VALUE_MAX + 1);
        for path in ["new/below/leaf", "made/other"] {
            assert_eq!(h.err(g, MsgType::Write, 0, &wr(path, &over)), "E2BIG", "{path}");
        }
    }
}

// ------------------------------------------- events longer than a payload

/// The message a ring gets in place of a watch event longer than a payload
/// (`ox/connection.ml:242-246`): an error with the event's ids.
fn e2big_event() -> Out {
    (ty(MsgType::Error), 0, 0, b"E2BIG\0".to_vec())
}

/// Guest 5 (`g`), with `data` that domain 6 may read; `w` (a socket if
/// `domid` is None, else the ring of that domain) watches
/// `/local/domain/5/data` with the longest token WATCH takes there, so that
/// every event below it is longer than a payload, and the one of the
/// registration just fits. Returns (h, socket, g, w).
fn oversized_watch(event_max: usize, domid: Option<u32>) -> (H, ConnId, ConnId, ConnId) {
    let (mut h, a, g) = with_guest(Config {
        watch_event_max: event_max,
        ..Config::default()
    });
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0");
    let w = domid.map_or(a, |d| h.core.open_domain(d));
    let token = "t".repeat(PAYLOAD_MAX - "/local/domain/5/data\0\0".len());
    assert_eq!(h.watch(w, "/local/domain/5/data", &token).len(), 1);
    h.drain();
    (h, a, g, w)
}

/// Writes `p` once on `c`, which must not be held, and reads its reply.
fn write_once(h: &mut H, c: ConnId, p: &str) {
    assert_eq!(h.send(c, ty(MsgType::Write), 0, &wr(p, "v")), Status::Idle);
    assert_eq!(h.drain_one(c).len(), 1);
}

#[test]
fn an_e2big_in_place_of_an_event_counts_as_an_event_and_holds_its_source_at_the_quota() {
    let (mut h, _, g, sink) = oversized_watch(8, Some(6));
    // Up to the quota, the guest goes on.
    for _ in 0..8 {
        write_once(&mut h, g, "data/x");
    }
    assert!(h.core.wants_input(g));
    let out = &h.core.conns.map[&sink].out;
    assert_eq!((out.events, out.replies, out.from(g)), (8, 0, 8));
    // One over: queued, then the guest waits.
    assert_eq!(flood(&mut h, g, "data/x", 1000), 1);
    assert!(!h.core.wants_input(g));
    assert_eq!(h.core.conns.map[&sink].out.events, 9);
    assert_eq!(h.core.output(sink).len(), 9 * (16 + "E2BIG\0".len()));
    // The sink reads them, as they were: the guest goes on.
    assert_eq!(h.drain_one(sink), vec![e2big_event(); 9]);
    assert!(h.core.wants_input(g));
    let mut dirty = Vec::new();
    h.core.take_dirty(&mut dirty);
    assert!(dirty.contains(&g));
    assert_eq!(h.core.conns.dropped, 0);
}

#[test]
fn an_e2big_in_place_of_an_event_of_domain_0_is_dropped_past_twice_the_quota() {
    let (mut h, a, g, sink) = oversized_watch(8, Some(6));
    // Domain 0 is never held: its events for a guest that does not read
    // are queued up to twice the quota, then dropped.
    for _ in 0..20 {
        write_once(&mut h, a, "/local/domain/5/data/y");
    }
    assert!(h.core.wants_input(a));
    assert_eq!(h.core.conns.map[&sink].out.events, 16);
    assert_eq!(h.core.conns.dropped, 4);
    // The guest's own: dropped too, and it is not held for them.
    write_once(&mut h, g, "data/x");
    assert_eq!((h.core.conns.dropped, h.core.conns.map[&sink].out.from(g)), (5, 0));
    let mut drops = Vec::new();
    h.core.take_drops(&mut drops);
    assert_eq!(drops, [Drops::Started(log::Who::Domain(6))]);
    assert_eq!(h.drain_one(sink), vec![e2big_event(); 16]);
    h.core.take_drops(&mut drops);
    assert_eq!(drops[1], Drops::Ended(log::Who::Domain(6), 5));
}

#[test]
fn for_the_ring_of_domain_0_an_e2big_holds_a_guest_and_is_never_dropped() {
    let (mut h, a, g, d0) = oversized_watch(8, Some(0));
    assert_eq!(flood(&mut h, g, "data/x", 1000), 9, "8 under the quota, 1 over");
    // Domain 0's own events are its own doing: none is dropped, and its
    // ring is not given up on.
    for _ in 0..100 {
        write_once(&mut h, a, "/local/domain/5/data/y");
    }
    assert_eq!(h.core.conns.map[&d0].out.events, 109);
    assert_eq!(h.core.conns.dropped, 0);
    assert_eq!(h.drain_one(d0), vec![e2big_event(); 109]);
    assert!(h.core.wants_input(g));
}

#[test]
fn a_socket_gets_an_event_longer_than_a_payload_whole_and_its_source_is_held_at_the_quota() {
    let (mut h, _, g, tool) = oversized_watch(8, None);
    assert_eq!(flood(&mut h, g, "data/x", 1000), 9, "8 under the quota, 1 over");
    let out = h.drain_one(tool);
    assert_eq!(out.len(), 9);
    for m in out {
        assert_eq!((m.0, m.1, m.2), (ty(MsgType::WatchEvent), 0, 0));
        assert_eq!(m.3.len(), PAYLOAD_MAX + "/x".len());
        assert!(m.3.starts_with(b"/local/domain/5/data/x\0tt"));
    }
    assert!(h.core.wants_input(g));
}

#[test]
fn a_commit_that_fires_several_e2big_in_place_of_events_holds_its_source_once() {
    // Five events: over the quota of 3, under the 6 a guest may be owed.
    let (mut h, _, g, sink) = oversized_watch(3, Some(6));
    let t = h.start(g);
    for n in ["a", "b", "c", "d", "e"] {
        h.write(g, t, &format!("data/{n}"), "v");
    }
    assert!(h.drain().is_empty());
    h.push(g, ty(MsgType::TransactionEnd), t, b"T\0");
    assert_eq!(h.core.process(g, 10), Status::Blocked, "all five queued, then it waits");
    h.core.audit().unwrap();
    let reply = h.drain_one(g);
    assert_eq!((reply.len(), reply[0].0), (1, ty(MsgType::TransactionEnd)));
    assert_eq!((h.core.conns.map[&sink].out.events, h.core.conns.map[&g].holds), (5, 1));
    assert_eq!(h.drain_one(sink), vec![e2big_event(); 5]);
    assert!(h.core.wants_input(g));
}

#[test]
fn events_that_fit_and_e2big_in_place_of_others_keep_their_order_and_share_the_quota() {
    let (mut h, _, g) = with_guest(Config {
        watch_event_max: 4,
        ..Config::default()
    });
    h.write(g, 0, "data", "");
    h.ok(g, MsgType::SetPerms, 0, b"data\0n5\0r6\0");
    let sink = h.core.open_domain(6);
    // The event of `data/a` is exactly a payload; that of `data/ab`, one
    // byte more.
    let token = "t".repeat(PAYLOAD_MAX - "/local/domain/5/data/a\0\0".len());
    h.watch(sink, "/local/domain/5/data", &token);
    h.drain();
    for p in ["data/a", "data/ab", "data/a", "data/ab"] {
        write_once(&mut h, g, p);
    }
    assert!(h.core.wants_input(g));
    assert_eq!(flood(&mut h, g, "data/ab", 10), 1, "the fifth goes over the quota");
    let fits = |p: &str| {
        let payload = [p.as_bytes(), b"\0", token.as_bytes(), b"\0"].concat();
        assert_eq!(payload.len(), PAYLOAD_MAX);
        (ty(MsgType::WatchEvent), 0, 0, payload)
    };
    let a = fits("/local/domain/5/data/a");
    let big = e2big_event();
    assert_eq!(h.drain_one(sink), [a.clone(), big.clone(), a, big.clone(), big]);
    assert!(h.core.wants_input(g));
}

/// A commit with nothing committed since the transaction started publishes
/// the transaction's version of the store as its requests made it, without
/// running them again (`ox/transaction.ml:238-246`). After a concurrent
/// commit they are run again, as oxenstored runs them when it cannot merge
/// the transaction (`ox/connection.ml:400`). Here a guest that
/// acts for domain 0 (SET_TARGET) removes a node in a transaction, then
/// acts for itself again: its commit publishes the removal.
#[test]
fn a_commit_on_an_unchanged_store_publishes_the_transaction_as_it_ran() {
    let (mut h, a, g) = with_guest(Config::default());
    h.ok(a, MsgType::SetTarget, 0, b"5\x000\0");
    let t = h.start(g);
    h.ok(g, MsgType::Rm, t, b"/tool\0");
    h.ok(a, MsgType::SetTarget, 0, b"5\x005\0");
    assert_eq!(h.end(g, t, true), Ok(()));
    assert_eq!(h.read(a, 0, "/tool"), Err("ENOENT".into()));
}

// ------------------------------------------------- the profiles' rules

const PROFILES: [Profile; 2] = [Profile::Oxenstored, Profile::Native];

/// `with_guest`, in `profile`.
fn guest_in(profile: Profile, cfg: Config) -> (H, ConnId, ConnId) {
    with_guest(Config { profile, ..cfg })
}

#[test]
fn the_rules_of_each_profile() {
    let ox = Profile::Oxenstored.rules();
    assert_eq!(ox.quota_error, Errno::EQUOTA);
    assert!(!ox.exact_counts && !ox.control_is_privileged && !ox.creator_owns);
    assert!(!ox.all_or_nothing && !ox.hide_missing);
    let native = Profile::Native.rules();
    assert_eq!(native.quota_error, Errno::ENOSPC);
    assert!(native.exact_counts && native.control_is_privileged && native.creator_owns);
    assert!(native.all_or_nothing && native.hide_missing);
    assert_eq!(Config::default().profile, Profile::Oxenstored);
    // A count at the quota is full, or one past it.
    assert!(!ox.full(3, 3) && ox.full(4, 3) && !ox.full(0, 0) && ox.full(1, 0));
    assert!(native.full(3, 3) && native.full(4, 3) && !native.full(2, 3) && native.full(0, 0));
}

#[test]
fn every_quota_refuses_with_equota_or_with_enospc_in_the_native_profile() {
    for profile in PROFILES {
        let e = profile.rules().quota_error.name();
        let cfg = Config {
            entity_max: 2,
            watch_max: Some(1),
            transaction_max: Some(1),
            request_max: Some(3),
            acl_max: 1,
            transaction_bytes_max: Some(300),
            ..Config::default()
        };
        let (mut h, a, g) = guest_in(profile, cfg);
        // Nodes: the home and one more.
        h.write(g, 0, "n", "");
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("m", "")), e, "{profile:?}");
        assert_eq!(h.err(g, MsgType::Mkdir, 0, b"m\0"), e);
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("m/o", "")), e);
        // ACL entries.
        assert_eq!(h.err(g, MsgType::SetPerms, 0, b"n\0n5\0r1\0r2\0"), e);
        // Watches: one, and one more where oxenstored allows it.
        h.watch(g, "/w1", "t");
        if profile == Profile::Oxenstored {
            h.watch(g, "/w2", "t");
        }
        assert_eq!(h.err(g, MsgType::Watch, 0, b"/w3\0t\0"), e);
        // Transactions, likewise.
        let t = h.start(g);
        if profile == Profile::Oxenstored {
            h.start(g);
        }
        assert_eq!(h.err(g, MsgType::TransactionStart, 0, b"\0"), e);
        // Bytes a transaction keeps, then requests in one.
        h.write(g, t, "n", &"v".repeat(400));
        assert_eq!(h.err(g, MsgType::Read, t, b"n\0"), e);
        assert_eq!(h.err(g, MsgType::Read, t, b"n\0"), e);
        h.ok(g, MsgType::ResetWatches, 0, b"\0");
        let t = h.start(g);
        for _ in 0..3 {
            h.read(g, t, "n").unwrap();
        }
        assert_eq!(h.err(g, MsgType::Read, t, b"n\0"), e);
        // Domain 0 meets none.
        h.ok(a, MsgType::SetPerms, 0, b"/local/domain/5/n\0n5\0r1\0r2\0");
        for i in 0..3 {
            h.watch(a, &format!("/a{i}"), "t");
            h.start(a);
        }
    }
}

#[test]
fn control_from_a_guest_is_ok_and_does_nothing_or_is_eacces_in_the_native_profile() {
    for profile in PROFILES {
        let (mut h, a, g) = guest_in(profile, Config::default());
        let stub = h.core.open_domain(7);
        h.ok(a, MsgType::SetTarget, 0, b"7\x000\0");
        h.watch(a, "/w", "t");
        let list = b"watch D7: /s t\nwatch A1: /w t\n\0";
        h.watch(stub, "/s", "t");
        for p in [
            &b"watches\0"[..],
            b"print\0x\0",
            b"quota\x005\0",
            b"mfn\x005\0",
            b"",
            b"frob\0",
        ] {
            let r = h.call(g, MsgType::Control, 0, p);
            match profile {
                Profile::Oxenstored => assert_eq!(r, (ty(MsgType::Control), h.req, 0, b"OK\0".to_vec())),
                Profile::Native => assert_eq!(r, (ty(MsgType::Error), h.req, 0, b"EACCES\0".to_vec())),
            }
            // Domain 0, and a domain acting for it, are served as before.
            for c in [a, stub] {
                let r = h.ok(c, MsgType::Control, 0, p);
                if p == b"watches\0" {
                    assert_eq!(r, list);
                }
            }
        }
        // In a transaction: its reply carries the transaction.
        let t = h.start(g);
        let r = h.call(g, MsgType::Control, t, b"print\0x\0");
        assert_eq!((r.0 == ty(MsgType::Error), r.2), (profile == Profile::Native, t));
    }
}

#[test]
fn a_node_a_guest_creates_is_its_own_in_the_native_profile_and_its_parent_s_owner_s_otherwise() {
    for profile in PROFILES {
        let native = profile == Profile::Native;
        let (mut h, a, g) = guest_in(
            profile,
            Config {
                entity_max: 20,
                ..Config::default()
            },
        );
        let perms = |h: &mut H, p: &str| String::from_utf8(h.one(a, MsgType::GetPerms, p)).unwrap();
        let count = |h: &mut H, d: &str| quota(h, a, 0, d);
        h.write(a, 0, "/open", "");
        h.ok(a, MsgType::SetPerms, 0, b"/open\0n0\0w5\0r6\0");
        // Missing parents and the node: one record, owner and ACL.
        h.write(g, 0, "/open/a/b/c", "v");
        let want = if native { "n5\0w5\0r6\0" } else { "n0\0w5\0r6\0" };
        for p in ["/open/a", "/open/a/b", "/open/a/b/c"] {
            assert_eq!(perms(&mut h, p), want, "{profile:?} {p}");
        }
        let node = |h: &H, p: &str| lookup(&h.core.root, &parse_absolute(p).unwrap()).unwrap().perms.clone();
        assert!(Arc::ptr_eq(&node(&h, "/open/a"), &node(&h, "/open/a/b/c")), "shared");
        assert_eq!(
            Arc::ptr_eq(&node(&h, "/open"), &node(&h, "/open/a")),
            !native,
            "the parent's record, unless the owner changes"
        );
        assert_eq!(
            count(&mut h, "5"),
            if native { "dom5 quota: 4/20" } else { "dom5 quota: 1/20" }
        );
        // Below its own home, the parent's record as it is.
        h.write(g, 0, "mine/x", "");
        assert!(Arc::ptr_eq(
            &node(&h, "/local/domain/5"),
            &node(&h, "/local/domain/5/mine/x")
        ));
        // Domain 0 creating below a guest's node: the guest's, as before.
        h.write(a, 0, "/open/a/by0", "");
        assert_eq!(perms(&mut h, "/open/a/by0"), want);
        // The new owner may change the ACL, not give the node away.
        if native {
            h.ok(g, MsgType::SetPerms, 0, b"/open/a\0n5\0r7\0");
            assert_eq!(h.err(g, MsgType::SetPerms, 0, b"/open/a\0n0\0"), "EACCES");
        } else {
            assert_eq!(h.err(g, MsgType::SetPerms, 0, b"/open/a\0n5\0r7\0"), "EACCES");
        }
        // In a transaction, committed as it is or run again.
        for again in [false, true] {
            let t = h.start(g);
            let p = format!("/open/t{again}");
            h.write(g, t, &format!("{p}/x"), "");
            if again {
                h.write(a, 0, "/elsewhere", "");
            }
            h.end(g, t, true).unwrap();
            assert_eq!(perms(&mut h, &p), if native { "n5\0w5\0r6\0" } else { "n0\0w5\0r6\0" });
        }
        // A stub domain acting for the guest owns what it creates, as C
        // xenstored has it (`conn->id`); one acting for domain 0 is
        // domain 0.
        let stub = h.core.open_domain(7);
        h.ok(a, MsgType::SetTarget, 0, b"7\x005\0");
        h.write(stub, 0, "/local/domain/5/by-stub", "");
        let by_stub = perms(&mut h, "/local/domain/5/by-stub");
        assert_eq!(by_stub, if native { "n7\0" } else { "n5\0" });
        h.ok(a, MsgType::SetTarget, 0, b"7\x000\0");
        h.write(stub, 0, "/open/by-dom0-stub", "");
        assert_eq!(perms(&mut h, "/open/by-dom0-stub"), "n0\0w5\0r6\0");
        // The guest dies: what it owns goes, wherever it is.
        h.dom_exc(&[(5, DomainState::Dead)]);
        let left = h.ls(a, 0, "/open");
        let want_left: &[&str] = if native {
            &["by-dom0-stub"]
        } else {
            &["a", "by-dom0-stub", "tfalse", "ttrue"]
        };
        assert_eq!(left, want_left, "{profile:?}");
        assert_eq!(count(&mut h, "5"), "dom5 quota: not set");
    }
}

#[test]
fn a_failed_write_or_mkdir_changes_nothing_in_the_native_profile() {
    for profile in PROFILES {
        let keeps = profile == Profile::Oxenstored;
        let (mut h, a, g) = guest_in(
            profile,
            Config {
                entity_max: 3,
                ..Config::default()
            },
        );
        h.watch(a, "/", "all");
        h.drain();
        // Room for two of the three parents: the quota.
        let before = h.core.root.clone();
        let e = profile.rules().quota_error.name();
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("a/b/c/d", "")), e);
        assert_eq!(Arc::ptr_eq(&before, &h.core.root), !keeps, "{profile:?}");
        assert!(h.drain().is_empty(), "nothing fires");
        assert_eq!(h.read(a, 0, "/local/domain/5/a/b").is_ok(), keeps);
        h.ok(a, MsgType::Rm, 0, b"/local/domain/5/a\0");
        // Room for both parents but not the node: the quota, after them.
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("a/b/c", "")), e);
        assert_eq!(h.read(a, 0, "/local/domain/5/a/b").is_ok(), keeps);
        h.ok(a, MsgType::Rm, 0, b"/local/domain/5/a\0");
        // The size, after the parents.
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("a/b", &"v".repeat(2049))), "E2BIG");
        assert_eq!(h.read(a, 0, "/local/domain/5/a").is_ok(), keeps);
        h.ok(a, MsgType::Rm, 0, b"/local/domain/5/a\0");
        // Room for the parents only, and a value too long: the size, before
        // the quota of the node.
        assert_eq!(h.err(g, MsgType::Write, 0, &wr("a/b/c", &"v".repeat(2049))), "E2BIG");
        assert_eq!(h.read(a, 0, "/local/domain/5/a/b").is_ok(), keeps);
        h.ok(a, MsgType::Rm, 0, b"/local/domain/5/a\0");
        // Domain 0 is not held: the size alone.
        let before = h.core.root.clone();
        assert_eq!(h.err(a, MsgType::Write, 0, &wr("/d/e/f", &"v".repeat(2049))), "E2BIG");
        assert_eq!(Arc::ptr_eq(&before, &h.core.root), !keeps);
        assert_eq!(h.read(a, 0, "/d/e").is_ok(), keeps);
        h.ok(a, MsgType::Rm, 0, b"/d\0");
        // In a transaction, its version is left as it was.
        let t = h.start(g);
        let version = h.core.conns.map[&g].txns[&t].tree.clone();
        assert_eq!(h.err(g, MsgType::Mkdir, t, b"m/n/o\0"), e);
        let after = h.core.conns.map[&g].txns[&t].tree.clone();
        assert_eq!(Arc::ptr_eq(&version, &after), !keeps);
        assert_eq!(h.read(g, t, "m").is_ok(), keeps);
        h.end(g, t, true).unwrap();
        // What does fit is made.
        h.write(g, 0, "a/b", "");
        assert_eq!(quota(&mut h, a, 0, "5"), "dom5 quota: 3/3");
    }
}

#[test]
fn a_missing_node_below_one_a_guest_may_not_read_is_enoent_or_eacces_in_the_native_profile() {
    for profile in PROFILES {
        let native = profile == Profile::Native;
        let (mut h, a, g) = guest_in(profile, Config::default());
        h.write(a, 0, "/closed/open/x", "");
        h.write(a, 0, "/open/x", "");
        h.write(a, 0, "/wonly/x", "");
        h.ok(a, MsgType::SetPerms, 0, b"/closed/open\0n0\0b5\0");
        h.ok(a, MsgType::SetPerms, 0, b"/open\0n0\0b5\0");
        h.ok(a, MsgType::SetPerms, 0, b"/wonly\0n0\0w5\0");
        let hidden = if native { "EACCES" } else { "ENOENT" };
        let reads = |p: &str| {
            [
                (MsgType::Read, format!("{p}\0")),
                (MsgType::Directory, format!("{p}\0")),
                (MsgType::GetPerms, format!("{p}\0")),
                (MsgType::DirectoryPart, format!("{p}\x000\0")),
            ]
        };
        for t in [0, h.start(g)] {
            for (p, want) in [
                ("/closed/missing", hidden),
                ("/closed/missing/deeper", hidden),
                ("/wonly/missing", hidden),
                ("/closed/open/missing", "ENOENT"),
                ("/closed/open/missing/deeper", "ENOENT"),
                ("/open/missing", "ENOENT"),
                ("/local/domain/5/missing", "ENOENT"),
                // A node that exists and may not be read: as before.
                ("/closed", "EACCES"),
            ] {
                for (ty, payload) in reads(p) {
                    assert_eq!(
                        h.err(g, ty, t, payload.as_bytes()),
                        want,
                        "{profile:?} {ty:?} {p} in {t}"
                    );
                }
            }
            // RM and SET_PERMS ask for write access.
            for (p, rm, set) in [
                ("/closed/missing", if native { Some("EACCES") } else { None }, hidden),
                ("/closed/missing/deeper", Some(hidden), hidden),
                ("/wonly/missing", None, "ENOENT"),
                ("/wonly/missing/deeper", Some("ENOENT"), "ENOENT"),
                ("/open/missing", None, "ENOENT"),
            ] {
                let r = h.call(g, MsgType::Rm, t, format!("{p}\0").as_bytes());
                let got = (r.0 == ty(MsgType::Error)).then(|| String::from_utf8(r.3).unwrap());
                assert_eq!(
                    got.as_deref(),
                    rm.map(|e| format!("{e}\0")).as_deref(),
                    "{profile:?} RM {p}"
                );
                let perms = format!("{p}\0n5\0");
                assert_eq!(h.err(g, MsgType::SetPerms, t, perms.as_bytes()), set, "{p}");
            }
        }
        // Domain 0, and a guest acting for it, may read everything.
        let stub = h.core.open_domain(7);
        h.ok(a, MsgType::SetTarget, 0, b"7\x000\0");
        for c in [a, stub] {
            for (ty, payload) in reads("/closed/missing") {
                assert_eq!(h.err(c, ty, 0, payload.as_bytes()), "ENOENT");
            }
            assert_eq!(h.err(c, MsgType::Rm, 0, b"/closed/missing/deeper\0"), "ENOENT");
            h.ok(c, MsgType::Rm, 0, b"/closed/missing\0");
        }
    }
}

/// The XSA regression tests, run again with every core the harness makes
/// in the native profile (`in_profile`): each asserts there what the
/// native rules give (`native()`, `rules()`, `quota_error()`).
mod in_the_native_profile {
    use super::*;

    macro_rules! native {
        ($($test:ident,)*) => {
            $(
                #[test]
                fn $test() {
                    in_profile(Profile::Native, super::$test)
                }
            )*
        };
    }

    native! {
        xsa_272_every_way_of_creating_a_node_counts,
        xsa_414_what_a_failed_creation_leaves_and_counts,
        xsa_419_who_owns_and_pays_for_a_node_a_guest_creates,
        xsa_483_a_dead_or_released_domain_starts_again_from_nothing,
        xsa_421_create_then_delete_in_one_transaction_counts_nothing,
        xsa_440_two_transactions_removing_the_same_nodes_count_once,
        xsa_326d_a_guest_s_watches_are_bounded_by_quota_maxwatch,
        xsa_326e_a_guest_s_open_transactions_are_bounded_by_quota_transaction,
        xsa_326e_a_transaction_takes_maxrequests_requests_then_nothing_not_even_its_end,
        xsa_326a_a_guest_that_does_not_read_its_replies_has_at_most_maxoutstanding,
        xsa_326b_a_guest_flooding_a_socket_that_does_not_read_is_held_and_the_socket_kept,
        xsa_326c_a_guest_flooding_a_guest_that_does_not_read_is_held_and_domain_0_never,
        xsa_326f_a_guest_removing_what_a_socket_watches_is_held_too,
        xsa_206_a_guest_that_keeps_failing_a_transaction_is_held_until_credit_comes_back,
        xsa_206_a_domain_0_transaction_commits_while_a_guest_hammers_what_it_read,
        xsa_206_blame_that_skips_what_a_transaction_cannot_see_blames_the_same,
        xsa_206_domain_0_and_sockets_are_never_held,
        xsa_206_an_innocent_guest_is_not_blamed_for_the_conflicts_of_others,
        xsa_206_a_commit_is_recorded_and_blamed_as_a_change,
        xsa_206_history_is_kept_only_for_young_transactions,
        xsa_206_credit_comes_back_a_point_a_period_to_one_domain_or_to_each,
        xsa_206_a_point_at_a_time_up_to_the_limit_and_nothing_for_who_is_gone,
        xsa_206_with_an_infinite_limit_nothing_changes,
        xsa_206_with_no_credit_to_start_with_a_guest_is_never_served,
        xsa_206_with_a_limit_of_one_a_conflict_pauses_and_a_point_resumes,
        xsa_325_a_guest_that_breaks_the_protocol_is_ignored_and_its_domain_still_dies,
        xsa_420_any_length_past_a_payload_ends_the_ring_once,
        xsa_115_a_commit_s_events_are_checked_against_the_store_before_and_after_the_transaction,
        xsa_72_after_e2big_a_ring_goes_on_and_directory_part_lists_it_all,
        xsa_322_a_dead_domain_s_acl_entries_do_not_come_back_with_a_transaction,
        xsa_323_the_length_limit_is_on_the_part_after_the_domain_s_home,
        xsa_324_after_an_oversized_event_a_ring_goes_on,
        xsa_330_and_512_reset_and_reconnection_leave_no_watch_behind,
        xsa_352_a_guest_cannot_give_a_node_away_in_a_transaction_either,
        xsa_353_the_root_is_checked_as_any_node,
        xsa_416_a_ring_that_does_not_read_is_held_at_the_soft_limit,
        xsa_417_permissions_granted_before_a_domain_exists_end_with_it,
        xsa_418_the_deepest_paths_a_request_can_name_fit_in_the_stack,
        xsa_481_paths_in_the_domain_prefix_are_refused_or_looked_up_as_any,
        xsa_484_reset_watches_in_a_transaction_ends_it,
    }
}
