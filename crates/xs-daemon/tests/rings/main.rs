// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The event loop serving rings and event channels, in-process over the
//! simulated Xen of `xs-sim`.

// A test crate, not the daemon: it may unwrap, index, print and panic (the
// no-panic rule of Cargo.toml is for code that is not a test).
#![allow(
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
)]

#[path = "../common/mod.rs"]
mod common;
mod harness;

use common::Client;
use harness::{eventually, introduce, introduce_at, introduced, request, Daemon, G, T};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use xs_core::Profile;
use xs_sim::Op;
use xs_sys::backend::DomainState;
use xs_sys::ring::{
    Field, CONNECTED, ERROR_COMM, ERROR_NONE, ERROR_PROTO, ERROR_RINGIDX, FEATURE_RECONNECTION, RING_SIZE,
};
use xs_wire::{nul_terminated, Decoder, Message, MsgType, HEADER_LEN, PAYLOAD_MAX};

const EIO: i32 = 5;
const EINVAL: i32 = 22;

fn p(fields: &[&str]) -> Vec<u8> {
    nul_terminated(&fields.iter().map(|f| f.as_bytes()).collect::<Vec<_>>())
}

/// Lets the loop finish what it was doing: a socket round trip after
/// anything the test did (the loop handles every ready descriptor before
/// the turns of the pass that answers it).
fn sync(c: &mut Client) {
    c.ok(MsgType::GetDomainPath, 0, b"0\0");
}

/// As `sync`, and the rest of that pass is over too: its writes to the
/// rings, which may come after the reply, and its notifications, at its
/// end. What a test then sees of the rings is all the loop did on account
/// of what came before: what did not happen will not.
fn settle(c: &mut Client) {
    sync(c);
    sync(c);
}

#[test]
fn dom0_ring_is_served_from_the_start() {
    // Written before the daemon exists: the notification is lost, and the
    // ring is examined at the start anyway.
    let d = Daemon::start_with(|_, hv| {
        let mut g = hv.guest(0).unwrap();
        g.send_request(MsgType::Read, 1, 0, b"/tool/xenstored\0", T).unwrap();
    });
    let mut g = G::new(d.hv.guest(0).unwrap());
    let m = g.g.recv_message(T).unwrap();
    assert_eq!((m.msg_type(), m.req_id), (Some(MsgType::Read), 1));
    assert!(!m.payload.is_empty(), "the executable");
    // As oxenstored: the reconnection feature, and the connection untouched.
    assert_eq!(
        (g.field(Field::ServerFeatures), g.field(Field::Connection)),
        (FEATURE_RECONNECTION, CONNECTED)
    );
    assert!(d.hv.is_bound(0));
    // Privileged: what only dom0 may do.
    assert_eq!(g.ok(MsgType::IsDomainIntroduced, b"0\0"), b"T\0");
    assert_eq!(g.ok(MsgType::IsDomainIntroduced, b"3\0"), b"F\0");
    g.write("/dom0-was-here", "1");
    assert_eq!(d.client().read(0, "/dom0-was-here"), Ok("1".into()));
}

#[test]
fn dom0_is_notified_at_the_start() {
    let d = Daemon::start();
    let mut g = d.hv.guest(0).unwrap();
    // `ox/domains.ml:173`: its kernel learns that xenstored is up.
    assert!(g.wait(T).unwrap());
    assert_eq!(g.ring().get(Field::ServerFeatures), FEATURE_RECONNECTION);
    // Domain 0 may not release itself.
    g.send_request(MsgType::Release, 9, 0, b"0\0", T).unwrap();
    let m = g.recv_message(T).unwrap();
    assert_eq!((m.req_id, &m.payload[..]), (9, &b"EINVAL\0"[..]));
    let mut c = d.client();
    assert!(introduced(&mut c, 0) && d.hv.is_bound(0));
}

#[test]
fn a_vm_starts_as_the_toolstack_starts_it() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut w = d.client();
    w.watch("@introduceDomain", "intro");
    w.watch("/local/domain/7/data", "w");
    w.wait_events(2);
    let (info, mut g) = d.domain(7);
    c.ok(MsgType::Mkdir, 0, &p(&["/local/domain/7"]));
    c.ok(MsgType::SetPerms, 0, &p(&["/local/domain/7", "n7"]));
    assert!(!introduced(&mut c, 7));
    assert_eq!(introduce(&mut c, &info), Ok(()));
    assert!(introduced(&mut c, 7));
    assert!(d.hv.is_bound(7));
    w.wait_events(3);
    assert_eq!(w.events[2], ("@introduceDomain".into(), "intro".into()));
    // What oxenstored sets on a new ring.
    assert_eq!(
        (
            g.field(Field::ServerFeatures),
            g.field(Field::Connection),
            g.field(Field::Error)
        ),
        (FEATURE_RECONNECTION, CONNECTED, ERROR_NONE)
    );

    // At home, relative and absolute.
    assert_eq!(g.ok(MsgType::GetDomainPath, b"7\0"), b"/local/domain/7\0");
    g.write("name", "vm7");
    assert_eq!(g.read("/local/domain/7/name"), Ok("vm7".into()));
    g.write("/local/domain/7/data", "x");
    assert_eq!(g.read("data"), Ok("x".into()));
    // Not elsewhere.
    assert_eq!(g.error(MsgType::Write, b"/elsewhere\0v"), "EACCES");
    assert_eq!(g.read("/tool/xenstored"), Err("EACCES".into()));
    assert_eq!(g.error(MsgType::IsDomainIntroduced, b"7\0"), "EACCES");
    assert_eq!(
        g.error(MsgType::Introduce, &harness::introduce_payload(8, 1, 1)),
        "EACCES"
    );

    // Ring to socket: the guest's write reaches the socket's watch.
    w.wait_events(4);
    assert_eq!(w.events[3], ("/local/domain/7/data".into(), "w".into()));
    // Socket to ring.
    g.watch("data", "tok");
    g.wait_events(1);
    assert_eq!(g.events[0], ("data".into(), "tok".into()));
    c.write(0, "/local/domain/7/data/k", "v");
    g.wait_events(2);
    assert_eq!(g.events[1], ("data/k".into(), "tok".into()));
    assert_eq!(g.read("data/k"), Ok("v".into()));
    // In a transaction too.
    let tx = String::from_utf8(g.ok(MsgType::TransactionStart, b"\0"))
        .unwrap()
        .trim_end_matches('\0')
        .parse()
        .unwrap();
    g.call_tx(MsgType::Write, tx, b"data/t\0in");
    assert_eq!(g.call_tx(MsgType::TransactionEnd, tx, b"T\0").payload, b"OK\0");
    assert_eq!(c.read(0, "/local/domain/7/data/t"), Ok("in".into()));
    g.wait_events(3);
}

#[test]
fn introduce_failures_leave_nothing_behind() {
    let d = Daemon::start();
    let mut c = d.client();
    let (info, mut g) = d.domain(7);
    let check_nothing = |c: &mut Client, g: &mut G| {
        assert!(!introduced(c, 7));
        assert!(!d.hv.is_bound(7));
        assert_eq!(g.field(Field::ServerFeatures), 0, "the page was not written");
    };
    d.hv.fail_once(Op::MapRing, EIO);
    assert_eq!(introduce(&mut c, &info), Err("EINVAL".into()));
    check_nothing(&mut c, &mut g);
    d.hv.fail_once(Op::BindInterdomain, EIO);
    assert_eq!(introduce(&mut c, &info), Err("EINVAL".into()));
    check_nothing(&mut c, &mut g);
    assert_eq!(
        introduce_at(&mut c, 7, info.gfn + 1, info.port),
        Err("EINVAL".into()),
        "an unknown gfn"
    );
    assert_eq!(
        introduce_at(&mut c, 7, info.gfn, info.port + 1),
        Err("EINVAL".into()),
        "a port that is not the guest's"
    );
    assert_eq!(
        introduce_at(&mut c, 99, info.gfn, info.port),
        Err("EINVAL".into()),
        "no such domain"
    );
    check_nothing(&mut c, &mut g);
    assert_eq!(introduce(&mut c, &info), Ok(()));
    assert_eq!(g.ok(MsgType::GetDomainPath, b"7\0"), b"/local/domain/7\0");
    assert_eq!(
        c.read(0, "/local/domain/7"),
        Err("ENOENT".into()),
        "INTRODUCE creates no node"
    );
}

#[test]
fn introduce_of_a_known_domain() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 7);
    let info = g.g.info();
    // The same ring and port: the event channel is bound again (`ox/process.ml:595-601`).
    assert_eq!(introduce(&mut c, &info), Ok(()));
    assert!(d.hv.is_bound(7));
    g.write("a", "1");
    // The old port cannot be unbound: EIO, and it stays.
    d.hv.fail_once(Op::Unbind, EIO);
    assert_eq!(introduce(&mut c, &info), Err("EIO".into()));
    assert!(d.hv.is_bound(7));
    g.write("a", "2");
    // Another ring: refused, nothing bound again.
    assert_eq!(introduce_at(&mut c, 7, info.gfn + 1, info.port), Err("EINVAL".into()));
    // The bind fails: EIO, and the old channel is bound again.
    d.hv.fail_once(Op::BindInterdomain, EINVAL);
    assert_eq!(introduce(&mut c, &info), Err("EIO".into()));
    assert!(d.hv.is_bound(7));
    g.write("a", "3");
    // Both fail: the guest is not served until introduced again, but
    // still gets what the ring carries.
    g.watch("a", "t");
    g.wait_events(1);
    d.hv.fail(Op::BindInterdomain, EINVAL);
    assert_eq!(introduce(&mut c, &info), Err("EIO".into()));
    assert!(!d.hv.is_bound(7));
    assert!(introduced(&mut c, 7));
    c.write(0, "/local/domain/7/a", "4");
    eventually("the event in the ring", || {
        g.field(Field::RspProd) != g.field(Field::RspCons)
    });
    g.wait_events(2);
    d.hv.heal(Op::BindInterdomain);
    assert_eq!(introduce(&mut c, &info), Ok(()));
    assert!(d.hv.is_bound(7));
    assert_eq!(g.read("a"), Ok("4".into()));
    // The guest introducing itself is EACCES; dom0's ring may.
    assert_eq!(
        g.error(MsgType::Introduce, &harness::introduce_payload(7, info.gfn, info.port)),
        "EACCES"
    );
    let mut g0 = G::new(d.hv.guest(0).unwrap());
    assert_eq!(
        g0.ok(MsgType::Introduce, &harness::introduce_payload(7, info.gfn, info.port)),
        b"OK\0"
    );
    assert_eq!(g.read("a"), Ok("4".into()));
    // Released without an event channel.
    d.hv.fail(Op::BindInterdomain, EINVAL);
    assert_eq!(introduce(&mut c, &info), Err("EIO".into()));
    assert_eq!(c.ok(MsgType::Release, 0, b"7\0"), b"OK\0");
    assert!(!introduced(&mut c, 7) && !d.hv.is_bound(7));
}

#[test]
fn guests_interleaved_see_their_own_replies() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut gs: Vec<G> = (1..=4).map(|domid| d.vm(&mut c, domid)).collect();
    for round in 0..20 {
        // Each guest sends, then each reads: the rings are all busy at once.
        let ids: Vec<u32> = gs
            .iter_mut()
            .enumerate()
            .map(|(i, g)| g.send(MsgType::Write, format!("v\0{i}-{round}").as_bytes()))
            .collect();
        for (g, id) in gs.iter_mut().zip(&ids) {
            let m = g.reply();
            assert_eq!((m.req_id, &m.payload[..]), (*id, &b"OK\0"[..]));
        }
        let ids: Vec<u32> = gs.iter_mut().map(|g| g.send(MsgType::Read, b"v\0")).collect();
        for (i, (g, id)) in gs.iter_mut().zip(&ids).enumerate() {
            let m = g.reply();
            assert_eq!(
                (m.req_id, String::from_utf8(m.payload).unwrap()),
                (*id, format!("{i}-{round}"))
            );
        }
    }
}

#[test]
fn requests_and_replies_larger_than_the_ring() {
    let d = Daemon::start_with(|o, _| o.config.value_max = usize::MAX);
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    // A payload of PAYLOAD_MAX: 4 KiB through a 1 KiB ring, each way.
    let value: Vec<u8> = (0..PAYLOAD_MAX - 4).map(|i| b'a' + (i % 26) as u8).collect();
    const { assert!(HEADER_LEN + PAYLOAD_MAX > 4 * RING_SIZE) };
    g.ok(MsgType::Write, &[&b"big\0"[..], &value].concat());
    assert_eq!(c.read(0, "/local/domain/3/big").unwrap().as_bytes(), &value[..]);
    let m = g.call(MsgType::Read, b"big\0");
    assert!(m.payload == value, "intact");
    // A reply over the protocol's limit is E2BIG on a ring.
    let name = "n".repeat(100);
    for i in 0..45 {
        c.write(0, &format!("/local/domain/3/dir/{name}{i}"), "");
    }
    assert_eq!(c.ls(0, "/local/domain/3/dir").len(), 45, "a socket gets it");
    assert_eq!(g.error(MsgType::Directory, b"dir\0"), "E2BIG");
    // A request over it: the core gives up on the ring.
    let mut header = request(MsgType::Write, 1, b"");
    header[12..16].copy_from_slice(&(PAYLOAD_MAX as u32 + 1).to_le_bytes());
    g.g.send(&header).unwrap();
    eventually("read", || g.field(Field::ReqProd) == g.field(Field::ReqCons));
    sync(&mut c);
    assert!(introduced(&mut c, 3), "kept, ignored");
    g.g.send(&request(MsgType::GetDomainPath, 2, b"3\0")).unwrap();
    settle(&mut c);
    assert_eq!(g.field(Field::RspProd), g.field(Field::RspCons), "no reply");
    assert_ne!(g.field(Field::ReqProd), g.field(Field::ReqCons), "not read");
    c.ok(MsgType::Release, 0, b"3\0");
}

#[test]
fn a_guest_that_does_not_read_is_held_at_the_soft_limit() {
    let d = Daemon::start_with(|o, _| o.config.output_soft_limit = 200);
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    let mut other = d.vm(&mut c, 6);
    c.write(0, "/local/domain/5/v", &"v".repeat(100));
    // Requests of 34 bytes, replies of 116: the reply ring fills after 8,
    // the core holds a little more and stops; what was read waits in the
    // core, and what comes next in the request ring.
    let mut sent = 0u32;
    let mut fill = |g: &mut G| {
        let r = g.g.ring();
        while RING_SIZE - (r.get(Field::ReqProd).wrapping_sub(r.get(Field::ReqCons)) as usize) >= 34 {
            assert_eq!(
                r.write(&request(MsgType::Read, sent, b"/local/domain/5/v\0")).unwrap(),
                34
            );
            sent += 1;
        }
        g.g.notify();
    };
    fill(&mut g);
    let first = g.field(Field::ReqProd);
    eventually("the reply ring full", || {
        g.field(Field::RspProd).wrapping_sub(g.field(Field::RspCons)) as usize > RING_SIZE - 116
    });
    // Then it stops reading. The turn that filled the reply ring read the
    // requests first, all of them at once (nothing had the loop look at
    // the ring before the notification).
    let held = g.field(Field::ReqCons);
    assert_eq!(held, first, "read at once");
    fill(&mut g);
    // Others are served meanwhile.
    for i in 0..10 {
        other.write("x", &i.to_string());
        c.write(0, "/y", "1");
    }
    settle(&mut c);
    assert_eq!(g.field(Field::ReqCons), held, "not read further");
    assert_ne!(g.field(Field::ReqProd), held, "requests wait in the ring");
    // The guest reads: everything completes, in order.
    for i in 0..sent {
        let m = g.g.recv_message(T).unwrap();
        assert_eq!((m.req_id, m.payload.len()), (i, 100));
    }
    assert_eq!(g.read("v").unwrap().len(), 100);
}

#[test]
fn requests_past_the_budget_need_no_new_notification() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 4);
    // 25 requests in one notification: more than a turn handles, and
    // replies that all fit in the ring, read without notifying.
    let mut bytes = Vec::new();
    for i in 0..25u32 {
        bytes.extend(request(MsgType::GetDomainPath, i, b"4\0"));
    }
    assert_eq!(g.g.ring().write(&bytes).unwrap(), bytes.len());
    g.g.notify();
    let mut dec = Decoder::new();
    let mut got = Vec::new();
    let mut buf = [0u8; RING_SIZE];
    eventually("25 replies", || {
        let n = g.g.ring().read(&mut buf).unwrap();
        dec.push(&buf[..n]);
        while let Some(m) = dec.next_message().unwrap() {
            got.push(m);
        }
        got.len() == 25
    });
    for (i, m) in got.iter().enumerate() {
        assert_eq!((m.req_id, &m.payload[..]), (i as u32, &b"/local/domain/4\0"[..]));
    }
}

/// A guest that notifies as Linux does (drivers/xen/xenbus/xenbus_comms.c):
/// after a write only if the server had consumed everything before it,
/// after a read only if the reply ring was full before it.
struct LinuxGuest {
    g: G,
    dec: Decoder,
}

impl LinuxGuest {
    fn write(&mut self, bytes: &[u8]) -> usize {
        let r = self.g.g.ring();
        let prod = r.get(Field::ReqProd);
        let n = r.write(bytes).unwrap();
        if n > 0 && r.get(Field::ReqCons).wrapping_sub(prod) as i32 >= 0 {
            self.g.g.notify();
        }
        n
    }

    fn read(&mut self) -> usize {
        let mut buf = [0u8; RING_SIZE];
        let r = self.g.g.ring();
        let cons = r.get(Field::RspCons);
        let n = r.read(&mut buf).unwrap();
        if n > 0 && r.get(Field::RspProd).wrapping_sub(cons) as usize >= RING_SIZE {
            self.g.g.notify();
        }
        self.dec.push(&buf[..n]);
        n
    }
}

#[test]
fn a_guest_that_notifies_only_when_needed_is_never_stalled() {
    let d = Daemon::start_with(|o, _| o.config.value_max = usize::MAX);
    let mut c = d.client();
    let mut lg = LinuxGuest {
        g: d.vm(&mut c, 9),
        dec: Decoder::new(),
    };
    // xorshift: sizes of all kinds, so that requests and replies straddle
    // the ends of the rings and each other.
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut out = Vec::new();
    let mut expect = std::collections::VecDeque::new();
    for i in 0..300u32 {
        let len = [0, 1, 100, 1000, 3000, PAYLOAD_MAX - 2][(next() % 6) as usize];
        let value = vec![b'0' + (i % 10) as u8; len];
        out.extend(request(MsgType::Write, 2 * i, &[&b"v\0"[..], &value].concat()));
        out.extend(request(MsgType::Read, 2 * i + 1, b"v\0"));
        expect.push_back((2 * i, b"OK\0".to_vec()));
        expect.push_back((2 * i + 1, value));
    }
    let mut sent = 0;
    while !expect.is_empty() {
        sent += lg.write(&out[sent..]);
        let moved = lg.read();
        while let Some(m) = lg.dec.next_message().unwrap() {
            let (id, payload) = expect.pop_front().unwrap();
            assert_eq!(m.req_id, id);
            assert!(m.payload == payload, "reply {id}");
        }
        if moved == 0 && !expect.is_empty() {
            // Nothing to read: the server owes a notification.
            assert!(lg.g.g.wait(T).unwrap(), "stalled with {} replies to come", expect.len());
        }
    }
}

#[test]
fn ring_reconnection() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 2);
    g.watch("w", "t");
    g.wait_events(1);
    let tx: u32 = String::from_utf8(g.ok(MsgType::TransactionStart, b"\0"))
        .unwrap()
        .trim_end_matches('\0')
        .parse()
        .unwrap();
    // A partial request, then the guest gives up on the ring.
    g.g.ring()
        .write(&request(MsgType::Write, 1, b"w\0partial")[..10])
        .unwrap();
    g.g.reconnect(T).unwrap();
    assert_eq!(g.field(Field::Connection), CONNECTED);
    assert_eq!(
        (
            g.field(Field::ReqCons),
            g.field(Field::ReqProd),
            g.field(Field::RspCons),
            g.field(Field::RspProd)
        ),
        (0, 0, 0, 0)
    );
    // Usable again; the transaction and the watch are gone.
    assert_eq!(g.call_tx(MsgType::Read, tx, b"w\0").payload, b"EIO\0");
    c.write(0, "/local/domain/2/w", "1");
    assert_eq!(g.read("w"), Ok("1".into()));
    assert_eq!(g.events.len(), 1, "no event");
    assert!(introduced(&mut c, 2));
    assert_eq!(g.ok(MsgType::TransactionStart, b"\0"), b"1\0", "ids start again");

    // Asked while output is on its way to the ring: not written, reset.
    // The reply and the event are read without notifying, which would
    // have the daemon look at the ring, and reset it, before the output.
    g.g.ring().write(&request(MsgType::Watch, 5, &p(&["w", "t2"]))).unwrap();
    g.g.notify();
    let (mut dec, mut got, mut buf) = (Decoder::new(), 0, [0u8; RING_SIZE]);
    eventually("the reply and the event", || {
        let n = g.g.ring().read(&mut buf).unwrap();
        dec.push(&buf[..n]);
        while dec.next_message().unwrap().is_some() {
            got += 1;
        }
        got == 2
    });
    // Its last look at the ring (it moved bytes) comes before this reply.
    sync(&mut c);
    g.g.ring().request_reconnect();
    c.write(0, "/local/domain/2/w", "2");
    g.g.notify();
    eventually("reconnected", || g.field(Field::Connection) == CONNECTED);
    assert_eq!(g.field(Field::RspProd), 0);
    assert_eq!(g.read("w"), Ok("2".into()));
}

#[test]
fn a_reconnection_asked_before_introduce_is_done_at_once() {
    let d = Daemon::start();
    let mut c = d.client();
    let (info, mut g) = d.domain(3);
    g.g.ring().request_reconnect();
    assert_eq!(introduce(&mut c, &info), Ok(()));
    eventually("connected", || g.field(Field::Connection) == CONNECTED);
    assert!(g.g.wait(T).unwrap(), "notified");
    assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
}

#[test]
fn a_guest_that_corrupts_its_ring_is_ignored_until_released() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut bad = d.vm(&mut c, 3);
    let mut bad_out = d.vm(&mut c, 4);
    let mut good = d.vm(&mut c, 5);
    bad.watch("x", "t");
    // Requests: a producer far ahead of the consumer.
    let cons = bad.field(Field::ReqCons);
    bad.g.ring().set(Field::ReqProd, cons.wrapping_add(5000));
    bad.g.notify();
    eventually("marked bad", || bad.field(Field::Error) == ERROR_RINGIDX);
    // Replies: a consumer ahead of the producer, found when the reply is written.
    let prod = bad_out.field(Field::RspProd);
    bad_out.g.ring().set(Field::RspCons, prod.wrapping_add(2000));
    bad_out.g.send_request(MsgType::GetDomainPath, 1, 0, b"4\0", T).unwrap();
    eventually("marked bad", || bad_out.field(Field::Error) == ERROR_RINGIDX);
    // The daemon goes on; the others are served; the domains stay known.
    good.write("x", "1");
    c.write(0, "/local/domain/3/x", "1");
    assert!(introduced(&mut c, 3) && introduced(&mut c, 4));
    // A bad connection is not served any more, and its notifications are ignored.
    for f in [Field::ReqCons, Field::ReqProd] {
        bad.g.ring().set(f, 0);
    }
    bad.g.send_request(MsgType::GetDomainPath, 2, 0, b"3\0", T).unwrap();
    settle(&mut c);
    assert_eq!(bad.field(Field::ReqCons), 0);
    // RELEASE cleans it.
    c.ok(MsgType::Release, 0, b"3\0");
    c.ok(MsgType::Release, 0, b"4\0");
    assert!(!introduced(&mut c, 3) && !d.hv.is_bound(3) && !d.hv.is_bound(4));
    assert_eq!(good.read("x"), Ok("1".into()));
}

#[test]
fn shutdown_and_death_through_virq_dom_exc() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut w = d.client();
    w.watch("@releaseDomain", "rel");
    w.wait_events(1);
    let mut g = d.vm(&mut c, 7);
    let mut alive = d.vm(&mut c, 8);
    g.write("data", "1");
    g.watch("/local/domain/8", "t");
    alive.write("data", "1");
    // Shut down: the watchers hear of it, the domain stays.
    d.hv.set_state(7, DomainState::Shutdown).unwrap();
    w.wait_events(2);
    assert_eq!(w.events[1], ("@releaseDomain".into(), "rel".into()));
    assert!(introduced(&mut c, 7));
    // A state that cannot be read does not kill a domain.
    d.hv.fail(Op::DomainState, EIO);
    d.hv.set_state(7, DomainState::Dead).unwrap();
    sync(&mut c);
    assert!(introduced(&mut c, 7) && introduced(&mut c, 8));
    d.hv.heal(Op::DomainState);
    // Dead: connection, watches, nodes and port go.
    d.hv.fire_dom_exc();
    w.wait_events(3);
    assert!(!introduced(&mut c, 7));
    assert!(!d.hv.is_bound(7));
    assert_eq!(c.read(0, "/local/domain/7/data"), Err("ENOENT".into()));
    let watches = String::from_utf8(c.ok(MsgType::Control, 0, b"watches\0")).unwrap();
    assert!(
        !watches.contains("D7") && watches.contains("@releaseDomain"),
        "{watches}"
    );
    // The other is untouched.
    assert!(introduced(&mut c, 8));
    assert_eq!(alive.read("data"), Ok("1".into()));
    // A destroyed domain, with an unbind that fails.
    d.hv.fail_once(Op::Unbind, EIO);
    d.hv.destroy_domain(8).unwrap();
    w.wait_events(4);
    assert!(!introduced(&mut c, 8));
    // VIRQ_DOM_EXC cannot be unmasked for a while: tried until it is,
    // and nothing is lost meanwhile.
    let _g9 = d.vm(&mut c, 9);
    d.hv.fail(Op::Unmask, EIO);
    d.hv.fire_dom_exc();
    sync(&mut c);
    d.hv.set_state(9, DomainState::Shutdown).unwrap();
    // A pass that tried again, and failed, after the VIRQ fired; and one
    // more.
    sync(&mut c);
    sync(&mut c);
    d.hv.heal(Op::Unmask);
    w.wait_events(5);
    assert!(introduced(&mut c, 9));
    // Those failures make one streak: logged once, at its first.
    let log = d.stop_with_log();
    let n = log.lines().filter(|l| l.contains("cannot unmask VIRQ_DOM_EXC")).count();
    assert_eq!(n, 1, "{log}");
}

#[test]
fn release_from_a_socket() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut w = d.client();
    w.watch("@releaseDomain", "rel");
    let mut g = d.vm(&mut c, 6);
    g.write("data", "1");
    assert_eq!(c.ok(MsgType::Release, 0, b"6\0"), b"OK\0");
    w.wait_events(2);
    assert!(!introduced(&mut c, 6) && !d.hv.is_bound(6));
    assert_eq!(c.read(0, "/local/domain/6/data"), Err("ENOENT".into()));
    assert_eq!(c.error(MsgType::Release, 0, b"6\0"), "EINVAL");
    // The guest's notifications go nowhere; introduced again, it is served.
    g.g.notify();
    assert_eq!(introduce(&mut c, &g.g.info()), Ok(()));
    assert_eq!(g.ok(MsgType::GetDomainPath, b"6\0"), b"/local/domain/6\0");
    // Introduced and released in one turn: the port that the bind left
    // pending is unbound when it is read.
    let (info, _g9) = d.domain(9);
    let mut bytes = request(
        MsgType::Introduce,
        1,
        &harness::introduce_payload(9, info.gfn, info.port),
    );
    bytes.extend(request(MsgType::Release, 2, b"9\0"));
    c.send_raw(&bytes);
    assert_eq!(
        (c.reply().payload, c.reply().payload),
        (b"OK\0".to_vec(), b"OK\0".to_vec())
    );
    sync(&mut c);
    assert!(!introduced(&mut c, 9) && !d.hv.is_bound(9));
}

#[test]
fn disable_socket_serves_the_rings_only() {
    let d = Daemon::start_with(|o, _| o.disable_socket = true);
    assert!(!d.socket.exists());
    assert!(!d.socket.parent().unwrap().exists());
    let mut g0 = G::new(d.hv.guest(0).unwrap());
    let (info, mut g) = d.domain(3);
    g0.ok(MsgType::Mkdir, b"/local/domain/3\0");
    g0.ok(MsgType::SetPerms, b"/local/domain/3\0n3\0");
    assert_eq!(
        g0.ok(MsgType::Introduce, &harness::introduce_payload(3, info.gfn, info.port)),
        b"OK\0"
    );
    g.write("k", "v");
    assert_eq!(g0.read("/local/domain/3/k"), Ok("v".into()));
}

#[test]
fn each_start_step_that_fails_fails_the_start_before_ready() {
    let cases: [(Op, &str); 5] = [
        (Op::DomainState, "cannot ask Xen about domain 0"),
        (Op::BindDomExc, "cannot bind VIRQ_DOM_EXC"),
        (Op::Dom0Ring, "cannot map domain 0's ring"),
        (Op::BindInterdomain, "cannot bind domain 0's event channel"),
        (Op::Notify, "cannot notify domain 0"),
    ];
    for (op, text) in cases {
        let f = Daemon::launch(|_, hv| hv.fail(op, EIO), Box::new(Ok))
            .err()
            .unwrap_or_else(|| panic!("{op:?}: started"));
        assert!(!f.ready_called);
        let msg = f.error.to_string();
        assert!(msg.starts_with(text) && msg.contains("os error 5"), "{op:?}: {msg}");
    }
    let f = Daemon::launch(|_, hv| hv.set_state(0, DomainState::Dead).unwrap(), Box::new(Ok))
        .err()
        .unwrap();
    assert!(f.error.to_string().contains("domain 0 does not exist"), "{}", f.error);
    let f = Daemon::launch(|_, _| {}, Box::new(|_| Err(io::Error::from_raw_os_error(2))))
        .err()
        .unwrap();
    assert!(
        f.error.to_string().starts_with("cannot open the Xen devices"),
        "{}",
        f.error
    );
    assert_eq!(f.error.kind(), io::ErrorKind::NotFound);
    let f = Daemon::launch(|o, _| o.socket = "/proc/rxenstored/socket".into(), Box::new(Ok))
        .err()
        .unwrap();
    assert!(f.error.to_string().contains("/proc/rxenstored/socket"), "{}", f.error);
}

#[test]
fn no_domain_init_touches_no_backend() {
    let opened = Arc::new(AtomicBool::new(false));
    let flag = opened.clone();
    let d = Daemon::launch(
        |o, _| o.domain_init = false,
        Box::new(move |x| {
            flag.store(true, Ordering::SeqCst);
            Ok(x)
        }),
    )
    .unwrap();
    let mut c = d.client();
    c.write(0, "/a", "1");
    assert_eq!(c.read(0, "/a"), Ok("1".into()));
    let info = d.hv.create_domain(3).unwrap();
    assert_eq!(introduce(&mut c, &info), Err("EINVAL".into()));
    assert!(!introduced(&mut c, 0));
    assert!(!opened.load(Ordering::SeqCst));
    assert!(!d.hv.is_bound(0));
    d.stop().unwrap();
}

#[test]
fn a_failing_event_channel_device_does_not_stop_the_service() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    let mut w = d.client();
    w.watch("@releaseDomain", "r");
    w.wait_events(1);
    // Every read of the pending ports fails: every ring and every domain
    // is examined instead.
    d.hv.fail(Op::Pending, EIO);
    g.write("a", "1");
    assert_eq!(g.read("a"), Ok("1".into()));
    d.hv.set_state(3, DomainState::Shutdown).unwrap();
    w.wait_events(2);
    d.hv.heal(Op::Pending);
    assert_eq!(g.read("a"), Ok("1".into()));
    sync(&mut c);
}

#[test]
fn notify_and_unmask_failures_are_survived() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    // The reply is in the ring, but the guest is not told.
    d.hv.fail(Op::Notify, EIO);
    g.g.send_request(MsgType::GetDomainPath, 1, 0, b"3\0", T).unwrap();
    eventually("the reply", || g.field(Field::RspProd) != g.field(Field::RspCons));
    g.g.send_request(MsgType::GetDomainPath, 2, 0, b"3\0", T).unwrap();
    eventually("the second reply", || {
        g.field(Field::RspProd).wrapping_sub(g.field(Field::RspCons)) == 2 * 32
    });
    d.hv.heal(Op::Notify);
    for id in [1, 2] {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, id);
    }
    // The port cannot be unmasked for a while: tried until it is.
    d.hv.fail(Op::Unmask, EIO);
    assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    g.g.send_request(MsgType::GetDomainPath, 3, 0, b"3\0", T).unwrap();
    // A pass that tried again, and failed, after the guest notified.
    sync(&mut c);
    d.hv.heal(Op::Unmask);
    assert_eq!(g.g.recv_message(T).unwrap().req_id, 3);
    for _ in 0..3 {
        assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    }
}

/// A failure that repeats is logged once per streak, at its first: three
/// notifications fail, then the unmasks of a pass after another.
#[test]
fn repeated_failures_are_logged_once() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    d.hv.fail(Op::Notify, EIO);
    for n in 1..=3u32 {
        g.g.send_request(MsgType::GetDomainPath, n, 0, b"3\0", T).unwrap();
        eventually("the reply", || {
            g.field(Field::RspProd).wrapping_sub(g.field(Field::RspCons)) == n * 32
        });
    }
    d.hv.heal(Op::Notify);
    for id in 1..=3 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, id);
    }
    d.hv.fail(Op::Unmask, EIO);
    for _ in 0..3 {
        assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
        sync(&mut c);
    }
    d.hv.heal(Op::Unmask);
    assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    drop((c, g));
    let log = d.stop_with_log();
    let count = |what: &str| log.lines().filter(|l| l.contains(what)).count();
    assert_eq!(count("domain 3: cannot notify local port"), 1, "{log}");
    assert_eq!(count("domain 3: cannot unmask its port, trying again"), 1, "{log}");
}

#[test]
fn stopping_leaves_the_rings_as_they_are() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    g.write("a", "1");
    g.g.ring().write(&request(MsgType::Read, 1, b"a\0")[..5]).unwrap();
    let mut g0 = G::new(d.hv.guest(0).unwrap());
    g0.write("/b", "1");
    let before: Vec<u32> = Field::ALL.iter().map(|&f| g.field(f)).collect();
    let before0: Vec<u32> = Field::ALL.iter().map(|&f| g0.field(f)).collect();
    d.stop().unwrap();
    assert_eq!(Field::ALL.iter().map(|&f| g.field(f)).collect::<Vec<_>>(), before);
    assert_eq!(Field::ALL.iter().map(|&f| g0.field(f)).collect::<Vec<_>>(), before0);
    assert!(c.next().is_none(), "socket clients see the end");
}

#[test]
fn the_daemon_does_not_notify_without_cause() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    // The reply's notification, at the end of its pass, is taken (unless
    // waiting for the reply took it).
    settle(&mut c);
    g.g.wait(Duration::ZERO).unwrap();
    // A notification with nothing in the ring moves nothing: no answer.
    g.g.notify();
    settle(&mut c);
    assert!(!g.g.wait(Duration::ZERO).unwrap());
}

/// Output that does not fit a full reply ring moves nothing, so it is no
/// cause to notify either.
#[test]
fn a_full_reply_ring_is_not_notified_for_nothing() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    g.watch("w", "t");
    g.wait_events(1);
    // 40 requests, whose replies (32 bytes each) fill the ring's 1,024.
    let mut bytes = Vec::new();
    for i in 0..40u32 {
        bytes.extend(request(MsgType::GetDomainPath, 100 + i, b"3\0"));
    }
    assert_eq!(g.g.ring().write(&bytes).unwrap(), bytes.len());
    g.g.notify();
    eventually("a full reply ring", || {
        g.field(Field::RspProd).wrapping_sub(g.field(Field::RspCons)) == RING_SIZE as u32
    });
    settle(&mut c);
    g.g.wait(Duration::ZERO).unwrap();
    // A watch event for it: queued, and written nowhere.
    c.write(0, "/local/domain/3/w", "1");
    settle(&mut c);
    assert!(!g.g.wait(Duration::ZERO).unwrap(), "notified, nothing moved");
}

#[test]
fn the_loop_sleeps_when_nothing_happens() {
    let t0 = Instant::now();
    let d = Daemon::start();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    g.watch("w", "t");
    c.write(0, "/local/domain/3/w", "1");
    g.wait_events(2);
    assert_eq!(g.read("w"), Ok("1".into()));
    settle(&mut c);
    // Every ring that fired was unmasked, nothing is queued: the loop
    // sleeps until the scan's first tick, 20 s after domain 0's ring was
    // added, so after `t0`: not 0 (a loop that spins), nor a short wait
    // (one that wakes up for nothing). Bracketed by `t0` and now, however
    // long the test took.
    let timeout = d.sleeping();
    let least = (t0 + Duration::from_secs(20))
        .saturating_duration_since(Instant::now())
        .as_millis();
    assert!(
        least <= timeout as u128 && timeout <= 20_000,
        "sleeps {timeout} ms, at least {least}"
    );
}

/// A guest that never notifies: it writes requests and reads replies
/// behind the server's back, as a buggy or lazy driver may.
struct LazyGuest {
    g: G,
    dec: Decoder,
}

impl LazyGuest {
    fn new(g: G) -> LazyGuest {
        LazyGuest { g, dec: Decoder::new() }
    }

    fn write(&mut self, bytes: &[u8]) {
        assert_eq!(self.g.g.ring().write(bytes).unwrap(), bytes.len());
    }

    /// Reads what there is; the messages complete so far.
    fn read(&mut self) -> Vec<Message> {
        let mut buf = [0u8; RING_SIZE];
        let n = self.g.g.ring().read(&mut buf).unwrap();
        self.dec.push(&buf[..n]);
        std::iter::from_fn(|| self.dec.next_message().unwrap()).collect()
    }

    /// The next `n` messages, read without notifying.
    fn replies(&mut self, n: usize) -> Vec<Message> {
        let mut got = Vec::new();
        eventually("replies to a lazy guest", || {
            got.extend(self.read());
            got.len() >= n
        });
        got
    }

    fn has_reply(&mut self) -> bool {
        self.g.field(Field::RspProd) != self.g.field(Field::RspCons)
    }
}

const SCAN: Duration = Duration::from_millis(200);

/// The next `n` messages to a lazy guest, which only the scan can bring
/// (nothing tells the loop about them), with fewer rings than a batch:
/// each tick looks at every ring. Meanwhile the loop is never seen asleep
/// for longer than the scan's period: what is owed comes within a period
/// of each tick, by construction rather than by a stopwatch.
fn by_the_scan(d: &Daemon, g: &mut LazyGuest, n: usize) -> Vec<Message> {
    let mut got = Vec::new();
    eventually("messages brought by the scan", || {
        got.extend(g.read());
        if got.len() >= n {
            return true;
        }
        let t = d.sleeping();
        assert!((0..=SCAN.as_millis() as i32).contains(&t), "sleeps {t} ms");
        false
    });
    got
}
/// What a loaded machine may add to a deadline.
const SLACK: Duration = Duration::from_millis(1500);

#[test]
fn a_guest_that_never_notifies_is_served_by_the_scan() {
    let d = Daemon::start_with(|o, _| o.ring_scan = Some(SCAN));
    let mut c = d.client();
    let mut g = LazyGuest::new(d.vm(&mut c, 3));
    for i in 0..3 {
        g.write(&request(MsgType::GetDomainPath, i, b"3\0"));
        let m = by_the_scan(&d, &mut g, 1);
        assert_eq!((m[0].req_id, &m[0].payload[..]), (i, &b"/local/domain/3\0"[..]));
    }
}

#[test]
fn a_guest_that_reads_without_notifying_gets_the_rest() {
    let d = Daemon::start_with(|o, _| {
        o.ring_scan = Some(SCAN);
        o.config.value_max = usize::MAX;
    });
    let mut c = d.client();
    let mut g = LazyGuest::new(d.vm(&mut c, 3));
    let value: String = (0..3000).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    c.write(0, "/local/domain/3/v", &value);
    // Notified, the request; the reply, three rings' worth, is read
    // without telling the server that there is room.
    g.g.g.send_request(MsgType::Read, 1, 0, b"v\0", T).unwrap();
    let m = by_the_scan(&d, &mut g, 1);
    assert_eq!((m[0].req_id, m[0].payload.len()), (1, value.len()));
    assert!(m[0].payload == value.as_bytes());
}

#[test]
fn the_scan_leaves_bad_connections_alone() {
    let d = Daemon::start_with(|o, _| o.ring_scan = Some(SCAN));
    let mut c = d.client();
    let mut bad = LazyGuest::new(d.vm(&mut c, 3));
    let mut good = LazyGuest::new(d.vm(&mut c, 4));
    let cons = bad.g.field(Field::ReqCons);
    bad.g.g.ring().set(Field::ReqProd, cons.wrapping_add(5000));
    bad.g.g.notify();
    eventually("marked bad", || bad.g.field(Field::Error) == ERROR_RINGIDX);
    for f in [Field::ReqCons, Field::ReqProd] {
        bad.g.g.ring().set(f, 0);
    }
    bad.write(&request(MsgType::GetDomainPath, 1, b"3\0"));
    good.write(&request(MsgType::GetDomainPath, 2, b"4\0"));
    // The good one's scan came; the bad one's was skipped. Three ticks:
    // each looked at every ring (fewer than a batch), the bad one's after
    // its request, and its turn would have come before the good one's
    // reply was written.
    for id in [2, 3, 4] {
        if id > 2 {
            good.write(&request(MsgType::GetDomainPath, id, b"4\0"));
        }
        assert_eq!(good.replies(1)[0].req_id, id);
        assert_eq!(bad.g.field(Field::ReqCons), 0, "not read");
    }
}

#[test]
fn without_the_scan_lazy_guests_stall_and_the_others_do_not() {
    let d = Daemon::start_with(|o, _| {
        o.ring_scan = None;
        o.config.value_max = usize::MAX;
    });
    let mut c = d.client();
    let mut silent = LazyGuest::new(d.vm(&mut c, 3));
    let mut reader = LazyGuest::new(d.vm(&mut c, 4));
    let mut good = d.vm(&mut c, 5);
    c.write(0, "/local/domain/4/v", &"v".repeat(3000));
    silent.write(&request(MsgType::GetDomainPath, 1, b"3\0"));
    reader.g.g.send_request(MsgType::Read, 2, 0, b"v\0", T).unwrap();
    eventually("a ring's worth of reply", || {
        reader
            .g
            .field(Field::RspProd)
            .wrapping_sub(reader.g.field(Field::RspCons)) as usize
            == RING_SIZE
    });
    // The write that filled the ring left output: the loop tries once
    // more at its next pass, without a notification, and finds the ring
    // full. Read before that try (a loaded machine may deschedule the
    // loop between the two passes), the ring would get more at once; so
    // the guest reads once that try is over, as a socket round trip
    // shows (that ring's flush comes first in its pass).
    sync(&mut c);
    assert!(reader.read().is_empty(), "a part");
    // Others are served meanwhile.
    for i in 0..20 {
        good.write("x", &i.to_string());
    }
    settle(&mut c);
    // And then the loop sleeps without a timeout: no scan, no timer, will
    // ever look at the lazy rings.
    assert_eq!(d.sleeping(), -1);
    assert!(!silent.has_reply(), "never read");
    assert!(!reader.has_reply(), "nothing more written");
    // They were only waiting for a notification.
    silent.g.g.notify();
    reader.g.g.notify();
    assert_eq!(silent.replies(1)[0].req_id, 1);
    eventually("more of the reply", || reader.has_reply());
}

#[test]
fn the_scan_goes_round_every_ring_within_one_interval() {
    let interval = Duration::from_secs(1);
    let d = Daemon::start_with(|o, _| o.ring_scan = Some(interval));
    let mut c = d.client();
    // With dom0's, five batches of at most 32.
    let n = 128;
    let mut gs: Vec<LazyGuest> = (1..=n).map(|domid| LazyGuest::new(d.vm(&mut c, domid))).collect();
    sync(&mut c);
    let start = Instant::now();
    for (i, g) in gs.iter_mut().enumerate() {
        g.write(&request(
            MsgType::GetDomainPath,
            i as u32,
            format!("{}\0", i + 1).as_bytes(),
        ));
    }
    let mut when = vec![None; gs.len()];
    eventually("every ring examined", || {
        for (g, w) in gs.iter_mut().zip(&mut when) {
            if w.is_none() && g.has_reply() {
                *w = Some(start.elapsed());
            }
        }
        when.iter().all(Option::is_some)
    });
    let first = when.iter().flatten().min().unwrap();
    let last = when.iter().flatten().max().unwrap();
    // One batch per interval would take five.
    assert!(*last < interval + SLACK, "the last ring at {last:?}");
    // And not all at once: the batches are spread over the interval.
    assert!(*last - *first >= interval / 4, "from {first:?} to {last:?}");
    for (i, g) in gs.iter_mut().enumerate() {
        assert_eq!(g.replies(1)[0].req_id, i as u32);
    }
}

#[test]
fn the_loop_stays_nearly_idle_with_many_rings_and_the_scan_on() {
    let d = Daemon::start_with(|o, _| o.ring_scan = Some(Duration::from_millis(500)));
    let mut c = d.client();
    let mut gs: Vec<G> = (1..=200).map(|domid| d.vm(&mut c, domid)).collect();
    sync(&mut c);
    // 201 rings, 7 batches per half second: 14 wake-ups a second, each
    // looking at 32 rings. A loop that spun would use all of the second.
    let (before, woken) = (d.cpu_ticks(), d.sleeps());
    // sleep-ok: measures a rate (wake-ups and CPU per second), with room:
    // 14 wake-ups expected, 40 allowed (other tests' threads, sharing
    // locks, may add a few; a loaded machine lowers both).
    std::thread::sleep(Duration::from_secs(1));
    let used = d.cpu_ticks() - before;
    let woken = d.sleeps() - woken;
    assert!(used <= 10, "{used} ticks of CPU in a second");
    assert!(woken <= 40, "woken {woken} times in a second");
    // It was scanning.
    let mut lazy = LazyGuest::new(gs.pop().unwrap());
    lazy.write(&request(MsgType::GetDomainPath, 7, b"200\0"));
    assert_eq!(lazy.replies(1)[0].req_id, 7);
}

#[test]
fn the_scan_goes_on_for_domain_0_s_ring_which_is_never_released() {
    let d = Daemon::start_with(|o, _| o.ring_scan = Some(Duration::from_millis(20)));
    let mut c = d.client();
    let _g = d.vm(&mut c, 3);
    c.ok(MsgType::Release, 0, b"3\0");
    assert_eq!(c.error(MsgType::Release, 0, b"0\0"), "EINVAL");
    // The scan ticks with domain 0's ring alone: a request there that is
    // not notified is answered.
    let mut g0 = LazyGuest::new(G::new(d.hv.guest(0).unwrap()));
    for id in 1..=3 {
        g0.write(&request(MsgType::GetDomainPath, id, b"0\0"));
        assert_eq!(g0.replies(1)[0].req_id, id);
    }
    let mut g = LazyGuest::new(d.vm(&mut c, 4));
    g.write(&request(MsgType::GetDomainPath, 1, b"4\0"));
    assert_eq!(g.replies(1)[0].req_id, 1);
}

#[test]
fn an_overflow_of_the_event_channel_device_loses_nothing() {
    // No scan: only the overflow's handling can find what was dropped.
    let d = Daemon::start_with(|o, _| o.ring_scan = None);
    let mut c = d.client();
    let mut w = d.client();
    w.watch("@releaseDomain", "r");
    w.wait_events(1);
    let mut a = d.vm(&mut c, 3);
    let mut b = d.vm(&mut c, 4);
    let _dies = d.vm(&mut c, 5);
    sync(&mut c);
    d.hv.overflow(|| {
        a.g.send_request(MsgType::GetDomainPath, 1, 0, b"3\0", T).unwrap();
        b.g.send_request(MsgType::GetDomainPath, 2, 0, b"4\0", T).unwrap();
        d.hv.destroy_domain(5).unwrap();
    });
    assert_eq!(a.g.recv_message(T).unwrap().req_id, 1);
    assert_eq!(b.g.recv_message(T).unwrap().req_id, 2);
    w.wait_events(2);
    assert!(!introduced(&mut c, 5) && !d.hv.is_bound(5));
    // Every port was unmasked: notifications are heard again, and
    // VIRQ_DOM_EXC.
    assert_eq!(a.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    assert_eq!(b.ok(MsgType::GetDomainPath, b"4\0"), b"/local/domain/4\0");
    d.hv.destroy_domain(4).unwrap();
    w.wait_events(3);
    assert!(!introduced(&mut c, 4));
    // And the loop does not spin: it sleeps, with no timer.
    settle(&mut c);
    assert_eq!(d.sleeping(), -1, "after an overflow");
}

#[test]
fn a_device_that_keeps_failing_is_read_less_and_less_often() {
    let d = Daemon::start_with(|o, _| o.ring_scan = None);
    let mut c = d.client();
    let mut g = d.vm(&mut c, 3);
    sync(&mut c);
    // Every read fails, and the device stays ready, as one in error.
    d.hv.fail(Op::Pending, EIO);
    g.g.notify();
    // The loop sleeps until the next try, whose delay doubles from 10 ms
    // up to a second: it is seen asleep for more than half a second once
    // it reached 640 ms (a loop that spun would not sleep at all).
    eventually("a delay past 500 ms", || {
        let t = d.sleeping();
        assert!((0..=1000).contains(&t), "sleeps {t} ms");
        t > 500
    });
    // Guests are served all the same, at each retry.
    assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    d.hv.heal(Op::Pending);
    // At the next try the device is read again, and watched again: the
    // loop sleeps with no timer, and requests are answered at once, which
    // only the device can have woken it up for.
    eventually("no timer", || d.sleeping() == -1);
    for _ in 0..20 {
        assert_eq!(g.ok(MsgType::GetDomainPath, b"3\0"), b"/local/domain/3\0");
    }
    // The streak in the log: its start once, and its end with its length,
    // at least the 7 tries that took the delay to 640 ms.
    drop((c, g));
    let log = d.stop_with_log();
    let lines = |what: &str| log.lines().filter(|l| l.contains(what)).count();
    assert_eq!(lines("cannot read the pending event channels"), 1, "{log}");
    let n: u64 = log
        .split_once("the pending event channels can be read again, after ")
        .and_then(|(_, rest)| rest.split_once(" failures"))
        .map(|(n, _)| n.parse().unwrap())
        .unwrap_or_else(|| panic!("{log}"));
    assert!(n >= 7, "{log}");
}

#[test]
fn xsa_325_a_guest_that_breaks_the_protocol_is_ignored_until_it_dies() {
    // In both profiles.
    for profile in [Profile::Oxenstored, Profile::Native] {
        let d = Daemon::start_with(|o, _| o.config.profile = profile);
        let mut c = d.client();
        let mut w = d.client();
        w.watch("@releaseDomain", "rel");
        w.wait_events(1);
        let mut g = d.vm(&mut c, 5);
        let mut other = d.vm(&mut c, 6);
        g.watch("x", "t");
        let mut bad = Vec::new();
        xs_wire::write_header(&mut bad, MsgType::Write as u32, 1, 0, PAYLOAD_MAX as u32 + 1);
        g.g.ring().write(&bad).unwrap();
        g.g.notify();
        eventually("ignored", || g.field(Field::Error) == ERROR_PROTO);
        // XSA-420: it may notify as it likes, its port stays masked.
        let before = d.cpu_ticks();
        for _ in 0..10_000 {
            g.g.notify();
        }
        sync(&mut c);
        assert!(d.cpu_ticks() - before <= 20, "{} ticks", d.cpu_ticks() - before);
        // The others are served; it stays known, without its watch.
        assert_eq!(other.read("x"), Err("ENOENT".into()));
        assert!(introduced(&mut c, 5));
        let watches = String::from_utf8(c.ok(MsgType::Control, 0, b"watches\0")).unwrap();
        assert!(!watches.contains("D5"), "{watches}");
        // Its death is seen: @releaseDomain, its port unbound, its nodes gone.
        d.hv.destroy_domain(5).unwrap();
        w.wait_events(2);
        assert!(!introduced(&mut c, 5) && !d.hv.is_bound(5));
        assert_eq!(c.read(0, "/local/domain/5"), Err("ENOENT".into()));
    }
}

#[test]
fn xsa_425_connections_that_go_while_others_wait_in_the_same_pass() {
    // In both profiles.
    for profile in [Profile::Oxenstored, Profile::Native] {
        let d = Daemon::start_with(|o, _| o.config.profile = profile);
        let mut c = d.client();
        let mut g5 = d.vm(&mut c, 5);
        let mut g6 = d.vm(&mut c, 6);
        let ask = |g: &mut G, id: u32| {
            g.g.ring().write(&request(MsgType::GetDomainPath, id, b"5\0")).unwrap();
            g.g.notify();
        };
        // Requests of 5 and 6 waiting, and RELEASE of 6 from a socket.
        ask(&mut g5, 1);
        ask(&mut g6, 1);
        c.ok(MsgType::Release, 0, b"6\0");
        assert_eq!(g5.g.recv_message(T).unwrap().req_id, 1);
        assert!(!d.hv.is_bound(6) && !introduced(&mut c, 6));
        // A domain acting for domain 0 releases itself: no reply is written
        // to the page it no longer has.
        let mut g7 = d.vm(&mut c, 7);
        c.ok(MsgType::SetTarget, 0, b"7\x000\0");
        let prod = g7.field(Field::RspProd);
        g7.g.send_request(MsgType::Release, 9, 0, b"7\0", T).unwrap();
        eventually("released", || !d.hv.is_bound(7));
        sync(&mut c);
        assert_eq!(g7.field(Field::RspProd), prod);
        // A domain that dies with requests waiting.
        ask(&mut g5, 2);
        d.hv.destroy_domain(5).unwrap();
        eventually("dead", || !introduced(&mut c, 5));
        assert!(!d.hv.is_bound(5));
        assert_eq!(c.read(0, "/tool/xenstored").map(|v| v.is_empty()), Ok(false));
    }
}

#[test]
fn a_ring_whose_output_overflows_is_ignored_with_a_communication_error() {
    let d = Daemon::start_with(|o, _| o.config.output_hard_limit = 8192);
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    g.write("v", &"v".repeat(2000));
    // Ten reads at once, no reply read: more than the ring and the limit hold.
    let mut bytes = Vec::new();
    for i in 0..10 {
        bytes.extend(request(MsgType::Read, i, b"v\0"));
    }
    g.g.ring().write(&bytes).unwrap();
    g.g.notify();
    eventually("ignored", || g.field(Field::Error) == ERROR_COMM);
    assert!(introduced(&mut c, 5));
}

#[test]
fn a_guest_held_by_a_watcher_goes_on_when_the_watcher_reads() {
    // The watcher's reading lets the guest go during a flush: the guest
    // gets its turn without any further event from it.
    let d = Daemon::start_with(|o, _| {
        o.config.watch_event_max = 8;
        o.config.value_max = usize::MAX;
    });
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    c.write(0, "/v", &"v".repeat(4000));
    let mut w = d.client();
    w.watch("/local/domain/5/x", "w");
    w.wait_events(1);
    // The watcher asks for more than its socket holds, and reads nothing:
    // its events wait in the core, behind the replies.
    let mut reads = Vec::new();
    for i in 0..128 {
        Message::new(MsgType::Read, 10_000 + i, 0, b"/v\0".to_vec())
            .unwrap()
            .encode_into(&mut reads);
    }
    w.send_raw(&reads);
    // Its turns (64 requests each) came before the replies of the next two
    // passes: all 128 read, their replies wait.
    settle(&mut c);
    // 20 writes at once: 8 events wait, the 9th holds the guest.
    let mut bytes = Vec::new();
    for i in 0..20 {
        bytes.extend(request(MsgType::Write, i, b"x\0v"));
    }
    g.g.ring().write(&bytes).unwrap();
    g.g.notify();
    for i in 0..9 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
    settle(&mut c);
    assert!(g.g.recv_message(Duration::ZERO).is_err(), "held");
    // The watcher reads everything; the guest's other writes are done.
    for _ in 0..128 {
        w.reply();
    }
    w.wait_events(21);
    for i in 9..20 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
}

#[test]
fn a_guest_held_by_a_socket_goes_on_when_the_socket_goes_and_the_socket_is_never_dropped() {
    let d = Daemon::start_with(|o, _| {
        o.config.watch_event_max = 8;
        o.config.value_max = usize::MAX;
        (o.config.output_soft_limit, o.config.output_hard_limit) = (600_000, 600_000);
    });
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    c.write(0, "/v", &"v".repeat(4000));
    let mut w = d.client();
    w.watch("/local/domain/5/x", "w");
    w.wait_events(1);
    let reads = |n: u32| {
        let mut out = Vec::new();
        for i in 0..n {
            Message::new(MsgType::Read, 10_000 + i, 0, b"/v\0".to_vec())
                .unwrap()
                .encode_into(&mut out);
        }
        out
    };
    w.send_raw(&reads(128));
    settle(&mut c);
    let mut bytes = Vec::new();
    for i in 0..20 {
        bytes.extend(request(MsgType::Write, i, b"x\0v"));
    }
    g.g.ring().write(&bytes).unwrap();
    g.g.notify();
    for i in 0..9 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
    // More than the hard limit: a socket is domain 0, which is never given
    // up on for its output (as oxenstored); the guest stays held...
    w.send_raw(&reads(100));
    settle(&mut c);
    assert!(g.g.recv_message(Duration::ZERO).is_err(), "still held");
    // ... and goes on when the watcher goes.
    drop(w);
    for i in 9..20 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
}

#[test]
fn a_guest_held_by_a_guest_watcher_goes_on_when_the_watcher_reads() {
    // As above with a guest as the watcher, which notifies once when it
    // has read its full ring: the flush that follows lets the writer go,
    // and nothing else happens. (A socket's reads wake the loop up again
    // and again, which hides the loss above.)
    let d = Daemon::start_with(|o, _| o.config.watch_event_max = 8);
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    let mut w = d.vm(&mut c, 6);
    g.write("x", "");
    g.ok(MsgType::SetPerms, &p(&["x", "n5", "r6"]));
    w.watch("/local/domain/5/x", "w");
    w.wait_events(1);
    // 50 writes at once: the watcher's ring takes 29 events (36 bytes
    // each, the last in part), 8 more wait in the core, the next holds
    // the writer.
    let mut bytes = Vec::new();
    for i in 0..50 {
        bytes.extend(request(MsgType::Write, i, b"x\0v"));
    }
    g.g.ring().write(&bytes).unwrap();
    g.g.notify();
    for i in 0..38 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
    settle(&mut c);
    assert!(g.g.recv_message(Duration::ZERO).is_err(), "held");
    assert_eq!(
        w.field(Field::RspProd).wrapping_sub(w.field(Field::RspCons)) as usize,
        RING_SIZE,
        "full"
    );
    // The watcher empties its ring and notifies, once.
    let mut buf = [0u8; RING_SIZE];
    assert_eq!(w.g.ring().read(&mut buf).unwrap(), RING_SIZE);
    w.g.notify();
    for i in 38..50 {
        assert_eq!(g.g.recv_message(T).unwrap().req_id, i);
    }
}

/// XSA-206: a guest that one conflict paused, given a point back once per
/// `period`.
fn a_paused_guest(period: Duration) -> (Daemon, Client, G) {
    let d = Daemon::start_with(|o, _| {
        o.config.conflict_burst_limit = 1.0;
        o.config.conflict_max_history = period;
    });
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    g.write("x", "0");
    let t = c.start();
    c.read(t, "/local/domain/5/x").unwrap();
    c.write(t, "/y", "");
    g.write("x", "1");
    assert_eq!(c.end(t, true), Err("EAGAIN".into()));
    (d, c, g)
}

#[test]
fn a_guest_paused_for_conflicts_is_not_read_meanwhile() {
    // A period of an hour: its point does not come back during the test.
    let (_d, mut c, mut g) = a_paused_guest(Duration::from_secs(3600));
    g.send(MsgType::Read, b"x\0");
    settle(&mut c);
    assert_ne!(
        g.field(Field::ReqCons),
        g.field(Field::ReqProd),
        "not read while paused"
    );
    assert_eq!(g.field(Field::RspProd), g.field(Field::RspCons), "no reply");
    // Others are served.
    c.write(0, "/local/domain/5/x", "2");
}

#[test]
fn a_guest_paused_for_conflicts_is_served_again_with_nothing_else_happening() {
    // The loop wakes up to give it its point back a period (50 ms, the
    // default) later. That it is not read before is the test above's.
    let (_d, _c, mut g) = a_paused_guest(Duration::from_millis(50));
    let id = g.send(MsgType::Read, b"x\0");
    let m = g.reply();
    assert_eq!((m.req_id, &m.payload[..]), (id, &b"1"[..]));
}

/// What stderr is given besides the daemon log: in a buffer.
#[derive(Clone, Default)]
struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Buf {
    /// The lines, `rxenstored: [<date>|` taken off.
    fn lines(&self) -> Vec<String> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| {
                l.strip_prefix("rxenstored: [")
                    .and_then(|l| l.split_once('|'))
                    .map_or(l, |(_, rest)| rest)
                    .to_string()
            })
            .collect()
    }
}

/// Watch events dropped for a guest that does not read them are told in
/// the daemon log once when they start and once, with their count, when
/// the guest reads again: never one line per event.
#[test]
fn dropped_watch_events_are_logged_once_per_streak() {
    use xs_daemon::log::{Dest, Echo, Level, Logger, Output, Settings};
    let dir = std::env::temp_dir().join(format!("rxenstored-rings-drops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let daemon_log = dir.join("xenstored.log");
    let s = Settings {
        daemon: Some((
            Output {
                dest: Dest::File(daemon_log.clone()),
                nb_files: 2,
                nb_lines: 1000,
                nb_chars: -1,
            },
            Level::Warn,
        )),
        access: None,
        ident: "rxenstored".into(),
        syslog_socket: dir.join("no-syslog"),
        queue_lines: 1000,
        queue_bytes: 1 << 20,
    };
    let logger =
        Arc::new(Logger::start_with(&s, Echo::new(Duration::from_secs(600), 0, Box::new(Buf::default()))).unwrap());
    let l = logger.clone();
    let d = Daemon::launch(
        |o, _| o.config.watch_event_max = 2,
        Box::new(move |xen| {
            l.install();
            Ok(xen)
        }),
    )
    .unwrap();
    let mut c = d.client();
    let mut g = d.vm(&mut c, 5);
    g.write("x", "");
    g.watch("x", "w");
    g.wait_events(1);
    // The guest reads nothing while the toolstack writes: its ring fills,
    // then twice the limit waits in the core, and the rest is dropped.
    let writes = 60;
    for i in 0..writes {
        c.write(0, "/local/domain/5/x", &i.to_string());
    }
    settle(&mut c);
    // It reads: every event that was kept comes before this reply.
    assert_eq!(g.read("x").unwrap(), (writes - 1).to_string());
    settle(&mut c);
    drop(c);
    d.stop().unwrap();
    let Ok(logger) = Arc::try_unwrap(logger) else {
        panic!("the logger is still shared")
    };
    logger.stop();
    let text = std::fs::read_to_string(&daemon_log).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("watch events")).collect();
    let dropped = writes + 1 - g.events.len();
    assert!(dropped > 0, "{} events came", g.events.len());
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].ends_with("|connection] domain 5: dropping watch events: it has twice quota-maxwatchevents unsent"),
        "{text}"
    );
    assert!(
        lines[1].ends_with(&format!(
            "|connection] domain 5: {dropped} watch events dropped, no more now"
        )),
        "{text}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The start, the stop and the first domains' comings and goings go to
/// stderr whatever the daemon log's level; past the cap, the domains go
/// to the daemon log only, at their level.
#[test]
fn stderr_tells_the_start_the_stop_and_the_first_domains() {
    use xs_daemon::log::{self, Dest, Echo, Level, Logger, Output, Settings};
    let dir = std::env::temp_dir().join(format!("rxenstored-rings-echo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let daemon_log = dir.join("xenstored.log");
    let s = Settings {
        daemon: Some((
            Output {
                dest: Dest::File(daemon_log.clone()),
                nb_files: 2,
                nb_lines: 1000,
                nb_chars: -1,
            },
            Level::Warn,
        )),
        access: None,
        ident: "rxenstored".into(),
        syslog_socket: dir.join("no-syslog"),
        queue_lines: 1000,
        queue_bytes: 1 << 20,
    };
    let echoed = Buf::default();
    let logger =
        Arc::new(Logger::start_with(&s, Echo::new(Duration::from_secs(600), 3, Box::new(echoed.clone()))).unwrap());
    let l = logger.clone();
    // The loop's thread logs to it from the opening of the devices on.
    let d = Daemon::launch(
        |_, _| {},
        Box::new(move |xen| {
            l.install();
            Ok(xen)
        }),
    )
    .unwrap();
    let mut c = d.client();
    let _g4 = d.vm(&mut c, 4);
    let _g5 = d.vm(&mut c, 5);
    assert_eq!(c.ok(MsgType::Release, 0, b"4\0"), b"OK\0");
    // Past the cap.
    let _g6 = d.vm(&mut c, 6);
    d.hv.destroy_domain(5).unwrap();
    eventually("domain 5 gone", || !introduced(&mut c, 5));
    drop(c);
    d.stop().unwrap();
    let lines = echoed.lines();
    assert_eq!(lines.len(), 7, "{lines:#?}");
    assert_eq!(lines[0], format!(" info|xenstored] {}", log::STARTED));
    assert!(
        lines[1].starts_with(" info|domains] domain 0's ring mapped from the simulated hypervisor, event channel "),
        "{lines:#?}"
    );
    assert!(
        lines[2].starts_with(" info|xenstored] listening on ") && lines[2].ends_with("run/socket"),
        "{lines:#?}"
    );
    assert!(
        lines[3].starts_with(" info|domains] domain 4 introduced: ring at gfn "),
        "{lines:#?}"
    );
    assert!(
        lines[4].starts_with(" info|domains] domain 5 introduced: "),
        "{lines:#?}"
    );
    assert_eq!(
        lines[5..],
        [
            " info|domains] domain 4 released: connection closed",
            " info|xenstored] stopped by request"
        ]
    );
    let Ok(logger) = Arc::try_unwrap(logger) else {
        panic!("the logger is still shared")
    };
    logger.stop();
    // The daemon log shows its level: here only the line of every start.
    let text = std::fs::read_to_string(&daemon_log).unwrap();
    assert_eq!(text.lines().collect::<Vec<_>>(), [log::STARTED]);
    std::fs::remove_dir_all(&dir).unwrap();
}
