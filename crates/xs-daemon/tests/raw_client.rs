// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The daemon over its socket, with a raw protocol client.

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

mod common;

use common::{Client, Daemon};
use std::process::Command;
use std::time::{Duration, Instant};
use xs_wire::{nul_terminated, write_header, Message, MsgType};

#[test]
fn store_operations_and_errors() {
    let d = Daemon::start();
    let mut c = d.client();
    assert_eq!(c.ls(0, "/"), ["@introduceDomain", "@releaseDomain", "local", "tool"]);
    // The daemon's own path, as oxenstored writes its own.
    let tool = c.read(0, "/tool/xenstored").unwrap();
    assert!(tool.starts_with('/') && tool.ends_with("/rxenstored"), "{tool}");
    c.write(0, "/a/b/c", "value");
    assert_eq!(c.read(0, "/a/b/c").unwrap(), "value");
    assert_eq!(c.ls(0, "/a"), ["b"]);
    c.ok(MsgType::Mkdir, 0, b"/a/m\0");
    assert_eq!(c.ls(0, "/a"), ["b", "m"]);
    c.ok(MsgType::SetPerms, 0, b"/a\0n0\0r5\0");
    assert_eq!(c.ok(MsgType::GetPerms, 0, b"/a\0"), b"n0\0r5\0");
    assert_eq!(c.ok(MsgType::Rm, 0, b"/a/nothing\0"), b"OK\0");
    assert_eq!(c.error(MsgType::Rm, 0, b"/a/nothing/below\0"), "ENOENT");
    c.ok(MsgType::Rm, 0, b"/a\0");
    assert_eq!(c.read(0, "/a/b/c"), Err("ENOENT".into()));
    assert_eq!(c.ok(MsgType::GetDomainPath, 0, b"12\0"), b"/local/domain/12\0");
    c.write(0, "relative/x", "1");
    assert_eq!(c.read(0, "/local/domain/0/relative/x").unwrap(), "1");
    assert_eq!(c.error(MsgType::Read, 0, b"/bad path\0"), "EINVAL");
    assert_eq!(
        c.error(MsgType::Write, 0, &[&b"/big\0"[..], &[b'x'; 2049]].concat()),
        "E2BIG"
    );
    // Too few fields (`ox/process.ml:585-610`).
    assert_eq!(c.error(MsgType::Introduce, 0, b"1\0"), "EINVAL");
    assert_eq!(c.error(MsgType::Read, 77, b"/\0"), "EIO");
    let mut raw = Vec::new();
    write_header(&mut raw, 9999, 5, 0, 0);
    c.send_raw(&raw);
    let r = c.next().unwrap();
    assert_eq!(
        (r.ty, r.req_id, r.payload.as_slice()),
        (MsgType::Error as u32, 5, &b"ENOSYS\0"[..])
    );
}

#[test]
fn watches_across_connections() {
    let d = Daemon::start();
    let (mut a, mut b) = (d.client(), d.client());
    a.watch("/w", "abs");
    a.watch("rel", "relative");
    a.wait_events(2);
    assert_eq!(
        a.events,
        [("/w".into(), "abs".into()), ("rel".into(), "relative".into())]
    );
    a.events.clear();
    b.write(0, "/w/x", "1");
    b.write(0, "rel/y", "1");
    b.ok(MsgType::Rm, 0, b"/w\0");
    a.wait_events(3);
    assert_eq!(
        a.events,
        [
            ("/w/x".into(), "abs".into()),
            ("rel/y".into(), "relative".into()),
            ("/w".into(), "abs".into())
        ]
    );
    assert_eq!(
        b.error(MsgType::Unwatch, 0, b"/w\0abs\0"),
        "ENOENT",
        "watches are per connection"
    );
    a.ok(MsgType::Unwatch, 0, b"/w\0abs\0");
    b.write(0, "/w", "again");
    b.write(0, "rel", "again");
    a.wait_events(4);
    assert_eq!(a.events[3], ("rel".into(), "relative".into()));
}

#[test]
fn transactions_and_conflicts() {
    let d = Daemon::start();
    let (mut a, mut b) = (d.client(), d.client());
    a.write(0, "/t/v", "0");
    let tx = a.start();
    assert_eq!(a.read(tx, "/t/v").unwrap(), "0");
    a.write(tx, "/t/v", "1");
    assert_eq!(b.read(0, "/t/v").unwrap(), "0");
    b.write(0, "/t/v", "outside");
    assert_eq!(a.end(tx, true), Err("EAGAIN".into()));
    assert_eq!(b.read(0, "/t/v").unwrap(), "outside");
    // Disjoint transactions on two connections both commit.
    let (ta, tb) = (a.start(), b.start());
    a.write(ta, "/t/a", "a");
    b.write(tb, "/t/b", "b");
    a.end(ta, true).unwrap();
    b.end(tb, true).unwrap();
    assert_eq!(a.ls(0, "/t"), ["a", "b", "v"]);
}

#[test]
fn partial_and_pipelined_requests() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut other = d.client();
    // One request, one byte at a time, each read alone: the daemon reads
    // what is there before it answers a request that came after.
    let mut bytes = Vec::new();
    Message::new(MsgType::Write, 1, 0, b"/slow\0drip".to_vec())
        .unwrap()
        .encode_into(&mut bytes);
    for b in &bytes {
        c.send_raw(std::slice::from_ref(b));
        other.ok(MsgType::GetDomainPath, 0, b"0\0");
    }
    assert_eq!(c.reply().payload, b"OK\0");
    // A thousand requests in one write; replies come back in order.
    let mut burst = Vec::new();
    for i in 0..1000u32 {
        Message::new(MsgType::Write, 1000 + i, 0, format!("/burst/{i}\0{i}").into_bytes())
            .unwrap()
            .encode_into(&mut burst);
    }
    c.send_raw(&burst);
    for i in 0..1000u32 {
        let r = c.reply();
        assert_eq!((r.req_id, r.payload.as_slice()), (1000 + i, &b"OK\0"[..]));
    }
    assert_eq!(c.ls(0, "/burst").len(), 1000);
    assert_eq!(c.read(0, "/slow").unwrap(), "drip");
}

#[test]
fn large_directory_reply() {
    let d = Daemon::start();
    let mut c = d.client();
    for i in 0..500 {
        c.write(0, &format!("/many/entry-{i:04}"), "");
    }
    let r = c.call(MsgType::Directory, 0, b"/many\0");
    assert!(r.payload.len() > 4096, "socket replies are not limited");
    assert_eq!(r.payload.split(|b| *b == 0).filter(|s| !s.is_empty()).count(), 500);
}

#[test]
fn disconnect_drops_watches_and_transactions() {
    let mut d = Daemon::start();
    let mut b = d.client();
    for _ in 0..20 {
        let mut a = d.client();
        a.watch("/gone", "t");
        let tx = a.start();
        a.write(tx, "/gone/never", "1");
        // Leave unread events and an open transaction behind.
        b.write(0, "/gone", "x");
        drop(a);
    }
    b.write(0, "/gone", "y");
    assert_eq!(b.read(0, "/gone/never"), Err("ENOENT".into()));
    assert!(d.alive());
    // The watches are gone: a new connection may register the same one,
    // and writes do not try to reach the old connections.
    let mut c = d.client();
    c.watch("/gone", "t");
    c.wait_events(1);
    b.write(0, "/gone", "z");
    c.wait_events(2);
}

/// A client that can no longer be written to is closed when a write
/// fails. The test above reaches that failure only when the daemon writes
/// after the client went (it may also see the end of the stream first):
/// here the client stops reading (shutdown(2)) before it asks, so the
/// reply's write fails (EPIPE) whatever the timing.
#[test]
fn a_client_that_cannot_be_written_to_is_closed() {
    let d = Daemon::start();
    let mut a = d.client();
    a.watch("/w", "a");
    a.wait_events(1);
    let mut b = d.client();
    b.watch("/w", "b");
    b.wait_events(1);
    a.stream.shutdown(std::net::Shutdown::Read).unwrap();
    let mut req = Vec::new();
    Message::new(MsgType::Write, 1, 0, b"/x\0v".to_vec())
        .unwrap()
        .encode_into(&mut req);
    a.send_raw(&req);
    // Its request came first: its turn came in the pass that answers this
    // one, or before (in any order with this one's turn: epoll does not
    // say which of two ready sockets it reports first), and its reply's
    // write failed at the end of that pass. So by the next reply, its
    // request is done and its connection closed.
    b.ok(MsgType::GetDomainPath, 0, b"0\0");
    assert_eq!(b.read(0, "/x").unwrap(), "v");
    let watches = String::from_utf8(b.ok(MsgType::Control, 0, b"watches\0")).unwrap();
    assert!(!watches.contains(" a\n") && watches.contains(" b\n"), "{watches}");
}

#[test]
fn thousands_of_connections() {
    xs_sys::raise_fd_limit().unwrap();
    let d = Daemon::start();
    let mut clients: Vec<Client> = (0..3000).map(|_| d.client()).collect();
    let mut probe = d.client();
    probe.watch("/conns", "w");
    probe.wait_events(1);
    // Every client sends before any reads.
    for (i, c) in clients.iter_mut().enumerate() {
        let mut m = Vec::new();
        Message::new(MsgType::Write, i as u32, 0, format!("/conns/{i}\0").into_bytes())
            .unwrap()
            .encode_into(&mut m);
        c.send_raw(&m);
    }
    for (i, c) in clients.iter_mut().enumerate() {
        let r = c.reply();
        assert_eq!((r.req_id, r.payload.as_slice()), (i as u32, &b"OK\0"[..]));
    }
    probe.wait_events(3001);
    assert_eq!(probe.ls(0, "/conns").len(), 3000);
}

#[test]
fn a_reader_that_does_not_read_does_not_stall_others() {
    let d = Daemon::start();
    let mut slow = d.client();
    slow.watch("/flood", "t");
    let mut w = d.client();
    let start = Instant::now();
    let n = 20_000;
    let mut batch = Vec::new();
    for i in 0..n {
        Message::new(
            MsgType::Write,
            i,
            0,
            b"/flood/some-longer-node-name-for-volume\0x".to_vec(),
        )
        .unwrap()
        .encode_into(&mut batch);
        if i % 500 == 499 {
            w.send_raw(&batch);
            batch.clear();
            for _ in 0..500 {
                assert_eq!(w.reply().payload, b"OK\0");
            }
        }
    }
    assert!(start.elapsed() < Duration::from_secs(30));
    // Far more than a socket buffer is queued for the slow reader; it is all delivered.
    slow.wait_events(1 + n as usize);
    assert!(slow
        .events
        .iter()
        .skip(1)
        .all(|e| e.0 == "/flood/some-longer-node-name-for-volume"));
}

#[test]
fn a_client_that_does_not_read_its_replies_is_held_back_then_served() {
    let d = Daemon::start();
    let mut c = d.client();
    for i in 0..500 {
        c.write(0, &format!("/many/entry-{i:04}"), "");
    }
    // 300 replies of 7.5 KB: twice the megabyte of unsent output above
    // which a connection's requests wait. Nothing is read meanwhile.
    let ask = |c: &mut Client, ids: std::ops::Range<u32>| {
        let mut burst = Vec::new();
        for i in ids {
            Message::new(MsgType::Directory, i, 0, b"/many\0".to_vec())
                .unwrap()
                .encode_into(&mut burst);
        }
        c.send_raw(&burst);
    };
    ask(&mut c, 1000..1300);
    // Others are served while it is held back. It gets a turn (64
    // requests) in each pass until it is: by the end of the fifth pass
    // after its requests came, 320 requests' worth, and the other's fifth
    // reply comes after that.
    let mut other = d.client();
    for i in 1..=5 {
        other.write(0, "/other", &i.to_string());
    }
    // More requests arrive while it is held back.
    ask(&mut c, 1300..1320);
    other.write(0, "/other", "6");
    // It reads: everything is answered, in order.
    for i in 1000..1320 {
        let r = c.reply();
        assert_eq!(r.req_id, i);
        assert_eq!(r.payload.len(), 500 * 11);
    }
    assert_eq!(c.read(0, "/other").unwrap(), "6");
}

#[test]
fn input_larger_than_one_read_is_handled_without_a_new_event() {
    let d = Daemon::start();
    let mut c = d.client();
    // 400 KB of requests of 2 KB each: several full reads, each holding
    // fewer requests than a turn may handle.
    let value = "v".repeat(2000);
    let mut burst = Vec::new();
    for i in 0..200u32 {
        Message::new(MsgType::Write, i, 0, format!("/bulk/{i}\0{value}").into_bytes())
            .unwrap()
            .encode_into(&mut burst);
    }
    c.send_raw(&burst);
    for i in 0..200u32 {
        let r = c.reply();
        assert_eq!((r.req_id, r.payload.as_slice()), (i, &b"OK\0"[..]));
    }
    assert_eq!(c.read(0, "/bulk/199").unwrap(), value);
}

/// Exactly two reads' worth (2 x 64 KiB) waiting, at once: a read that
/// fills the buffer leaves the connection readable without a new event
/// (edge-triggered, none comes), and the read after the last full one
/// finds the socket empty (EAGAIN), which is no end of the connection.
#[test]
fn input_of_exactly_two_reads_then_nothing() {
    let d = Daemon::start();
    let mut c = d.client();
    let mut burst = Vec::new();
    for i in 0..64u32 {
        // 16 + 2032 bytes each (a value of at most 2048 bytes: the quota).
        let payload = format!("/r{i:02}\0{}", "v".repeat(2032 - 5));
        Message::new(MsgType::Write, i, 0, payload.into_bytes())
            .unwrap()
            .encode_into(&mut burst);
    }
    assert_eq!(burst.len(), 128 << 10);
    // All of it in the socket before the daemon looks: stopped meanwhile
    // (the kernel may queue a large write in two parts).
    let signal = |s| {
        // SAFETY: plain call; the pid is the daemon's, a child not reaped.
        assert_eq!(unsafe { libc::kill(d.pid() as libc::pid_t, s) }, 0);
    };
    signal(libc::SIGSTOP);
    // Stopped once /proc says so (the signal is acted on asynchronously).
    let stat = format!("/proc/{}/stat", d.pid());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !std::fs::read_to_string(&stat)
        .unwrap()
        .rsplit_once(')')
        .is_some_and(|(_, s)| s.trim_start().starts_with('T'))
    {
        assert!(std::time::Instant::now() < deadline, "the daemon did not stop");
        std::thread::yield_now();
    }
    c.send_raw(&burst);
    signal(libc::SIGCONT);
    // Before this client reads a reply (which would wake the daemon): the
    // daemon took all of it, without a new event, before it slept.
    asleep_in_epoll(d.pid());
    let value = d.client().read(0, "/r63").unwrap();
    assert_eq!(value.len(), 2032 - 5);
    for i in 0..64u32 {
        let r = c.reply();
        assert_eq!((r.req_id, r.payload.as_slice()), (i, &b"OK\0"[..]));
    }
    // Once the daemon has read again (and found nothing), the connection
    // still serves.
    asleep_in_epoll(d.pid());
    c.write(0, "/after", "1");
    assert_eq!(c.read(0, "/after").unwrap(), "1");
}

/// A client that closes with a reply unread: Linux gives the daemon's next
/// read ECONNRESET (not 0), and the connection is closed all the same.
#[test]
fn a_client_gone_with_replies_unread_is_closed() {
    let d = Daemon::start();
    let mut c = d.client();
    c.write(0, "/x", "1");
    let before = d.fds();
    let mut gone = d.client();
    let mut m = Vec::new();
    Message::new(MsgType::Read, 1, 0, b"/x\0".to_vec())
        .unwrap()
        .encode_into(&mut m);
    gone.send_raw(&m);
    // The reply is in its socket once the daemon slept again.
    asleep_in_epoll(d.pid());
    assert_eq!(d.fds(), before + 1);
    drop(gone);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while d.fds() != before {
        assert!(std::time::Instant::now() < deadline, "the connection was not closed");
        std::thread::yield_now();
    }
    assert_eq!(c.read(0, "/x").unwrap(), "1");
}

/// Waits until the main thread of process `pid` sleeps in an epoll wait
/// (`/proc` shows the system call a sleeping thread is in); panics after
/// 30 s, a guard against hanging, not a time the test depends on.
fn asleep_in_epoll(pid: u32) {
    let task = format!("/proc/{pid}/task/{pid}");
    let waits = [libc::SYS_epoll_wait, libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let syscall = std::fs::read_to_string(format!("{task}/syscall")).unwrap_or_default();
        let stat = std::fs::read_to_string(format!("{task}/stat")).unwrap_or_default();
        let nr = syscall.split_whitespace().next().and_then(|n| n.parse::<i64>().ok());
        let sleeping = stat
            .rsplit_once(')')
            .is_some_and(|(_, s)| s.trim_start().starts_with('S'));
        if sleeping && nr.is_some_and(|n| waits.contains(&n)) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{task}: {syscall} {stat}");
        std::thread::yield_now();
    }
}

#[test]
fn out_of_descriptors_the_daemon_serves_who_is_connected_and_accepts_again_later() {
    // 24 files for the daemon: its own (eight, plus whatever it inherits)
    // and at most 16 clients. A hard limit of 25, for the soft one to be
    // raised later (the daemon raises it to the hard one at its start).
    let mut d = Daemon::start_limited(Some(25));
    let nofile = |soft: u32| {
        let status = Command::new("prlimit")
            .arg(format!("--pid={}", d.pid()))
            .arg(format!("--nofile={soft}:25"))
            .status()
            .unwrap();
        assert!(status.success());
    };
    nofile(24);
    let request = |id: u32, path: &str| {
        let mut m = Vec::new();
        Message::new(MsgType::Write, id, 0, format!("{path}\x001").into_bytes())
            .unwrap()
            .encode_into(&mut m);
        m
    };
    // A client that connects when the daemon has no descriptor left: the
    // kernel queues its connection, the daemon cannot accept it. It tried
    // in the pass that answered the next request (its listener was ready
    // before that request came); had it accepted it, it would have read
    // its request by the end of the pass after, before the third reply.
    let wait = |clients: &mut Vec<Client>, i: usize| {
        let mut late = d.client();
        late.send_raw(&request(77, &format!("/fd/late{i}")));
        clients[0].write(0, &format!("/fd/sync{i}"), "1");
        clients[0].write(0, &format!("/fd/sync{i}"), "2");
        assert_eq!(
            clients[0].read(0, &format!("/fd/late{i}")),
            Err("ENOENT".into()),
            "the one that waits is not served"
        );
        late
    };
    // Clients connect while the daemon has a descriptor free: each is
    // accepted and served. Its count is exact after a reply: the
    // connection with which `Daemon::start` saw it listen, closed before
    // the request, is gone.
    let mut clients: Vec<Client> = Vec::new();
    loop {
        let mut c = d.client();
        c.send_raw(&request(77, &format!("/fd/{}", clients.len())));
        let r = c.reply();
        assert_eq!((r.req_id, r.payload.as_slice()), (77, &b"OK\0"[..]));
        clients.push(c);
        let fds = d.fds();
        assert!(fds <= 24, "the limit did not apply: {fds}");
        if fds == 24 {
            break;
        }
    }
    let n = clients.len();
    assert!(n >= 2, "{n} clients");
    // The limit is raised: no connection closed, the listener's retry
    // accepts the one that waited.
    let mut late = wait(&mut clients, 0);
    // Meanwhile the event loop sleeps: the listener, ready while the
    // connection waits, rests out of the epoll set instead of waking the
    // loop at once, pass after pass.
    asleep_in_epoll(d.pid());
    nofile(25);
    let r = late.reply();
    assert_eq!((r.req_id, r.payload.as_slice()), (77, &b"OK\0"[..]));
    assert_eq!(d.fds(), 25);
    // A client leaves: the one that waited is accepted at once.
    let mut late = wait(&mut clients, 1);
    clients.truncate(n - 1);
    let r = late.reply();
    assert_eq!((r.req_id, r.payload.as_slice()), (77, &b"OK\0"[..]));
    assert_eq!(clients[0].read(0, "/fd/late1").unwrap(), "1");
    assert!(d.alive());
    // Meanwhile the listener rested: accept(2) failed, and that was logged
    // once per streak of failures, not at every pass of a loop spinning on
    // a listener that stays ready while a connection waits. A streak
    // starts when the limit is reached: the accept that follows the one
    // that took the last descriptor fails, connection waiting or not
    // (Linux takes the descriptor first). Three: the last of the first
    // clients, the first one that waited, the second.
    assert_eq!(d.stop("TERM"), Some(0));
    let log = d.daemon_log();
    let accepts: Vec<&str> = log.lines().filter(|l| l.contains("|xenstored] accept: ")).collect();
    assert_eq!(accepts.len(), 3, "{log}");
    assert!(
        accepts
            .iter()
            .all(|l| l.contains("|error|") && l.ends_with("Too many open files (os error 24)")),
        "{log}"
    );
}

#[test]
fn oversized_request_closes_only_that_connection() {
    let mut d = Daemon::start();
    let mut bad = d.client();
    let mut raw = Vec::new();
    write_header(&mut raw, MsgType::Write as u32, 1, 0, 5000);
    raw.extend_from_slice(&[b'x'; 5000]);
    bad.send_raw(&raw);
    assert!(bad.next().is_none(), "closed by the daemon");
    let mut good = d.client();
    good.write(0, "/still", "here");
    assert!(d.alive());
}

#[test]
fn reset_watches_over_the_socket() {
    let d = Daemon::start();
    let mut a = d.client();
    a.watch("/r", "t");
    let tx = a.start();
    assert_eq!(a.ok(MsgType::ResetWatches, 0, b""), b"OK\0");
    assert_eq!(a.error(MsgType::Read, tx, b"/\0"), "EIO");
    assert_eq!(a.error(MsgType::Unwatch, 0, &nul_terminated(&[b"/r", b"t"])), "ENOENT");
}

#[test]
fn sigterm_and_sigint_stop_the_daemon_cleanly() {
    for signal in ["TERM", "INT"] {
        let mut d = Daemon::start();
        let mut c = d.client();
        c.write(0, "/x", "1");
        assert_eq!(d.stop(signal), Some(0), "SIG{signal}");
        // Its clients see their connection closed.
        assert!(c.next().is_none());
    }
}

#[test]
fn command_line() {
    let bin = env!("CARGO_BIN_EXE_rxenstored");
    let out = Command::new(bin)
        .args(["--compat=oxenstored", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--socket"));
    let out = Command::new(bin)
        .args(["--compat=oxenstored", "--nope"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin)
        .args([
            "--compat=oxenstored",
            "--no-domain-init",
            "--socket",
            "/proc/no/such/dir/socket",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/proc/no/such/dir/socket"));
}
