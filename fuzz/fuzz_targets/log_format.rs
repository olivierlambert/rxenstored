// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! xs-daemon's log formatting (`xs_daemon::log::format`): the access line
//! of any connection, transaction, operation and data; dates of any time;
//! the daemon-log prefix, the syslog header, line truncation.
//!
//! Asserts: no panic; `escape` writes printable ASCII only (0x20..=0x7e),
//! so no line can be split or forged by a path or value, and it is
//! reversible: unescaping gives the data back with NUL as a space
//! (`sanitize_data` then `String.escaped`); an access line is printable
//! ASCII and ends with the escaped data; a date is
//! `YYYYMMDDTHH:MM:SS.mmmZ` (a year of any width and sign); `truncate`
//! leaves a line of at most `nb_chars - 1` bytes alone and otherwise keeps
//! `max(nb_chars - 1, 2) - 2` bytes and appends `..`.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use xs_core::log::{Op, Who};
use xs_daemon::log::format::{
    access_line, daemon_prefix, date, escape, line, op_level, op_name, severity, syslog_header, truncate, Stamp,
};
use xs_daemon::log::Level;

#[derive(Arbitrary, Debug)]
enum AOp {
    Request(u32),
    Error,
    Event,
    NotFired,
    Start,
    End,
    Commit,
    Conflict,
    NewConn,
    EndConn,
    Print,
}

impl AOp {
    fn op(&self) -> Op {
        match *self {
            AOp::Request(t) => Op::Request(t),
            AOp::Error => Op::Error,
            AOp::Event => Op::Event,
            AOp::NotFired => Op::NotFired,
            AOp::Start => Op::Start,
            AOp::End => Op::End,
            AOp::Commit => Op::Commit,
            AOp::Conflict => Op::Conflict,
            AOp::NewConn => Op::NewConn,
            AOp::EndConn => Op::EndConn,
            AOp::Print => Op::Print,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    socket: bool,
    who: u64,
    tid: u32,
    op: AOp,
    data: Vec<u8>,
    secs: i64,
    nanos: u32,
    file: bool,
    nb_chars: i64,
    level: u8,
    key: String,
    pri: u8,
    local: i64,
}

fn printable(b: &[u8]) -> bool {
    b.iter().all(|c| (0x20..=0x7e).contains(c))
}

/// The inverse of `escape`, NUL having become a space.
fn unescape(e: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < e.len() {
        if e[i] != b'\\' {
            out.push(e[i]);
            i += 1;
            continue;
        }
        let c = *e.get(i + 1).expect("a lone backslash");
        match c {
            b'"' | b'\\' => out.push(c),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'b' => out.push(8),
            b'0'..=b'9' => {
                let d = &e[i + 1..i + 4];
                assert!(d.iter().all(u8::is_ascii_digit), "bad \\ddd: {d:?}");
                let v = (d[0] - b'0') as u32 * 100 + (d[1] - b'0') as u32 * 10 + (d[2] - b'0') as u32;
                out.push(u8::try_from(v).expect("\\ddd above 255"));
                i += 4;
                continue;
            }
            _ => panic!("unknown escape \\{}", c as char),
        }
        i += 2;
    }
    out
}

fn check_date(d: &[u8]) {
    // [-]Y+ MM DD T HH : MM : SS . mmm Z: the last 18 bytes are fixed.
    assert!(d.len() >= 19, "{:?}", String::from_utf8_lossy(d));
    let (y, rest) = d.split_at(d.len() - 18);
    let y = y.strip_prefix(b"-").unwrap_or(y);
    assert!(
        !y.is_empty() && y.iter().all(u8::is_ascii_digit),
        "year {:?}",
        String::from_utf8_lossy(d)
    );
    let shape = b"MMDDTHH:MM:SS.mmmZ";
    for (c, s) in rest.iter().zip(shape) {
        match s {
            b'T' | b':' | b'.' | b'Z' => assert_eq!(c, s, "{:?}", String::from_utf8_lossy(d)),
            _ => assert!(c.is_ascii_digit(), "{:?}", String::from_utf8_lossy(d)),
        }
    }
    let n = |a: usize| (rest[a] - b'0') as u32 * 10 + (rest[a + 1] - b'0') as u32;
    assert!((1..=12).contains(&n(0)) && (1..=31).contains(&n(2)));
    assert!(n(5) < 24 && n(8) < 60 && n(11) < 60);
}

fuzz_target!(|i: Input| {
    // escape
    let mut e = Vec::new();
    escape(&mut e, &i.data);
    assert!(printable(&e), "escape left a byte that is not printable");
    let back: Vec<u8> = i.data.iter().map(|c| if *c == 0 { b' ' } else { *c }).collect();
    assert_eq!(unescape(&e), back);

    // date
    let t = Stamp {
        secs: i.secs,
        nanos: i.nanos,
    };
    let mut d = Vec::new();
    date(&mut d, t);
    check_date(&d);

    // access line
    let who = if i.socket {
        Who::Socket(i.who)
    } else {
        Who::Domain(i.who as u32)
    };
    let op = i.op.op();
    let _ = (op_name(op), op_level(op));
    let mut l = Vec::new();
    access_line(&mut l, i.file.then_some(t), who, i.tid, op, &i.data);
    assert!(printable(&l), "access line not printable");
    assert!(l.ends_with(&e), "access line does not end with the escaped data");
    let mut l2 = Vec::new();
    line(&mut l2, i.file.then_some(t), "A1", "write    ", &i.data);
    assert!(printable(&l2));

    // truncate
    let before = l.clone();
    truncate(&mut l, i.nb_chars);
    if i.nb_chars > 0 && before.len() as i64 > i.nb_chars - 1 {
        let keep = (i.nb_chars - 1).max(2) as usize - 2;
        assert_eq!(l.len(), keep + 2);
        assert_eq!(&l[..keep], &before[..keep]);
        assert!(l.ends_with(b".."));
    } else {
        assert_eq!(l, before);
    }

    // daemon prefix, syslog header
    let level = [Level::Debug, Level::Info, Level::Warn, Level::Error, Level::Null][i.level as usize % 5];
    let _ = severity(level);
    let mut p = Vec::new();
    daemon_prefix(&mut p, i.file.then_some(t), level, &i.key);
    let mut s = Vec::new();
    syslog_header(&mut s, i.pri, i.local, &i.key);
    assert!(s.starts_with(b"<"));
});
