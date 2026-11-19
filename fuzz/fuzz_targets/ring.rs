// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! `xs_sys::ring`: the server's view of a ring page whose every byte, the
//! indices included, a hostile guest writes between the server's calls.
//!
//! The page is a memfd page mapped between two PROT_NONE guard pages, so
//! that any access past it faults (and the target is built with
//! AddressSanitizer for the heap side: the caller's buffers). Before each
//! call the harness takes a copy of the page and computes, from the
//! indices it holds, what the call must do; after it, the whole page must
//! be that copy with exactly the expected words and bytes changed:
//! - a queue whose `prod - cons` (mod 2^32) is above RING_SIZE is refused
//!   with `CorruptRing { cons, prod }` and nothing in the page changes,
//!   even for an empty buffer;
//! - otherwise a read moves `min(buf.len(), queued)` bytes, taken from the
//!   masked offsets of the queue, and advances `cons` by that much only;
//!   a write moves `min(len, RING_SIZE - queued)` bytes to the masked
//!   offsets and advances `prod` by that much only; never more than
//!   RING_SIZE in one call;
//! - `reconnect` fills both queues with 0xff, zeroes the four indices,
//!   sets `connection` to CONNECTED and touches nothing else.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::ptr::NonNull;
use xs_sys::fd::{memfd, Memfd};
use xs_sys::map::{Mapping, PAGE_SIZE};
use xs_sys::ring::{CorruptRing, Field, GuestRing, Ring, CONNECTED, RECONNECT, RING_SIZE};

/// Offsets of the words, as `xs_wire.h` lays them out.
fn offset(f: Field) -> usize {
    2 * RING_SIZE + 4 * f as usize
}

const FIELDS: [Field; 7] = Field::ALL;

struct Setup {
    _fd: Memfd,
    server: Ring,
    guest: GuestRing,
    /// The server's mapping (the guarded one): what the harness reads and pokes.
    page: *mut u8,
}

thread_local! {
    static SETUP: RefCell<Option<Setup>> = const { RefCell::new(None) };
}

fn setup() -> Setup {
    let fd = memfd("fuzz-ring", PAGE_SIZE as u64).expect("memfd");
    // SAFETY: a fresh anonymous reservation of three pages, then the memfd
    // page mapped over the middle one; the reservation is never unmapped
    // (the setup lives as long as the process), so the guards stay.
    let page = unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            3 * PAGE_SIZE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED);
        let mid = (base as *mut u8).add(PAGE_SIZE);
        let p = libc::mmap(
            mid.cast(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_FIXED,
            std::os::fd::AsRawFd::as_raw_fd(fd.file()),
            0,
        );
        assert_eq!(p, mid.cast());
        mid
    };
    // SAFETY: `page` is a live mapping of one page that only this Mapping unmaps.
    let map = unsafe { Mapping::from_raw(NonNull::new(page).expect("non-null"), PAGE_SIZE, None) };
    let server = Ring::new(map).expect("server ring");
    let guest = GuestRing::new(fd.map(0, PAGE_SIZE).expect("guest map")).expect("guest ring");
    Setup {
        _fd: fd,
        server,
        guest,
        page,
    }
}

fn snapshot(page: *mut u8) -> Vec<u8> {
    // SAFETY: `page` is a mapped page; volatile reads, byte by byte, no reference.
    (0..PAGE_SIZE).map(|i| unsafe { page.add(i).read_volatile() }).collect()
}

fn word(p: &[u8], f: Field) -> u32 {
    let o = offset(f);
    u32::from_le_bytes(p[o..o + 4].try_into().unwrap())
}

fn set_word(p: &mut [u8], f: Field, v: u32) {
    let o = offset(f);
    p[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Val {
    Raw(u32),
    /// The other index of the same queue, plus this.
    Near(i16),
    Wrap(u8),
}

#[derive(Arbitrary, Debug)]
enum Op {
    SetField(u8, Val),
    GuestWrite(Vec<u8>),
    /// `len` bytes made from a seed: writes longer than the input.
    GuestWriteLong(u16, u8),
    Poke(u16, Vec<u8>),
    ServerRead(u16),
    ServerWrite(Vec<u8>),
    ServerWriteLong(u16, u8),
    GuestRead(u16),
    Reconnect,
    GuestRequestReconnect,
    SetFeatures(u32),
    SetConnection(u32),
    SetError(u32),
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    /// Requests: guest produces, server consumes.
    Req,
    /// Replies: server produces, guest consumes.
    Rsp,
}

impl Side {
    fn data(self) -> usize {
        match self {
            Side::Req => 0,
            Side::Rsp => RING_SIZE,
        }
    }
    fn cons(self) -> Field {
        match self {
            Side::Req => Field::ReqCons,
            Side::Rsp => Field::RspCons,
        }
    }
    fn prod(self) -> Field {
        match self {
            Side::Req => Field::ReqProd,
            Side::Rsp => Field::RspProd,
        }
    }
}

fn long(len: u16, seed: u8) -> Vec<u8> {
    let len = len as usize % (2 * RING_SIZE + 9);
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// What a read of `len` bytes from `side` must return and leave in the page.
fn expect_read(before: &[u8], side: Side, len: usize) -> (Result<usize, CorruptRing>, Vec<u8>, Vec<u8>) {
    let (cons, prod) = (word(before, side.cons()), word(before, side.prod()));
    let queued = prod.wrapping_sub(cons);
    if queued > RING_SIZE as u32 {
        return (Err(CorruptRing { cons, prod }), before.to_vec(), Vec::new());
    }
    let n = len.min(queued as usize);
    let data: Vec<u8> = (0..n)
        .map(|i| before[side.data() + (cons.wrapping_add(i as u32) as usize % RING_SIZE)])
        .collect();
    let mut after = before.to_vec();
    if n > 0 {
        set_word(&mut after, side.cons(), cons.wrapping_add(n as u32));
    }
    (Ok(n), after, data)
}

fn expect_write(before: &[u8], side: Side, bytes: &[u8]) -> (Result<usize, CorruptRing>, Vec<u8>) {
    let (cons, prod) = (word(before, side.cons()), word(before, side.prod()));
    let queued = prod.wrapping_sub(cons);
    if queued > RING_SIZE as u32 {
        return (Err(CorruptRing { cons, prod }), before.to_vec());
    }
    let n = bytes.len().min(RING_SIZE - queued as usize);
    let mut after = before.to_vec();
    for (i, b) in bytes[..n].iter().enumerate() {
        after[side.data() + (prod.wrapping_add(i as u32) as usize % RING_SIZE)] = *b;
    }
    if n > 0 {
        set_word(&mut after, side.prod(), prod.wrapping_add(n as u32));
    }
    (Ok(n), after)
}

fn check_page(page: *mut u8, want: &[u8], what: &str) {
    let got = snapshot(page);
    if got != want {
        let diff: Vec<usize> = (0..PAGE_SIZE).filter(|i| got[*i] != want[*i]).take(16).collect();
        panic!("{what}: the page differs from the expected one at offsets {diff:?}");
    }
}

fn run(s: &mut Setup, ops: &[Op]) {
    // A fresh page.
    for i in 0..PAGE_SIZE {
        // SAFETY: inside the mapped page.
        unsafe { s.page.add(i).write_volatile(0) };
    }
    for op in ops {
        let before = snapshot(s.page);
        match op {
            Op::SetField(f, v) => {
                let f = FIELDS[*f as usize % FIELDS.len()];
                let other = match f {
                    Field::ReqCons => Field::ReqProd,
                    Field::ReqProd => Field::ReqCons,
                    Field::RspCons => Field::RspProd,
                    Field::RspProd => Field::RspCons,
                    x => x,
                };
                let v = match *v {
                    Val::Raw(v) => v,
                    Val::Near(d) => word(&before, other).wrapping_add(d as i32 as u32),
                    Val::Wrap(d) => u32::MAX.wrapping_sub(d as u32),
                };
                s.guest.set(f, v);
                let mut want = before.clone();
                set_word(&mut want, f, v);
                check_page(s.page, &want, "guest set");
                assert_eq!(s.guest.get(f), v);
            }
            Op::GuestWrite(bytes) => {
                let (r, want) = expect_write(&before, Side::Req, bytes);
                assert_eq!(s.guest.write(bytes), r, "guest write");
                check_page(s.page, &want, "guest write");
            }
            Op::GuestWriteLong(len, seed) => {
                let bytes = long(*len, *seed);
                let (r, want) = expect_write(&before, Side::Req, &bytes);
                assert_eq!(s.guest.write(&bytes), r, "guest write");
                check_page(s.page, &want, "guest write");
            }
            Op::Poke(off, bytes) => {
                let off = *off as usize % PAGE_SIZE;
                let mut want = before.clone();
                for (i, b) in bytes.iter().enumerate().take(PAGE_SIZE - off) {
                    // SAFETY: inside the mapped page.
                    unsafe { s.page.add(off + i).write_volatile(*b) };
                    want[off + i] = *b;
                }
                check_page(s.page, &want, "poke");
            }
            Op::ServerRead(len) => {
                let len = *len as usize % (2 * RING_SIZE + 9);
                let (r, want, data) = expect_read(&before, Side::Req, len);
                // A heap buffer of exactly `len` bytes: ASan sees a write past it.
                let mut buf = vec![0xa5u8; len];
                let got = s.server.read(&mut buf);
                assert_eq!(got, r, "server read of {len}");
                if let Ok(n) = got {
                    assert!(n <= RING_SIZE);
                    assert_eq!(&buf[..n], &data[..], "server read: bytes");
                    assert!(buf[n..].iter().all(|b| *b == 0xa5), "server read wrote past n");
                }
                check_page(s.page, &want, "server read");
            }
            Op::ServerWrite(bytes) => {
                let (r, want) = expect_write(&before, Side::Rsp, bytes);
                let got = s.server.write(bytes);
                assert_eq!(got, r, "server write");
                assert!(got.map_or(true, |n| n <= RING_SIZE));
                check_page(s.page, &want, "server write");
            }
            Op::ServerWriteLong(len, seed) => {
                let bytes = long(*len, *seed);
                let (r, want) = expect_write(&before, Side::Rsp, &bytes);
                let got = s.server.write(&bytes);
                assert_eq!(got, r, "server write");
                assert!(got.map_or(true, |n| n <= RING_SIZE));
                check_page(s.page, &want, "server write");
            }
            Op::GuestRead(len) => {
                let len = *len as usize % (2 * RING_SIZE + 9);
                let (r, want, data) = expect_read(&before, Side::Rsp, len);
                let mut buf = vec![0u8; len];
                let got = s.guest.read(&mut buf);
                assert_eq!(got, r, "guest read");
                if let Ok(n) = got {
                    assert_eq!(&buf[..n], &data[..]);
                }
                check_page(s.page, &want, "guest read");
            }
            Op::Reconnect => {
                s.server.reconnect();
                let mut want = before.clone();
                want[..2 * RING_SIZE].fill(0xff);
                for f in [Field::ReqCons, Field::ReqProd, Field::RspCons, Field::RspProd] {
                    set_word(&mut want, f, 0);
                }
                set_word(&mut want, Field::Connection, CONNECTED);
                check_page(s.page, &want, "reconnect");
                assert_eq!(s.server.connection(), CONNECTED);
            }
            Op::GuestRequestReconnect => {
                s.guest.request_reconnect();
                let mut want = before.clone();
                set_word(&mut want, Field::Connection, RECONNECT);
                check_page(s.page, &want, "request reconnect");
                assert_eq!(s.server.connection(), RECONNECT);
            }
            Op::SetFeatures(v) => {
                s.server.set_server_features(*v);
                let mut want = before.clone();
                set_word(&mut want, Field::ServerFeatures, *v);
                check_page(s.page, &want, "features");
                assert_eq!(s.server.server_features(), *v);
            }
            Op::SetConnection(v) => {
                s.server.set_connection(*v);
                let mut want = before.clone();
                set_word(&mut want, Field::Connection, *v);
                check_page(s.page, &want, "connection");
                assert_eq!(s.server.connection(), *v);
            }
            Op::SetError(v) => {
                s.server.set_error(*v);
                let mut want = before.clone();
                set_word(&mut want, Field::Error, *v);
                check_page(s.page, &want, "error");
                assert_eq!(s.server.error(), *v);
            }
        }
    }
}

fuzz_target!(|ops: Vec<Op>| {
    SETUP.with(|cell| {
        let mut cell = cell.borrow_mut();
        let s = cell.get_or_insert_with(setup);
        run(s, &ops);
    });
});
