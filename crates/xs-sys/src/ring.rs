// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The xenstore ring of a shared page.
//!
//! Layout: `struct xenstore_domain_interface` of
//! `xen/include/public/io/xs_wire.h`; protocol: `docs/misc/xenstore-ring.txt`.
//! Two queues of `RING_SIZE` bytes, requests (guest to server) then
//! replies (server to guest), each with a consumer and a producer index
//! that run free modulo 2^32, then three words of signalling.
//!
//! The peer is untrusted and runs concurrently with us. Each shared word
//! is read once per operation, indices are checked before they are used,
//! data is copied at masked offsets, and full fences order the indices
//! with the data, as `xen_mb()` does in both C and OCaml xenstored.
//! Neither side notifies here: the daemon signals the event channel after
//! every operation that moved bytes.
//!
//! Every access to the page is atomic: a word is an `AtomicU32`, a queue
//! byte an `AtomicU8`, all with relaxed ordering (the fences order them).
//! The peer may write any byte at any time (only a hostile one writes the
//! bytes we are reading); in Rust's memory model a non-atomic access,
//! volatile or not, that races with a write is undefined behaviour, an
//! atomic one is not, and on x86-64 and aarch64 a relaxed atomic load or
//! store of a byte or an aligned word is the same plain instruction.
//! The only references made into the page are these short-lived
//! `&AtomicU32` and `&AtomicU8`, which allow mutation by others.
//!
//! `Ring` is the server's view, `GuestRing` the guest's (tests and
//! `xs-sim`); each owns its own mapping, so the two can run on two threads.

use crate::map::{Mapping, PAGE_SIZE};
use std::fmt;
use std::io;
use std::sync::atomic::{fence, AtomicU32, AtomicU8, Ordering};

/// Bytes in each of the two queues.
pub const RING_SIZE: usize = 1024;

/// `server_features` bits.
pub const FEATURE_RECONNECTION: u32 = 1;
pub const FEATURE_ERROR: u32 = 2;

/// `connection` values.
pub const CONNECTED: u32 = 0;
pub const RECONNECT: u32 = 1;

/// `error` values.
pub const ERROR_NONE: u32 = 0;
pub const ERROR_COMM: u32 = 1;
pub const ERROR_RINGIDX: u32 = 2;
pub const ERROR_PROTO: u32 = 3;

/// The words after the two queues, in page order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ReqCons,
    ReqProd,
    RspCons,
    RspProd,
    ServerFeatures,
    Connection,
    Error,
}

impl Field {
    pub const ALL: [Field; 7] = [
        Field::ReqCons,
        Field::ReqProd,
        Field::RspCons,
        Field::RspProd,
        Field::ServerFeatures,
        Field::Connection,
        Field::Error,
    ];

    /// Byte offset in a page whose queues hold `N` bytes each: after the
    /// two queues, 4-aligned (`N` is a multiple of 4, `Page::VALID`), and
    /// the last word ends at `2 * N + 28` (2076 for `RING_SIZE`).
    fn offset<const N: usize>(self) -> usize {
        2 * N + 4 * self as usize
    }
}

/// The indices of a queue do not describe at most `RING_SIZE` bytes: the
/// peer is buggy or hostile. The connection is to be dropped, with error
/// `ERROR_RINGIDX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorruptRing {
    pub cons: u32,
    pub prod: u32,
}

impl fmt::Display for CorruptRing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "corrupt ring: consumer index {:#x}, producer index {:#x}",
            self.cons, self.prod
        )
    }
}

impl std::error::Error for CorruptRing {}

impl From<CorruptRing> for io::Error {
    fn from(e: CorruptRing) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Where one queue's bytes and indices are.
#[derive(Clone, Copy)]
struct Queue {
    data: usize,
    cons: Field,
    prod: Field,
}

/// The algorithm, common to both views, for queues of `N` bytes each:
/// `RING_SIZE` on a real page; the proofs (`ring_proofs.rs`) also take
/// smaller ones.
struct Page<const N: usize> {
    map: Mapping,
}

impl<const N: usize> Page<N> {
    /// The queue sizes the layout allows, checked when the code is built:
    /// a power of two (an index is masked), at least 4 (the words after
    /// the queues are then 4-aligned), and the two queues and the seven
    /// words within a page (so `N` fits in a `u32` too).
    const VALID: () = {
        assert!(N.is_power_of_two() && N >= 4 && N <= (PAGE_SIZE - 28) / 2);
    };

    const MASK: u32 = N as u32 - 1;

    const REQUESTS: Queue = Queue {
        data: 0,
        cons: Field::ReqCons,
        prod: Field::ReqProd,
    };
    const REPLIES: Queue = Queue {
        data: N,
        cons: Field::RspCons,
        prod: Field::RspProd,
    };

    fn new(map: Mapping) -> io::Result<Page<N>> {
        let () = Self::VALID;
        if map.len() < PAGE_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a ring needs a whole page"));
        }
        // The words are accessed as `AtomicU32`, which must be aligned: a
        // page boundary aligns them all. Every mapping starts on one; a
        // pointer handed to `Mapping::from_raw` might not.
        if !map.as_ptr().cast::<u8>().addr().is_multiple_of(PAGE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a ring page must start on a page boundary",
            ));
        }
        Ok(Page { map })
    }

    /// The word `f`. The peer may write it at any time: an atomic load
    /// reads it exactly once and whole.
    fn word(&self, f: Field) -> &AtomicU32 {
        // SAFETY: `f.offset::<N>() + 4 <= 2 * N + 28 <= PAGE_SIZE <=
        // map.len()` (`VALID`, `new`), so the word is inside the mapping,
        // which lives as long as `self`; it is 4-aligned (`new` checks the
        // page is aligned, and the offset is a multiple of 4 as `N` is).
        // This module accesses it only as an `AtomicU32` (the queues,
        // `queue`, end where the words start).
        unsafe { AtomicU32::from_ptr(self.map.as_ptr().add(f.offset::<N>()).cast()) }
    }

    /// The bytes of the queue `q` from index `at` (masked) to its end, then
    /// those from its start: the order in which the queue's bytes follow
    /// one another from `at`. The callers iterate over the two by
    /// reference: by value (`array::IntoIter`) the same loop costs the
    /// Kani proofs ten times the memory (scripts/kani.sh).
    fn queue(&self, q: Queue, at: u32) -> [&[AtomicU8]; 2] {
        // SAFETY: `q` is this page's `REQUESTS` or `REPLIES` (the only
        // queues the module gives a `Page<N>`), so `q.data + N <= 2 * N <
        // PAGE_SIZE <= map.len()` (`VALID`, `new`): the queue is inside the
        // mapping, which lives as long as `self`. An `AtomicU8` has the size
        // and alignment of a `u8`, and this module accesses the queues only
        // as `AtomicU8`.
        let all: &[AtomicU8] = unsafe { std::slice::from_raw_parts(self.map.as_ptr().add(q.data).cast(), N) };
        // `at & MASK < N`: the split always succeeds.
        let (before, from) = all.split_at_checked((at & Self::MASK) as usize).unwrap_or_default();
        [from, before]
    }

    fn get(&self, f: Field) -> u32 {
        self.word(f).load(Ordering::Relaxed)
    }

    fn set(&mut self, f: Field, v: u32) {
        self.word(f).store(v, Ordering::Relaxed);
    }

    /// Moves up to `buf.len()` bytes out of `q`.
    fn read(&mut self, q: Queue, buf: &mut [u8]) -> Result<usize, CorruptRing> {
        let cons = self.get(q.cons);
        let prod = self.get(q.prod);
        // No byte may be read before the producer index that covers it.
        fence(Ordering::SeqCst);
        let queued = prod.wrapping_sub(cons);
        if queued > N as u32 {
            return Err(CorruptRing { cons, prod });
        }
        let n = buf.len().min(queued as usize);
        if n == 0 {
            return Ok(0);
        }
        // The peer may be writing these bytes (only a hostile one would):
        // each is read once, and nothing is assumed of its value.
        let mut to = buf.iter_mut().take(n);
        for part in &self.queue(q, cons) {
            for (shared, b) in part.iter().zip(to.by_ref()) {
                *b = shared.load(Ordering::Relaxed);
            }
        }
        // The bytes must be read before the peer may overwrite them.
        fence(Ordering::SeqCst);
        self.set(q.cons, cons.wrapping_add(n as u32));
        Ok(n)
    }

    /// Moves as many of `bytes` as fit into `q`.
    fn write(&mut self, q: Queue, bytes: &[u8]) -> Result<usize, CorruptRing> {
        let cons = self.get(q.cons);
        let prod = self.get(q.prod);
        // No byte may be written before the consumer index that frees its
        // place has been read.
        fence(Ordering::SeqCst);
        let queued = prod.wrapping_sub(cons);
        if queued > N as u32 {
            return Err(CorruptRing { cons, prod });
        }
        let n = bytes.len().min(N - queued as usize);
        if n == 0 {
            return Ok(0);
        }
        let mut from = bytes.iter().take(n);
        for part in &self.queue(q, prod) {
            for (shared, &b) in part.iter().zip(from.by_ref()) {
                shared.store(b, Ordering::Relaxed);
            }
        }
        // The bytes must be visible before the producer index that covers them.
        fence(Ordering::SeqCst);
        self.set(q.prod, prod.wrapping_add(n as u32));
        Ok(n)
    }

    /// `connection`, written after everything before it.
    fn set_connection(&mut self, v: u32) {
        fence(Ordering::SeqCst);
        self.set(Field::Connection, v);
    }

    /// The server's half of a reconnection (`Ring::reconnect`).
    fn reconnect(&mut self) {
        // As oxenstored does: indices back to 0 and the queues full of
        // 0xff, which reads as an invalid message type.
        for q in [Self::REQUESTS, Self::REPLIES] {
            for part in &self.queue(q, 0) {
                for shared in *part {
                    shared.store(0xff, Ordering::Relaxed);
                }
            }
        }
        for f in [Field::ReqCons, Field::ReqProd, Field::RspCons, Field::RspProd] {
            self.set(f, 0);
        }
        self.set_connection(CONNECTED);
    }
}

/// The page of a real ring.
type RingPage = Page<RING_SIZE>;

/// The server's view of a ring page: reads requests, writes replies.
pub struct Ring {
    page: RingPage,
}

impl Ring {
    /// Fails if `map` is shorter than a page.
    pub fn new(map: Mapping) -> io::Result<Ring> {
        Ok(Ring { page: Page::new(map)? })
    }

    /// Moves up to `buf.len()` request bytes into `buf`; 0: none queued.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, CorruptRing> {
        self.page.read(RingPage::REQUESTS, buf)
    }

    /// Queues as many reply bytes as fit; 0: the reply queue is full.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, CorruptRing> {
        self.page.write(RingPage::REPLIES, bytes)
    }

    pub fn server_features(&self) -> u32 {
        self.page.get(Field::ServerFeatures)
    }

    /// To be done before the first byte is read or written: a guest may
    /// rely on features only if they were there from the start.
    pub fn set_server_features(&mut self, features: u32) {
        self.page.set(Field::ServerFeatures, features);
    }

    /// `CONNECTED`, or `RECONNECT` when the guest asks for `reconnect`.
    /// Meaningful only with `FEATURE_RECONNECTION`. `read` and `write` do
    /// not look at it: the daemon checks it first on each event, as a
    /// guest that asked to reconnect has given up on what is queued.
    pub fn connection(&self) -> u32 {
        self.page.get(Field::Connection)
    }

    pub fn set_connection(&mut self, v: u32) {
        self.page.set_connection(v);
    }

    pub fn error(&self) -> u32 {
        self.page.get(Field::Error)
    }

    /// Tells the guest why the server stopped serving it.
    pub fn set_error(&mut self, e: u32) {
        // Whatever was written before is visible before the verdict.
        fence(Ordering::SeqCst);
        self.page.set(Field::Error, e);
    }

    /// The server's half of a reconnection: empties both queues and sets
    /// `connection` back to `CONNECTED`. The guest ignores every other
    /// word while it waits, so resetting its indices too is allowed. The
    /// daemon drops the connection's state first and notifies after.
    pub fn reconnect(&mut self) {
        self.page.reconnect();
    }
}

/// The guest's view of a ring page: writes requests, reads replies. It
/// can also write any word, as a buggy or hostile guest would.
pub struct GuestRing {
    page: RingPage,
}

impl GuestRing {
    /// Fails if `map` is shorter than a page.
    pub fn new(map: Mapping) -> io::Result<GuestRing> {
        Ok(GuestRing { page: Page::new(map)? })
    }

    /// Queues as many request bytes as fit; 0: the request queue is full.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, CorruptRing> {
        self.page.write(RingPage::REQUESTS, bytes)
    }

    /// Moves up to `buf.len()` reply bytes into `buf`; 0: none queued.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, CorruptRing> {
        self.page.read(RingPage::REPLIES, buf)
    }

    /// Sets `connection` to `RECONNECT`; then the guest notifies and waits
    /// for `CONNECTED`.
    pub fn request_reconnect(&mut self) {
        fence(Ordering::SeqCst);
        self.page.set(Field::Connection, RECONNECT);
    }

    pub fn get(&self, f: Field) -> u32 {
        self.page.get(f)
    }

    pub fn set(&mut self, f: Field, v: u32) {
        self.page.set(f, v);
    }
}

// Kani proofs of `Page` (`read`, `write`, `reconnect`, `new`) and of the
// layout, at `RING_SIZE` and at smaller queue sizes (sequential, bounded):
// scripts/kani.sh.
#[cfg(kani)]
#[path = "ring_proofs.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::mem::ManuallyDrop;
    use std::ops::{Deref, DerefMut};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// The shared page of a test. Natively, a memfd mapped once per view,
    /// as a guest's page is mapped by the guest and by the daemon. Under
    /// Miri, which has neither memfd nor file mappings, one heap page that
    /// every view points to: the views must not unmap it (`View`), the
    /// page frees it when dropped, after them.
    struct TestPage {
        #[cfg(not(miri))]
        f: crate::fd::Memfd,
        #[cfg(miri)]
        ptr: std::ptr::NonNull<u8>,
    }

    #[cfg(miri)]
    fn layout() -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap()
    }

    impl TestPage {
        #[cfg(not(miri))]
        fn new() -> TestPage {
            TestPage {
                f: crate::fd::memfd("xs-sys-ring", PAGE_SIZE as u64).unwrap(),
            }
        }

        #[cfg(miri)]
        fn new() -> TestPage {
            // SAFETY: the layout is not zero-sized.
            let p = unsafe { std::alloc::alloc_zeroed(layout()) };
            TestPage {
                ptr: std::ptr::NonNull::new(p).unwrap(),
            }
        }

        /// A mapping of the page's first `len` bytes. Under Miri it must
        /// not be dropped (see `View`).
        fn mapping(&self, len: usize) -> Mapping {
            #[cfg(not(miri))]
            return self.f.map(0, len).unwrap();
            // SAFETY: the page outlives the views (each test drops it
            // last), and no view unmaps it (`View`).
            #[cfg(miri)]
            return unsafe { Mapping::from_raw(self.ptr, len, None) };
        }

        fn ring(&self) -> View<Ring> {
            View::new(Ring::new(self.mapping(PAGE_SIZE)).unwrap())
        }

        fn guest(&self) -> View<GuestRing> {
            View::new(GuestRing::new(self.mapping(PAGE_SIZE)).unwrap())
        }

        /// The page's bytes at `offset`, read beside the views.
        fn read_at(&self, buf: &mut [u8], offset: usize) {
            #[cfg(not(miri))]
            std::os::unix::fs::FileExt::read_at(self.f.file(), buf, offset as u64).unwrap();
            #[cfg(miri)]
            {
                assert!(offset + buf.len() <= PAGE_SIZE);
                // SAFETY: inside the page, which no other thread writes
                // while a test looks at it.
                unsafe { std::ptr::copy_nonoverlapping(self.ptr.as_ptr().add(offset), buf.as_mut_ptr(), buf.len()) };
            }
        }
    }

    #[cfg(miri)]
    impl Drop for TestPage {
        fn drop(&mut self) {
            // SAFETY: allocated in `new` with this layout.
            unsafe { std::alloc::dealloc(self.ptr.as_ptr(), layout()) };
        }
    }

    /// A ring over the test page. Natively it owns its mapping and unmaps
    /// it when dropped; under Miri the page is not a mapping and is freed
    /// by `TestPage`, so the ring is not dropped (it owns nothing else).
    struct View<T>(ManuallyDrop<T>);

    impl<T> View<T> {
        fn new(t: T) -> View<T> {
            View(ManuallyDrop::new(t))
        }
    }

    impl<T> Drop for View<T> {
        fn drop(&mut self) {
            // SAFETY: dropped once, here; never used after.
            #[cfg(not(miri))]
            unsafe {
                ManuallyDrop::drop(&mut self.0)
            };
        }
    }

    impl<T> Deref for View<T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T> DerefMut for View<T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    /// Server and guest views of one fresh page.
    fn pair() -> (TestPage, View<Ring>, View<GuestRing>) {
        let f = TestPage::new();
        let (s, g) = (f.ring(), f.guest());
        (f, s, g)
    }

    /// xorshift64: deterministic, and enough to vary lengths and bytes.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    fn set_all(g: &mut GuestRing, idx: u32) {
        for f in [Field::ReqCons, Field::ReqProd, Field::RspCons, Field::RspProd] {
            g.set(f, idx);
        }
    }

    fn words(g: &GuestRing) -> Vec<u32> {
        Field::ALL.iter().map(|&f| g.get(f)).collect()
    }

    #[test]
    fn layout_matches_xs_wire_h() {
        let (f, mut s, mut g) = pair();
        for (i, &field) in Field::ALL.iter().enumerate() {
            g.set(field, 0x0101_0101 * (i as u32 + 1));
        }
        let mut raw = [0u8; 28];
        f.read_at(&mut raw, 2048);
        for i in 0..7 {
            assert_eq!(
                u32::from_ne_bytes(raw[4 * i..4 * i + 4].try_into().unwrap()),
                0x0101_0101 * (i as u32 + 1)
            );
        }
        set_all(&mut g, 0);
        assert_eq!(g.write(b"req").unwrap(), 3);
        assert_eq!(s.write(b"rsp").unwrap(), 3);
        let mut q = [0u8; 3];
        f.read_at(&mut q, 0);
        assert_eq!(&q, b"req");
        f.read_at(&mut q, 1024);
        assert_eq!(&q, b"rsp");
        assert_eq!(
            (FEATURE_RECONNECTION, FEATURE_ERROR, CONNECTED, RECONNECT),
            (1, 2, 0, 1)
        );
        assert_eq!((ERROR_NONE, ERROR_COMM, ERROR_RINGIDX, ERROR_PROTO), (0, 1, 2, 3));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "a refused mapping is dropped, so unmapped: under Miri it is the test's heap page"
    )]
    fn a_ring_needs_a_page() {
        let f = TestPage::new();
        let short = f.mapping(2076);
        assert_eq!(Ring::new(short).err().unwrap().kind(), io::ErrorKind::InvalidInput);
        let short = f.mapping(100);
        assert_eq!(GuestRing::new(short).err().unwrap().kind(), io::ErrorKind::InvalidInput);
        // A page that does not start on a page boundary: refused, in
        // release builds too (the words would be misaligned atomics).
        let two = crate::fd::memfd("xs-sys-ring-2", 2 * PAGE_SIZE as u64).unwrap();
        let both = two.map(0, 2 * PAGE_SIZE).unwrap();
        for off in [1, 4, 2048] {
            // SAFETY: inside `both`, which outlives it; the refused view is
            // dropped, and its `munmap` of an address not on a page
            // boundary fails (EINVAL) without touching `both`.
            let m =
                unsafe { Mapping::from_raw(std::ptr::NonNull::new(both.as_ptr().add(off)).unwrap(), PAGE_SIZE, None) };
            let e = Ring::new(m).err().unwrap();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(e.to_string(), "a ring page must start on a page boundary");
        }
        // `both` is still mapped.
        // SAFETY: inside `both`; this test is the only user of the file.
        unsafe { both.as_ptr().add(PAGE_SIZE).write(7) };
        drop(both);
        fn send<T: Send>() {}
        send::<Ring>();
        send::<GuestRing>();
    }

    #[test]
    fn requests_and_replies_cross() {
        let (_f, mut s, mut g) = pair();
        assert_eq!(g.write(b"hello").unwrap(), 5);
        assert_eq!((g.get(Field::ReqCons), g.get(Field::ReqProd)), (0, 5));
        let mut buf = [0u8; 64];
        assert_eq!(s.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(g.get(Field::ReqCons), 5);
        assert_eq!(s.write(b"world!").unwrap(), 6);
        assert_eq!(g.read(&mut buf).unwrap(), 6);
        assert_eq!(&buf[..6], b"world!");
        assert_eq!(words(&g)[..4], [5, 5, 6, 6]);
    }

    #[test]
    fn empty_and_full_queues() {
        let (_f, mut s, mut g) = pair();
        set_all(&mut g, 77);
        let before = words(&g);
        let mut buf = [0u8; RING_SIZE + 1];
        assert_eq!(s.read(&mut buf).unwrap(), 0);
        assert_eq!(g.read(&mut buf).unwrap(), 0);
        assert_eq!(s.write(&[]).unwrap(), 0);
        assert_eq!(g.write(&[]).unwrap(), 0);
        assert_eq!(words(&g), before, "nothing moved, nothing published");

        let data: Vec<u8> = (0..RING_SIZE).map(|i| i as u8).collect();
        assert_eq!(g.write(&data).unwrap(), RING_SIZE);
        assert_eq!(s.write(&data).unwrap(), RING_SIZE);
        assert_eq!(g.write(b"x").unwrap(), 0);
        assert_eq!(s.write(b"x").unwrap(), 0);
        let before = words(&g);
        assert_eq!(s.read(&mut []).unwrap(), 0);
        assert_eq!(words(&g), before);
        assert_eq!(s.read(&mut buf).unwrap(), RING_SIZE);
        assert_eq!(&buf[..RING_SIZE], &data[..]);
        assert_eq!(g.read(&mut buf).unwrap(), RING_SIZE);
        assert_eq!(&buf[..RING_SIZE], &data[..]);
        assert_eq!(words(&g)[..4], [77 + 1024; 4]);
    }

    #[test]
    fn partial_reads_and_writes() {
        let (_f, mut s, mut g) = pair();
        let mut rng = Rng(1);
        let data = rng.bytes(1500);
        assert_eq!(g.write(&data).unwrap(), RING_SIZE);
        let mut buf = [0u8; 100];
        assert_eq!(s.read(&mut buf).unwrap(), 100);
        assert_eq!(&buf[..], &data[..100]);
        assert_eq!(g.write(&data[RING_SIZE..]).unwrap(), 100);
        let mut all = vec![0u8; 2000];
        assert_eq!(s.read(&mut all).unwrap(), RING_SIZE);
        assert_eq!(&all[..RING_SIZE], &data[100..1124]);

        let reply = rng.bytes(1100);
        assert_eq!(s.write(&reply).unwrap(), RING_SIZE);
        assert_eq!(g.read(&mut buf[..1]).unwrap(), 1);
        assert_eq!(s.write(&reply[RING_SIZE..]).unwrap(), 1);
        assert_eq!(g.read(&mut all).unwrap(), RING_SIZE);
        assert_eq!(&all[..RING_SIZE], &reply[1..1025]);
    }

    #[test]
    fn wrap_around_at_every_offset() {
        let (_f, mut s, mut g) = pair();
        let mut rng = Rng(2);
        let mut buf = vec![0u8; RING_SIZE];
        // Indices free-run: start anywhere, including just before 2^32.
        // Every offset; under Miri (about a million times slower) those
        // at and next to the ends and the middle of the queue.
        let offsets: Vec<u32> = if cfg!(miri) {
            vec![0, 1, 2, 511, 512, 513, 1021, 1022, 1023]
        } else {
            (0..RING_SIZE as u32).collect()
        };
        for base in [0u32, 1 << 20, u32::MAX - 2 * RING_SIZE as u32 + 1, u32::MAX - 511] {
            for &off in &offsets {
                for len in [1usize, 2, 511, 1023, 1024] {
                    let idx = base.wrapping_add(off);
                    set_all(&mut g, idx);
                    let data = rng.bytes(len);
                    assert_eq!(g.write(&data).unwrap(), len);
                    assert_eq!(s.read(&mut buf).unwrap(), len);
                    assert_eq!(&buf[..len], &data[..], "requests from {idx:#x}, {len} bytes");
                    assert_eq!(s.write(&data).unwrap(), len);
                    assert_eq!(g.read(&mut buf).unwrap(), len);
                    assert_eq!(&buf[..len], &data[..], "replies from {idx:#x}, {len} bytes");
                    assert_eq!(words(&g)[..4], [idx.wrapping_add(len as u32); 4]);
                }
            }
        }
    }

    /// A peer that moves bytes in uneven bits, against a model of both queues.
    #[test]
    fn a_lazy_peer_against_a_model() {
        let (_f, mut s, mut g) = pair();
        let mut rng = Rng(3);
        set_all(&mut g, u32::MAX - 5000);
        let (mut req, mut rsp) = (VecDeque::new(), VecDeque::new());
        let mut buf = vec![0u8; 1500];
        for _ in 0..if cfg!(miri) { 1000 } else { 20_000 } {
            let len = match rng.below(4) {
                0 => 0,
                1 => 1 + rng.below(16) as usize,
                2 => rng.below(1500) as usize,
                _ => RING_SIZE,
            };
            match rng.below(4) {
                0 => {
                    let data = rng.bytes(len);
                    let n = g.write(&data).unwrap();
                    assert_eq!(n, len.min(RING_SIZE - req.len()));
                    req.extend(&data[..n]);
                }
                1 => {
                    let n = s.read(&mut buf[..len]).unwrap();
                    assert_eq!(n, len.min(req.len()));
                    assert!(buf[..n].iter().eq(req.drain(..n).collect::<Vec<_>>().iter()));
                }
                2 => {
                    let data = rng.bytes(len);
                    let n = s.write(&data).unwrap();
                    assert_eq!(n, len.min(RING_SIZE - rsp.len()));
                    rsp.extend(&data[..n]);
                }
                _ => {
                    let n = g.read(&mut buf[..len]).unwrap();
                    assert_eq!(n, len.min(rsp.len()));
                    assert!(buf[..n].iter().eq(rsp.drain(..n).collect::<Vec<_>>().iter()));
                }
            }
            assert_eq!(
                g.get(Field::ReqProd).wrapping_sub(g.get(Field::ReqCons)) as usize,
                req.len()
            );
            assert_eq!(
                g.get(Field::RspProd).wrapping_sub(g.get(Field::RspCons)) as usize,
                rsp.len()
            );
        }
    }

    #[test]
    fn corrupt_indices_are_refused_and_nothing_moves() {
        let (f, mut s, mut g) = pair();
        let mut buf = [0u8; 2 * RING_SIZE];
        let mut before = [0u8; PAGE_SIZE];
        let mut after = [0u8; PAGE_SIZE];
        // prod - cons beyond RING_SIZE: too far ahead, behind (an index
        // moved backwards), or anything a jump of about 2^31 or 2^32 gives.
        let gaps = [
            1025u32,
            4096,
            1 << 31,
            (1 << 31) + 1,
            u32::MAX,
            0u32.wrapping_sub(1024),
            0u32.wrapping_sub(1),
        ];
        for cons in [0u32, 3, 1023, 1 << 31, u32::MAX] {
            for gap in gaps {
                let prod = cons.wrapping_add(gap);
                let bad = Err(CorruptRing { cons, prod });
                g.set(Field::ReqCons, cons);
                g.set(Field::ReqProd, prod);
                g.set(Field::RspCons, cons);
                g.set(Field::RspProd, prod);
                f.read_at(&mut before, 0);
                assert_eq!(s.read(&mut buf), bad);
                assert_eq!(s.write(b"x"), bad);
                assert_eq!(g.write(b"x"), bad);
                assert_eq!(g.read(&mut buf), bad);
                // Refused even when there is nothing to move.
                assert_eq!(s.read(&mut []), bad);
                assert_eq!(s.write(&[]), bad);
                f.read_at(&mut after, 0);
                assert!(before == after, "cons {cons:#x} prod {prod:#x}: the page changed");
            }
        }
        // The largest valid gap is a full queue.
        g.set(Field::ReqCons, u32::MAX);
        g.set(Field::ReqProd, 1023);
        assert_eq!(s.read(&mut buf), Ok(RING_SIZE));
    }

    #[test]
    fn indices_moved_between_calls() {
        let (_f, mut s, mut g) = pair();
        let mut buf = [0u8; 64];
        set_all(&mut g, 100);
        assert_eq!(g.write(b"0123456789").unwrap(), 10);
        assert_eq!(s.read(&mut buf[..4]).unwrap(), 4);
        // The guest moves the server's consumer index back: the server
        // reads the same bytes again, which harms the guest only.
        g.set(Field::ReqCons, 102);
        assert_eq!(s.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf[..8], b"23456789");
        // Producer moved back behind the consumer.
        g.set(Field::ReqProd, 105);
        assert_eq!(s.read(&mut buf), Err(CorruptRing { cons: 110, prod: 105 }));
        // And forward by 2^32 - 5 + 5: a jump of 2^32 is no jump, valid and empty.
        g.set(Field::ReqProd, 110);
        assert_eq!(s.read(&mut buf).unwrap(), 0);
        // The guest claims to have consumed replies that were never written.
        assert_eq!(s.write(b"abc").unwrap(), 3);
        g.set(Field::RspCons, 104);
        assert_eq!(s.write(b"d"), Err(CorruptRing { cons: 104, prod: 103 }));
        // Or rewinds by a whole queue, which leaves no space: nothing lost.
        g.set(Field::RspCons, 103u32.wrapping_sub(1024));
        assert_eq!(s.write(b"d").unwrap(), 0);
        g.set(Field::RspCons, 100);
        assert_eq!(s.write(b"d").unwrap(), 1);
        assert_eq!(g.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"abcd");
    }

    /// A hostile guest flips an index between a valid and an invalid value
    /// as fast as it can: an implementation that read it twice could
    /// validate one value and use the other.
    #[test]
    fn indices_are_read_once_against_a_racing_peer() {
        // Rounds at least, and of each outcome unless 2 s pass; Miri runs
        // fewer (about a million times slower).
        let (rounds, each) = if cfg!(miri) { (200, 20) } else { (2000, 100) };
        let f = TestPage::new();
        let (mut s, mut g) = (f.ring(), f.guest());
        let mut hostile = f.guest();
        set_all(&mut g, 0);
        assert_eq!(g.write(b"abcd").unwrap(), 4);
        let stop = Arc::new(AtomicBool::new(false));
        let peer = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut flips = 0u64;
                while !stop.load(Ordering::Relaxed) || flips < 1000 {
                    for v in [4, 0x8000_0000] {
                        hostile.set(Field::ReqProd, v);
                        hostile.set(Field::RspCons, v.wrapping_sub(4));
                    }
                    flips += 1;
                }
            })
        };
        let mut buf = [0u8; RING_SIZE];
        let (mut ok, mut bad) = (0, 0);
        let start = std::time::Instant::now();
        while (ok < each || bad < each) && start.elapsed() < std::time::Duration::from_secs(2) || ok + bad < rounds {
            g.set(Field::ReqCons, 0);
            match s.read(&mut buf) {
                Ok(n) => {
                    assert_eq!(n, 4);
                    assert_eq!(&buf[..4], b"abcd");
                    assert_eq!(g.get(Field::ReqCons), 4);
                    ok += 1;
                }
                Err(e) => {
                    assert_eq!((e.cons, e.prod), (0, 0x8000_0000));
                    bad += 1;
                }
            }
            // Replies: a consumer of 0 leaves the whole queue free, one of
            // 0x7fff_fffc is invalid.
            g.set(Field::RspProd, 0);
            match s.write(&buf) {
                Ok(n) => assert_eq!(n, RING_SIZE),
                Err(e) => assert_eq!((e.cons, e.prod), (0x7fff_fffc, 0)),
            }
        }
        stop.store(true, Ordering::Relaxed);
        peer.join().unwrap();
    }

    /// A hostile guest rewrites the request bytes while the server copies
    /// them out. The server reads each byte once and assumes nothing of
    /// its value; under Miri, the copy must not be a data race (each byte
    /// is an atomic access, see the module comment).
    #[test]
    fn a_peer_rewriting_the_bytes_being_read() {
        // Rounds, and full queues read, at least.
        let (rounds, fulls) = if cfg!(miri) { (20, 2) } else { (2000, 100) };
        let f = TestPage::new();
        let (mut s, mut g) = (f.ring(), f.guest());
        let mut hostile = f.guest();
        set_all(&mut g, 0);
        let stop = Arc::new(AtomicBool::new(false));
        let peer = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut fills = 0u64;
                while !stop.load(Ordering::Relaxed) || fills < 10 {
                    for v in [0xaa, 0x55] {
                        // The queue full of `v` again: the producer index
                        // goes from 0 back to 1024.
                        hostile.set(Field::ReqProd, 0);
                        let _ = hostile.write(&[v; RING_SIZE]);
                    }
                    fills += 1;
                }
            })
        };
        let mut buf = [0u8; RING_SIZE];
        let (mut done, mut full) = (0, 0);
        while done < rounds || full < fulls {
            done += 1;
            g.set(Field::ReqCons, 0);
            match s.read(&mut buf).unwrap() {
                0 => {}
                n => {
                    assert_eq!(n, RING_SIZE);
                    assert!(buf.iter().all(|b| [0, 0xaa, 0x55].contains(b)));
                    full += 1;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        peer.join().unwrap();
    }

    #[test]
    fn reconnection() {
        let (f, mut s, mut g) = pair();
        s.set_server_features(FEATURE_RECONNECTION | FEATURE_ERROR);
        assert_eq!(s.server_features(), 3);
        assert_eq!(g.get(Field::ServerFeatures), 3);
        set_all(&mut g, 4000);
        assert_eq!(g.write(b"half a requ").unwrap(), 11);
        assert_eq!(s.write(b"half a rep").unwrap(), 10);
        assert_eq!(s.connection(), CONNECTED);
        g.request_reconnect();
        assert_eq!(s.connection(), RECONNECT);
        s.reconnect();
        assert_eq!(words(&g), [0, 0, 0, 0, 3, CONNECTED, ERROR_NONE]);
        let mut queues = [0u8; 2 * RING_SIZE];
        f.read_at(&mut queues, 0);
        assert!(queues.iter().all(|&b| b == 0xff));
        let mut buf = [0u8; 16];
        assert_eq!(s.read(&mut buf).unwrap(), 0);
        assert_eq!(g.read(&mut buf).unwrap(), 0);
        assert_eq!(g.write(b"again").unwrap(), 5);
        assert_eq!(s.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"again");
    }

    #[test]
    fn signalling_words() {
        let (_f, mut s, g) = pair();
        assert_eq!((s.connection(), s.error()), (CONNECTED, ERROR_NONE));
        s.set_error(ERROR_RINGIDX);
        assert_eq!((s.error(), g.get(Field::Error)), (ERROR_RINGIDX, ERROR_RINGIDX));
        s.set_connection(RECONNECT);
        assert_eq!(g.get(Field::Connection), RECONNECT);
        let e = CorruptRing { cons: 1, prod: 0x500 };
        assert_eq!(e.to_string(), "corrupt ring: consumer index 0x1, producer index 0x500");
        let io: io::Error = e.into();
        assert_eq!(io.kind(), io::ErrorKind::InvalidData);
        assert_eq!(io.into_inner().unwrap().downcast::<CorruptRing>().unwrap().prod, 0x500);
    }

    /// Server and guest on two threads and two mappings, a long stream each
    /// way, in chunks of uneven sizes.
    #[test]
    fn two_threads_stream_both_ways() {
        // Under Miri (about a million times slower) 16 KiB, still across
        // the wrap of the indices at 2^32.
        const LEN: usize = if cfg!(miri) { 1 << 14 } else { 1 << 20 };
        let f = TestPage::new();
        let (mut s, mut g) = (f.ring(), f.guest());
        set_all(&mut g, u32::MAX - if cfg!(miri) { 5000 } else { 100_000 });
        let requests = Rng(4).bytes(LEN);
        let replies = Rng(5).bytes(LEN);
        let server = {
            let (requests, replies) = (requests.clone(), replies.clone());
            std::thread::spawn(move || {
                let mut rng = Rng(6);
                let (mut got, mut sent) = (Vec::with_capacity(LEN), 0);
                let mut buf = [0u8; 1500];
                while got.len() < LEN || sent < LEN {
                    let want = 1 + rng.below(1500) as usize;
                    let n = s.read(&mut buf[..want]).unwrap();
                    got.extend_from_slice(&buf[..n]);
                    let m = s
                        .write(&replies[sent..LEN.min(sent + 1 + rng.below(1500) as usize)])
                        .unwrap();
                    sent += m;
                    if n == 0 && m == 0 {
                        std::thread::yield_now();
                    }
                }
                assert!(got == requests, "requests arrived intact");
            })
        };
        let mut rng = Rng(7);
        let (mut got, mut sent) = (Vec::with_capacity(LEN), 0);
        let mut buf = [0u8; 1500];
        while got.len() < LEN || sent < LEN {
            let m = g
                .write(&requests[sent..LEN.min(sent + 1 + rng.below(1500) as usize)])
                .unwrap();
            sent += m;
            let want = 1 + rng.below(1500) as usize;
            let n = g.read(&mut buf[..want]).unwrap();
            got.extend_from_slice(&buf[..n]);
            if n == 0 && m == 0 {
                std::thread::yield_now();
            }
        }
        assert!(got == replies, "replies arrived intact");
        server.join().unwrap();
    }
}
