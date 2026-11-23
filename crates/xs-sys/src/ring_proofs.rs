// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Kani proofs of the ring: `Page::read`, `Page::write`, `Page::reconnect`,
//! `Page::word`, `Page::queue`, `Page::new`, the layout. Gate:
//! scripts/kani.sh, whose header lists the harnesses, what each proves
//! and its bounds.
//!
//! The guest is the page's contents: when a harness starts, every byte of
//! the page (both queues, the seven words, the rest) is arbitrary. Kani
//! runs one thread, an atomic access as a plain one and a fence as
//! nothing: this proves the sequential algorithm against any page a guest
//! may leave between two operations, not against a guest writing during
//! one (Miri's part, scripts/miri.sh).
//!
//! The page is a heap allocation of `PAGE_SIZE` bytes aligned on
//! `PAGE_SIZE`, given to `Mapping::from_raw` and to the unmodified
//! `Page::new`, and never dropped (a drop would `munmap` it). A property of
//! every page byte or buffer byte is asserted at one arbitrary position,
//! which proves it at all of them.
//!
//! Each check is written once, generic over the queue size `N` and the
//! longest buffer `B`, and run at `N = RING_SIZE` (the code the daemon
//! runs; short buffers) and at small `N` (`Page<4>` to `Page<32>`: the
//! same source monomorphised with another constant; buffers longer than
//! the ring). A proof at a small `N` is a proof about `Page<N>`, not about
//! `Page<RING_SIZE>`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]

use super::*;
use std::mem::ManuallyDrop;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;

/// A page of arbitrary contents, and a copy of them.
fn any_page() -> (NonNull<u8>, [u8; PAGE_SIZE]) {
    let layout = std::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
    // SAFETY: the layout is not zero-sized.
    let p = NonNull::new(unsafe { std::alloc::alloc(layout) }).unwrap();
    let init: [u8; PAGE_SIZE] = kani::any();
    // SAFETY: `p` is a fresh allocation of `PAGE_SIZE` bytes.
    unsafe { p.cast::<[u8; PAGE_SIZE]>().write(init) };
    (p, init)
}

/// A mapping of the page at `p`, never to be dropped.
fn mapping(p: NonNull<u8>) -> Mapping {
    // SAFETY: `p` is a live allocation of `PAGE_SIZE` bytes, never freed;
    // the mapping is never dropped, so never unmapped.
    unsafe { Mapping::from_raw(p, PAGE_SIZE, None) }
}

/// A view of the page at `p` with queues of `N` bytes; there may be more
/// than one, as there are two mappings of a real page.
fn page<const N: usize>(p: NonNull<u8>) -> ManuallyDrop<Page<N>> {
    ManuallyDrop::new(Page::new(mapping(p)).unwrap())
}

/// The page byte at `i`, as it is now.
fn byte(p: NonNull<u8>, i: usize) -> u8 {
    assert!(i < PAGE_SIZE);
    // SAFETY: inside the page; no reference into it is live.
    unsafe { p.as_ptr().add(i).read() }
}

/// The word `f` of the page contents `bytes`, for queues of `N` bytes.
fn word_of<const N: usize>(bytes: &[u8; PAGE_SIZE], f: Field) -> u32 {
    let o = f.offset::<N>();
    u32::from_ne_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
}

fn any_queue<const N: usize>() -> Queue {
    if kani::any() {
        Page::<N>::REQUESTS
    } else {
        Page::<N>::REPLIES
    }
}

/// An arbitrary number below `n`.
fn any_below(n: usize) -> usize {
    let i: usize = kani::any();
    kani::assume(i < n);
    i
}

/// What the page byte at `i` must be after an operation that leaves every
/// byte as in `init` but the word `f`, which it sets to `v`.
fn with_word<const N: usize>(init: &[u8; PAGE_SIZE], f: Field, v: u32, i: usize) -> u8 {
    let o = f.offset::<N>();
    if (o..o + 4).contains(&i) {
        v.to_ne_bytes()[i - o]
    } else {
        init[i]
    }
}

/// What an operation did, for the harnesses' cover properties.
struct Outcome {
    len: usize,
    cons: u32,
    prod: u32,
    queued: u32,
    /// `Ok(n)`'s `n`, `None` on `CorruptRing`.
    n: Option<usize>,
}

impl Outcome {
    /// The operation moved bytes whose indices cross the end of the queue.
    fn crosses_end<const N: usize>(&self, from: u32) -> bool {
        matches!(self.n, Some(n) if (from & Page::<N>::MASK) as usize + n > N)
    }

    /// The operation moved bytes whose indices cross 2^32.
    fn crosses_2_32(&self, from: u32) -> bool {
        matches!(self.n, Some(n) if n > 0 && from.wrapping_add(n as u32) < from)
    }
}

/// `Page::read`, the counts and the page: the result is `CorruptRing` with
/// the indices read exactly when they describe more than `N` bytes, and
/// then no page byte changes; otherwise `n` is `min(len, queued)` and the
/// only page bytes that change are those of the consumer index, which
/// becomes `cons + n` (mod 2^32). Buffers of 0 to `B` bytes.
fn check_read<const N: usize, const B: usize>(q: Queue) -> Outcome {
    let (p, init) = any_page();
    let mut page = page::<N>(p);
    let mut buf: [u8; B] = kani::any();
    let len = any_below(B + 1);
    let (cons, prod) = (word_of::<N>(&init, q.cons), word_of::<N>(&init, q.prod));
    let queued = prod.wrapping_sub(cons);

    let r = page.read(q, &mut buf[..len]);

    let i = any_below(PAGE_SIZE);
    match r {
        Err(e) => {
            assert!(queued > N as u32);
            assert_eq!(e, CorruptRing { cons, prod });
            assert_eq!(byte(p, i), init[i]);
        }
        Ok(n) => {
            assert!(queued <= N as u32);
            assert_eq!(n, len.min(queued as usize));
            assert_eq!(
                byte(p, i),
                with_word::<N>(&init, q.cons, cons.wrapping_add(n as u32), i)
            );
        }
    }
    Outcome {
        len,
        cons,
        prod,
        queued,
        n: r.ok(),
    }
}

/// `Page::read`, the bytes: the `n` bytes read are those of the queue at
/// masked offsets `cons..cons + n`, in order; the rest of the buffer, and
/// all of it on `CorruptRing`, is unchanged. Buffers of 0 to `B` bytes.
fn check_read_bytes<const N: usize, const B: usize>(q: Queue) -> Outcome {
    let (p, init) = any_page();
    let mut page = page::<N>(p);
    let mut buf: [u8; B] = kani::any();
    let before = buf;
    let len = any_below(B + 1);
    let (cons, prod) = (word_of::<N>(&init, q.cons), word_of::<N>(&init, q.prod));

    let r = page.read(q, &mut buf[..len]);

    let j = any_below(B);
    match r {
        Ok(n) if j < n => {
            let at = q.data + (cons.wrapping_add(j as u32) & Page::<N>::MASK) as usize;
            assert_eq!(buf[j], init[at]);
        }
        _ => assert_eq!(buf[j], before[j]),
    }
    Outcome {
        len,
        cons,
        prod,
        queued: prod.wrapping_sub(cons),
        n: r.ok(),
    }
}

/// `Page::write`: the result is `CorruptRing` with the indices read exactly
/// when they describe more than `N` bytes, and then no page byte changes;
/// otherwise `n` is `min(len, N - queued)`, and the page bytes that change
/// are exactly the `n` queue bytes at masked offsets `prod..prod + n`,
/// which become `bytes[..n]` in order, and those of the producer index,
/// which becomes `prod + n` (mod 2^32). Buffers of 0 to `B` bytes.
fn check_write<const N: usize, const B: usize>(q: Queue) -> Outcome {
    let (p, init) = any_page();
    let mut page = page::<N>(p);
    let bytes: [u8; B] = kani::any();
    let len = any_below(B + 1);
    let (cons, prod) = (word_of::<N>(&init, q.cons), word_of::<N>(&init, q.prod));
    let queued = prod.wrapping_sub(cons);

    let r = page.write(q, &bytes[..len]);

    let i = any_below(PAGE_SIZE);
    match r {
        Err(e) => {
            assert!(queued > N as u32);
            assert_eq!(e, CorruptRing { cons, prod });
            assert_eq!(byte(p, i), init[i]);
        }
        Ok(n) => {
            assert!(queued <= N as u32);
            assert_eq!(n, len.min(N - queued as usize));
            // The place of byte `i` in the queue's order from `prod`.
            let k = (i.wrapping_sub(q.data) as u32).wrapping_sub(prod) & Page::<N>::MASK;
            if (q.data..q.data + N).contains(&i) && (k as usize) < n {
                assert_eq!(byte(p, i), bytes[k as usize]);
            } else {
                assert_eq!(
                    byte(p, i),
                    with_word::<N>(&init, q.prod, prod.wrapping_add(n as u32), i)
                );
            }
        }
    }
    Outcome {
        len,
        cons,
        prod,
        queued,
        n: r.ok(),
    }
}

/// A write then a read of one queue of `N` bytes through two views of one
/// page, from any valid state of the queue (`queued` bytes already in it,
/// any indices, any bytes): the reader gets the queued bytes, then the
/// written ones, in order. Buffers of 0 to `B` bytes. `write` and `read`
/// make the two views: `Ring` and `GuestRing` at `RING_SIZE`, two
/// `Page<N>` below.
fn round_trip<const N: usize, const B: usize>(
    q: Queue,
    write: impl FnOnce(NonNull<u8>, &[u8]) -> Result<usize, CorruptRing>,
    read: impl FnOnce(NonNull<u8>, &mut [u8]) -> Result<usize, CorruptRing>,
) -> Trip {
    let (p, init) = any_page();
    let (cons, prod) = (word_of::<N>(&init, q.cons), word_of::<N>(&init, q.prod));
    let queued = prod.wrapping_sub(cons) as usize;
    kani::assume(queued <= N);
    let bytes: [u8; B] = kani::any();
    let wlen = any_below(B + 1);
    let mut buf: [u8; B] = kani::any();
    let rlen = any_below(B + 1);

    let w = write(p, &bytes[..wlen]).unwrap();
    let r = read(p, &mut buf[..rlen]).unwrap();

    assert_eq!(w, wlen.min(N - queued));
    assert_eq!(r, rlen.min(queued + w));
    let j = any_below(B);
    if j < r {
        if j < queued {
            assert_eq!(
                buf[j],
                init[q.data + (cons.wrapping_add(j as u32) & Page::<N>::MASK) as usize]
            );
        } else {
            assert_eq!(buf[j], bytes[j - queued]);
        }
    }
    assert_eq!(word_now::<N>(p, q.cons), cons.wrapping_add(r as u32));
    assert_eq!(word_now::<N>(p, q.prod), prod.wrapping_add(w as u32));
    // Not vacuous: the reader gets written bytes that cross the end of the
    // queue, and written bytes whose indices cross 2^32.
    kani::cover!(r > queued && (prod & Page::<N>::MASK) as usize + w > N);
    kani::cover!(r > queued && prod.wrapping_add(w as u32) < prod);
    Trip {
        queued,
        wlen,
        w,
        rlen,
        r,
    }
}

/// What a round trip did, for the harnesses' cover properties.
struct Trip {
    queued: usize,
    wlen: usize,
    w: usize,
    rlen: usize,
    r: usize,
}

/// The word `f` of the page at `p`, as it is now.
fn word_now<const N: usize>(p: NonNull<u8>, f: Field) -> u32 {
    let o = f.offset::<N>();
    u32::from_ne_bytes([byte(p, o), byte(p, o + 1), byte(p, o + 2), byte(p, o + 3)])
}

/// A round trip at `N < RING_SIZE` on the queue `q`: the writer and the
/// reader are two `Page<N>` on the page.
fn small_round_trip<const N: usize, const B: usize>(q: Queue) {
    let t = round_trip::<N, B>(q, |p, b| page::<N>(p).write(q, b), |p, b| page::<N>(p).read(q, b));
    // Buffers longer than the free space, than what is then queued, than
    // the ring: a queue filled, then read whole, at once.
    kani::cover!(t.queued > 0 && t.wlen > N - t.queued && t.rlen > t.queued + t.w);
    kani::cover!(t.queued == 0 && t.w == N && t.r == N && t.wlen > N && t.rlen > N);
}

/// An operation of `sequence`.
#[derive(Clone, Copy)]
enum Op {
    Write,
    Read,
    /// A write or a read, arbitrary.
    Either,
}

/// The `K` operations `ops` on the queue `q` of `N` bytes through two views
/// of one page, each of 0 to `B` bytes, from any valid state of the queue,
/// checked against a model of the queue: a log of every byte queued, from
/// the bytes already in the queue, and the number read and written. After
/// each operation: its count is the model's, each byte read is the model's
/// next, the indices are the model's.
fn sequence<const N: usize, const B: usize, const K: usize, const LOG: usize>(q: Queue, ops: [Op; K]) {
    assert!(LOG >= N + K * B);
    let (p, init) = any_page();
    let mut writer = page::<N>(p);
    let mut reader = page::<N>(p);
    let (cons, prod) = (word_of::<N>(&init, q.cons), word_of::<N>(&init, q.prod));
    let queued = prod.wrapping_sub(cons) as usize;
    kani::assume(queued <= N);
    // The model: `log[..tail]` every byte queued so far, `log[head..tail]`
    // those in the queue.
    let mut log = [0u8; LOG];
    for (k, slot) in log.iter_mut().enumerate().take(N) {
        *slot = init[q.data + (cons.wrapping_add(k as u32) & Page::<N>::MASK) as usize];
    }
    let (mut head, mut tail) = (0, queued);
    let mut wrote_across_end = false;
    let mut each_moved = true;
    for op in ops {
        let len = any_below(B + 1);
        let writes = match op {
            Op::Write => true,
            Op::Read => false,
            Op::Either => kani::any(),
        };
        if writes {
            let bytes: [u8; B] = kani::any();
            let w = writer.write(q, &bytes[..len]).unwrap();
            assert_eq!(w, len.min(N - (tail - head)));
            let at = prod.wrapping_add((tail - queued) as u32);
            wrote_across_end |= (at & Page::<N>::MASK) as usize + w > N;
            each_moved &= w > 0;
            for (k, &b) in bytes.iter().enumerate().take(w) {
                log[tail + k] = b;
            }
            tail += w;
        } else {
            let mut buf: [u8; B] = kani::any();
            let r = reader.read(q, &mut buf[..len]).unwrap();
            assert_eq!(r, len.min(tail - head));
            let j = any_below(B);
            if j < r {
                assert_eq!(buf[j], log[head + j]);
            }
            head += r;
            each_moved &= r > 0;
            kani::cover!(r > 0 && head > queued && wrote_across_end);
        }
        assert_eq!(word_now::<N>(p, q.cons), cons.wrapping_add(head as u32));
        assert_eq!(word_now::<N>(p, q.prod), prod.wrapping_add((tail - queued) as u32));
    }
    // Not vacuous: every operation moved bytes, and all the bytes queued
    // went through.
    kani::cover!(each_moved && head == tail);
}

/// A reconnection, `reconnect`, of the page with queues of `N` bytes, on
/// any page: both queues all 0xff, the four indices 0, `connection`
/// `CONNECTED`, every other byte (`server_features`, `error`, the bytes
/// after the words) unchanged.
fn check_reconnect<const N: usize>(reconnect: impl FnOnce(NonNull<u8>)) {
    let (p, init) = any_page();

    reconnect(p);

    let i = any_below(PAGE_SIZE);
    let expect = if i < 2 * N {
        0xff
    } else {
        let f = Field::ALL[(i - 2 * N) / 4 % Field::ALL.len()];
        let o = f.offset::<N>();
        match f {
            _ if !(o..o + 4).contains(&i) => init[i],
            Field::ReqCons | Field::ReqProd | Field::RspCons | Field::RspProd => 0u32.to_ne_bytes()[i - o],
            Field::Connection => CONNECTED.to_ne_bytes()[i - o],
            Field::ServerFeatures | Field::Error => init[i],
        }
    };
    assert_eq!(byte(p, i), expect);
}

/// The place of each word in `Field::ALL`; a word added to `Field` and
/// not here does not compile.
fn rank(f: Field) -> usize {
    match f {
        Field::ReqCons => 0,
        Field::ReqProd => 1,
        Field::RspCons => 2,
        Field::RspProd => 3,
        Field::ServerFeatures => 4,
        Field::Connection => 5,
        Field::Error => 6,
    }
}

/// The layout `word` and `queue` rely on, for queues of `N` bytes: each
/// word is 4-aligned, after both queues, inside the page, and overlaps no
/// other; the queues are one after the other; a masked index is a place
/// in a queue, and masking agrees with indices that run free modulo 2^32.
fn check_layout<const N: usize>() {
    let () = Page::<N>::VALID;
    let mask = Page::<N>::MASK;
    let a = Field::ALL[any_below(Field::ALL.len())];
    let b = Field::ALL[any_below(Field::ALL.len())];
    let (oa, ob) = (a.offset::<N>(), b.offset::<N>());
    assert!(oa.is_multiple_of(4));
    assert!(oa >= Page::<N>::REPLIES.data + N);
    assert!(oa + 4 <= 2 * N + 28 && 2 * N + 28 <= PAGE_SIZE);
    assert!(a == b || oa + 4 <= ob || ob + 4 <= oa);
    assert!(Page::<N>::REQUESTS.data + N <= Page::<N>::REPLIES.data);
    assert!(Page::<N>::REPLIES.data + N <= Field::ReqCons.offset::<N>());
    assert!(N.is_power_of_two() && mask as usize == N - 1);
    let (x, k): (u32, u32) = (kani::any(), kani::any());
    assert!(((x & mask) as usize) < N);
    assert_eq!(x.wrapping_add(k) & mask, ((x & mask) + (k & mask)) & mask);
}

/// `Page::word` and `Page::queue` point where their SAFETY comments say,
/// for queues of `N` bytes: the word at its offset, 4-aligned; the queue
/// from the masked index to its end, then from its start to the masked
/// index (`split_at_checked` never fails, so `unwrap_or_default` never
/// empties a queue).
fn check_word_and_queue<const N: usize>() {
    let (p, _) = any_page();
    let page = page::<N>(p);
    let f = Field::ALL[any_below(Field::ALL.len())];
    let w: *const u8 = std::ptr::from_ref(page.word(f)).cast();
    assert_eq!(w, p.as_ptr().cast_const().wrapping_add(f.offset::<N>()));
    assert!(w.addr().is_multiple_of(4));

    let q = any_queue::<N>();
    let at: u32 = kani::any();
    let m = (at & Page::<N>::MASK) as usize;
    let [from, before] = page.queue(q, at);
    assert_eq!(
        from.as_ptr().cast::<u8>(),
        p.as_ptr().cast_const().wrapping_add(q.data + m)
    );
    assert_eq!(from.len(), N - m);
    assert_eq!(
        before.as_ptr().cast::<u8>(),
        p.as_ptr().cast_const().wrapping_add(q.data)
    );
    assert_eq!(before.len(), m);
}

/// Calls of `Page::word` per word since the harness started.
static WORD_CALLS: [AtomicUsize; 7] = [const { AtomicUsize::new(0) }; 7];

/// `Page::word`, counting its calls: the stub of the `_once` harnesses.
/// Every access to a word, load or store, goes through `word`, the
/// module's only way to a word.
fn counted_word<const N: usize>(page: &Page<N>, f: Field) -> &AtomicU32 {
    WORD_CALLS[rank(f)].fetch_add(1, Ordering::Relaxed);
    // SAFETY: as in `Page::word`.
    unsafe { AtomicU32::from_ptr(page.map.as_ptr().add(f.offset::<N>()).cast()) }
}

fn calls(f: Field) -> usize {
    WORD_CALLS[rank(f)].load(Ordering::Relaxed)
}

/// `Page::read` (`reads`) or `Page::write` accesses the queue's two
/// indices once each, and the index it moves once more, to store it, when
/// it moved bytes; no other word. Needs `Page::word` stubbed by
/// `counted_word`. Buffers of 0 to `B` bytes.
fn check_once<const N: usize, const B: usize>(q: Queue, reads: bool) {
    let (p, _) = any_page();
    let mut page = page::<N>(p);
    let mut buf: [u8; B] = kani::any();
    let len = any_below(B + 1);

    let r = if reads {
        page.read(q, &mut buf[..len])
    } else {
        page.write(q, &buf[..len])
    };

    let stored = matches!(r, Ok(n) if n > 0);
    let moved = if reads { q.cons } else { q.prod };
    let f = Field::ALL[any_below(Field::ALL.len())];
    let expect = match f {
        _ if f == moved => 1 + usize::from(stored),
        _ if f == q.cons || f == q.prod => 1,
        _ => 0,
    };
    assert_eq!(calls(f), expect);
}

// The harnesses at `RING_SIZE`: the code the daemon runs, buffers shorter
// than the queue.

#[kani::proof]
#[kani::unwind(34)]
fn read() {
    let o = check_read::<RING_SIZE, 32>(any_queue::<RING_SIZE>());
    kani::cover!(o.n == Some(o.len) && o.crosses_end::<RING_SIZE>(o.cons));
    kani::cover!(o.crosses_2_32(o.cons));
}

#[kani::proof]
#[kani::unwind(10)]
fn read_bytes() {
    let o = check_read_bytes::<RING_SIZE, 8>(any_queue::<RING_SIZE>());
    kani::cover!(o.crosses_end::<RING_SIZE>(o.cons));
}

#[kani::proof]
#[kani::unwind(10)]
fn write() {
    let o = check_write::<RING_SIZE, 8>(any_queue::<RING_SIZE>());
    kani::cover!(o.crosses_end::<RING_SIZE>(o.prod));
    kani::cover!(o.crosses_2_32(o.prod));
}

#[kani::proof]
#[kani::unwind(10)]
fn guest_to_server() {
    round_trip::<RING_SIZE, 8>(
        RingPage::REQUESTS,
        |p, b| ManuallyDrop::new(GuestRing::new(mapping(p)).unwrap()).write(b),
        |p, b| ManuallyDrop::new(Ring::new(mapping(p)).unwrap()).read(b),
    );
}

#[kani::proof]
#[kani::unwind(10)]
fn server_to_guest() {
    round_trip::<RING_SIZE, 8>(
        RingPage::REPLIES,
        |p, b| ManuallyDrop::new(Ring::new(mapping(p)).unwrap()).write(b),
        |p, b| ManuallyDrop::new(GuestRing::new(mapping(p)).unwrap()).read(b),
    );
}

/// Needs `-Z stubbing`.
#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(Page::word, counted_word)]
fn read_once() {
    check_once::<RING_SIZE, 8>(any_queue::<RING_SIZE>(), true);
}

/// Needs `-Z stubbing`.
#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(Page::word, counted_word)]
fn write_once() {
    check_once::<RING_SIZE, 8>(any_queue::<RING_SIZE>(), false);
}

/// `Ring::reconnect`.
#[kani::proof]
#[kani::unwind(1025)]
fn reconnect() {
    check_reconnect::<RING_SIZE>(|p| ManuallyDrop::new(Ring::new(mapping(p)).unwrap()).reconnect());
}

/// Every queue size `Page::VALID` allows: 4 to 1,024.
#[kani::proof]
fn layout() {
    for (k, f) in Field::ALL.into_iter().enumerate() {
        assert_eq!(rank(f), k);
    }
    check_layout::<4>();
    check_layout::<8>();
    check_layout::<16>();
    check_layout::<32>();
    check_layout::<64>();
    check_layout::<128>();
    check_layout::<256>();
    check_layout::<512>();
    check_layout::<RING_SIZE>();
}

/// Every queue size `Page::VALID` allows: 4 to 1,024.
#[kani::proof]
fn word_and_queue() {
    check_word_and_queue::<4>();
    check_word_and_queue::<8>();
    check_word_and_queue::<16>();
    check_word_and_queue::<32>();
    check_word_and_queue::<64>();
    check_word_and_queue::<128>();
    check_word_and_queue::<256>();
    check_word_and_queue::<512>();
    check_word_and_queue::<RING_SIZE>();
}

/// `Page::new` accepts a mapping exactly when it is a whole page or more
/// and starts on a page boundary, for any start in the first page of an
/// allocation of two and any length that fits. Needs `-Z c-ffi`: a refused
/// mapping is dropped, and its drop calls `munmap`, then a foreign function
/// without a body.
#[kani::proof]
fn page_new() {
    let layout = std::alloc::Layout::from_size_align(2 * PAGE_SIZE, PAGE_SIZE).unwrap();
    // SAFETY: the layout is not zero-sized.
    let base = NonNull::new(unsafe { std::alloc::alloc(layout) }).unwrap();
    let off = any_below(PAGE_SIZE + 1);
    let len = any_below(2 * PAGE_SIZE - off + 1);
    let start = NonNull::new(base.as_ptr().wrapping_add(off)).unwrap();
    // SAFETY: inside the allocation, which is never freed; a mapping that
    // `new` accepts is never dropped.
    let r = RingPage::new(unsafe { Mapping::from_raw(start, len, None) });
    assert_eq!(r.is_ok(), off.is_multiple_of(PAGE_SIZE) && len >= PAGE_SIZE);
    std::mem::forget(r);
}

// The harnesses at small `N`: buffers from empty to longer than two rings
// (`2 * N + 1` bytes). Every loop of `Page` runs at most `N` times whatever
// the buffer, so the unwind bound is `N + 1`. Either queue, arbitrary,
// unless the harness names one: a check on an arbitrary queue that did
// not fit in 7 GB of memory is run once per queue. Not every check at
// every size: the others do not fit (scripts/kani.sh).

/// `$name`: `check_read` at `N = $n`, buffers of 0 to `$b` bytes, unwind
/// `$u`, on the queue `$q`; and so for the other macros.
macro_rules! small_read {
    ($name:ident, $n:literal, $b:literal, $u:literal, $q:expr) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn $name() {
            let o = check_read::<$n, $b>($q);
            kani::cover!(o.n == Some(o.len) && o.crosses_end::<$n>(o.cons));
            kani::cover!(o.crosses_2_32(o.cons));
            // A buffer longer than what is queued, than the ring, than
            // two rings: all of a full queue read at once.
            kani::cover!(o.n.is_some() && o.len > o.queued as usize && o.queued > 0);
            kani::cover!(o.n == Some($n) && o.len > $n);
            kani::cover!(o.n.is_some() && o.len > 2 * $n);
        }
    };
}

macro_rules! small_read_bytes {
    ($name:ident, $n:literal, $b:literal, $u:literal, $q:expr) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn $name() {
            let o = check_read_bytes::<$n, $b>($q);
            kani::cover!(o.n == Some($n) && o.len > $n && o.crosses_end::<$n>(o.cons));
            kani::cover!(o.crosses_2_32(o.cons));
        }
    };
}

macro_rules! small_write {
    ($name:ident, $n:literal, $b:literal, $u:literal, $q:expr) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn $name() {
            let o = check_write::<$n, $b>($q);
            kani::cover!(o.crosses_end::<$n>(o.prod));
            kani::cover!(o.crosses_2_32(o.prod));
            // A buffer longer than the free space, than the ring, than
            // two rings: an empty queue filled at once.
            kani::cover!(o.n.is_some() && o.len > $n - o.queued as usize && o.queued > 0);
            kani::cover!(o.n == Some($n) && o.len > $n);
            kani::cover!(o.n.is_some() && o.len > 2 * $n);
        }
    };
}

macro_rules! small_round_trip {
    ($name:ident, $n:literal, $b:literal, $u:literal, $q:expr) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn $name() {
            small_round_trip::<$n, $b>($q);
        }
    };
}

/// `$reads`: `Page::read`, else `Page::write`. Needs `-Z stubbing`.
macro_rules! small_once {
    ($name:ident, $n:literal, $b:literal, $u:literal, $q:expr, $reads:literal) => {
        #[kani::proof]
        #[kani::unwind($u)]
        #[kani::stub(Page::word, counted_word)]
        fn $name() {
            check_once::<$n, $b>($q, $reads);
        }
    };
}

macro_rules! small_reconnect {
    ($name:ident, $n:literal, $u:literal) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn $name() {
            check_reconnect::<$n>(|p| page::<$n>(p).reconnect());
        }
    };
}

small_read!(small4_read, 4, 9, 5, any_queue::<4>());
small_read_bytes!(small4_read_bytes, 4, 9, 5, any_queue::<4>());
small_write!(small4_write, 4, 9, 5, any_queue::<4>());
small_round_trip!(small4_round_trip_requests, 4, 9, 5, Page::<4>::REQUESTS);
small_round_trip!(small4_round_trip_replies, 4, 9, 5, Page::<4>::REPLIES);
small_once!(small4_read_once, 4, 9, 5, any_queue::<4>(), true);
small_once!(small4_write_once, 4, 9, 5, any_queue::<4>(), false);
small_reconnect!(small4_reconnect, 4, 5);

/// Write, write, read, read, of 0 to 9 bytes each, on the request queue of
/// a `Page<4>`, against the model of `sequence`.
#[kani::proof]
#[kani::unwind(5)]
fn small4_wwrr() {
    sequence::<4, 9, 4, 40>(Page::<4>::REQUESTS, [Op::Write, Op::Write, Op::Read, Op::Read]);
}

/// Write, read, write, read, as `small4_wwrr`.
#[kani::proof]
#[kani::unwind(5)]
fn small4_wrwr() {
    sequence::<4, 9, 4, 40>(Page::<4>::REQUESTS, [Op::Write, Op::Read, Op::Write, Op::Read]);
}

small_read!(small8_read, 8, 17, 9, any_queue::<8>());
small_read_bytes!(small8_read_bytes, 8, 17, 9, any_queue::<8>());
small_write!(small8_write, 8, 17, 9, any_queue::<8>());
small_round_trip!(small8_round_trip_requests, 8, 17, 9, Page::<8>::REQUESTS);
small_round_trip!(small8_round_trip_replies, 8, 17, 9, Page::<8>::REPLIES);
small_once!(small8_read_once, 8, 17, 9, any_queue::<8>(), true);
small_once!(small8_write_once, 8, 17, 9, any_queue::<8>(), false);
small_reconnect!(small8_reconnect, 8, 9);

small_read!(small16_read, 16, 33, 17, any_queue::<16>());
small_read_bytes!(small16_read_bytes_requests, 16, 33, 17, Page::<16>::REQUESTS);
small_read_bytes!(small16_read_bytes_replies, 16, 33, 17, Page::<16>::REPLIES);
small_once!(small16_read_once, 16, 33, 17, any_queue::<16>(), true);
small_once!(small16_write_once, 16, 33, 17, any_queue::<16>(), false);
small_reconnect!(small16_reconnect, 16, 17);

small_read!(small32_read, 32, 65, 33, any_queue::<32>());
small_once!(small32_read_once, 32, 65, 33, any_queue::<32>(), true);
small_once!(small32_write_once, 32, 65, 33, any_queue::<32>(), false);
small_reconnect!(small32_reconnect, 32, 33);
