// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! `xs_wire`: the incremental decoder, fed a stream cut at arbitrary
//! points, against a reference parser of the whole stream.
//!
//! Asserts:
//! - every message the decoder returns is the reference's next one: a
//!   16-byte header (type, request id, transaction id, length, little
//!   endian) and `length <= PAYLOAD_MAX` bytes of payload; `None` exactly
//!   when the reference needs more bytes; `PayloadTooLarge(length)`
//!   exactly when the next header announces more than PAYLOAD_MAX;
//! - after an error the decoder keeps returning it (framing is lost: the
//!   core drops the connection), whatever is pushed after;
//! - `encode_into` of a returned message gives back the bytes it was
//!   decoded from; `Message::new` refuses exactly the payloads above
//!   PAYLOAD_MAX; `fields` and `nul_terminated` invert each other for
//!   fields without NUL; `MsgType::from_u32` and the error names round-trip;
//! - memory: the bytes the process holds while the decoder runs stay
//!   within twice the largest buffer the decoder may keep (what is pushed
//!   and not consumed, plus up to 64 KiB consumed, plus one push), plus
//!   slack: the decoder never grows without bound.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use xs_wire::{nul_terminated, Decoder, Errno, Message, MsgType, WireError, HEADER_LEN, PAYLOAD_MAX};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator, counting bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new, Ordering::Relaxed);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Push the next `n` bytes of the stream.
    Push(u16),
    /// Push the next `n` bytes, `times` times over (a long stream from a short input).
    Repeat(u16, u8),
    /// Ask for messages, up to this many.
    Next(u8),
}

/// The length a header announces.
#[derive(Arbitrary, Debug)]
enum Len {
    /// The payload's.
    True,
    /// PAYLOAD_MAX plus this: the limit's edges.
    AroundMax(i8),
    Raw(u32),
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// A stream of messages to frame: (type, req, tx, payload, the length the header gives).
    msgs: Vec<(u32, u32, u32, Vec<u8>, Len)>,
    /// Raw bytes appended to the stream.
    raw: Vec<u8>,
    ops: Vec<Op>,
    fields: Vec<Vec<u8>>,
    ty: u32,
}

/// The reference: the next message of `s`, or None if `s` is too short.
fn reference(s: &[u8]) -> Result<Option<(Message, usize)>, WireError> {
    if s.len() < HEADER_LEN {
        return Ok(None);
    }
    let w = |i: usize| u32::from_le_bytes(s[i..i + 4].try_into().unwrap());
    let len = w(12) as usize;
    if len > PAYLOAD_MAX {
        return Err(WireError::PayloadTooLarge(len));
    }
    if s.len() < HEADER_LEN + len {
        return Ok(None);
    }
    let m = Message {
        ty: w(0),
        req_id: w(4),
        tx_id: w(8),
        payload: s[HEADER_LEN..HEADER_LEN + len].to_vec(),
    };
    Ok(Some((m, HEADER_LEN + len)))
}

fn statics(input: &Input) {
    for t in MsgType::ALL {
        assert_eq!(MsgType::from_u32(t as u32), Some(t));
    }
    if let Some(t) = MsgType::from_u32(input.ty) {
        assert_eq!(t as u32, input.ty);
    } else {
        assert!(MsgType::ALL.iter().all(|t| *t as u32 != input.ty));
    }
    for e in Errno::ALL {
        let n = e.name();
        assert!(Errno::ALL.iter().filter(|x| x.name() == n).count() == 1);
        assert!(n.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }
    // nul_terminated / fields.
    let fields: Vec<&[u8]> = input
        .fields
        .iter()
        .map(|f| &f[..])
        .filter(|f| !f.contains(&0))
        .collect();
    let payload = nul_terminated(&fields);
    assert_eq!(payload.len(), fields.iter().map(|f| f.len() + 1).sum::<usize>());
    match Message::new(MsgType::Write, 1, 2, payload.clone()) {
        Ok(m) => {
            assert!(payload.len() <= PAYLOAD_MAX);
            assert_eq!(m.msg_type(), Some(MsgType::Write));
            assert_eq!(m.fields(), fields);
            let mut out = Vec::new();
            m.encode_into(&mut out);
            let mut d = Decoder::new();
            d.push(&out);
            assert_eq!(d.next_message(), Ok(Some(m)));
            assert_eq!(d.next_message(), Ok(None));
        }
        Err(e) => {
            assert!(payload.len() > PAYLOAD_MAX);
            assert_eq!(e, WireError::PayloadTooLarge(payload.len()));
        }
    }
}

fuzz_target!(|input: Input| {
    statics(&input);
    // The stream.
    let mut stream = Vec::new();
    for (ty, req, tx, payload, len) in &input.msgs {
        let len = match *len {
            Len::True => payload.len() as u32,
            Len::AroundMax(d) => (PAYLOAD_MAX as i64 + d as i64) as u32,
            Len::Raw(n) => n,
        };
        stream.extend_from_slice(&ty.to_le_bytes());
        stream.extend_from_slice(&req.to_le_bytes());
        stream.extend_from_slice(&tx.to_le_bytes());
        stream.extend_from_slice(&len.to_le_bytes());
        stream.extend_from_slice(payload);
    }
    stream.extend_from_slice(&input.raw);
    if stream.is_empty() {
        return;
    }

    let base = LIVE.load(Ordering::Relaxed);
    let mut d = Decoder::new();
    // `fed`: the bytes pushed, in order (the reference parses them).
    let mut fed: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let mut failed: Option<WireError> = None;
    let mut at = 0usize; // next byte of `stream` to push
    let mut peak = 0usize;
    let mut chunk_max = 0usize;
    let mut next_byte = |n: usize, out: &mut Vec<u8>| {
        for _ in 0..n {
            out.push(stream[at % stream.len()]);
            at += 1;
        }
    };
    for op in &input.ops {
        match *op {
            Op::Push(n) | Op::Repeat(n, _) => {
                let times = match *op {
                    Op::Repeat(_, t) => t as usize,
                    _ => 1,
                };
                let n = n as usize % 8192;
                let mut chunk = Vec::with_capacity(n);
                next_byte(n, &mut chunk);
                for _ in 0..times {
                    d.push(&chunk);
                    fed.extend_from_slice(&chunk);
                    chunk_max = chunk_max.max(chunk.len());
                    peak = peak.max(fed.len() - consumed + chunk.len());
                }
            }
            Op::Next(k) => {
                for _ in 0..=k {
                    let got = d.next_message();
                    if let Some(e) = &failed {
                        assert_eq!(got.as_ref(), Err(e), "after an error the decoder must keep failing");
                        break;
                    }
                    let want = reference(&fed[consumed..]);
                    match (got, want) {
                        (Ok(None), Ok(None)) => break,
                        (Ok(Some(m)), Ok(Some((r, used)))) => {
                            assert!(m.payload.len() <= PAYLOAD_MAX);
                            assert_eq!(m, r);
                            let mut enc = Vec::new();
                            m.encode_into(&mut enc);
                            assert_eq!(&enc[..], &fed[consumed..consumed + used], "encode(decode(x)) != x");
                            consumed += used;
                        }
                        (Err(e), Err(r)) => {
                            assert_eq!(e, r);
                            failed = Some(e);
                            break;
                        }
                        (g, w) => panic!("decoder {g:?}, reference {w:?}"),
                    }
                }
            }
        }
        // Memory: the decoder's buffer, less what the harness holds itself
        // (`fed`, a chunk, `stream`, which existed before `base`).
        let live = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        let harness = fed.capacity() + chunk_max;
        let bound = 2 * (peak + 64 * 1024 + chunk_max) + harness + 2 * PAYLOAD_MAX + 4096;
        assert!(
            live <= bound,
            "{live} bytes live, bound {bound} (peak unconsumed {peak}, fed {})",
            fed.len()
        );
    }
});
