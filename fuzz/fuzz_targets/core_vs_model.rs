// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Differential: the core against the naive model of oxenstored of
//! `crates/xs-core/tests/oracle/` (the model test's), in either profile, on
//! request sequences
//! whose every choice is a byte of the input. The model compares every
//! reply and watch event at every step, the whole store every 50 steps and
//! at the end, and runs `Core::audit` after each step: any difference
//! panics.
//!
//! Input: byte 0 picks the quotas (bit 0: default or tight), the key of
//! the watch index (bits 1 and 2) and the profile (bit 3: oxenstored's or
//! the native one, whose rules the model then follows); then one byte per
//! choice of the generator (connection, request type, path, transaction,
//! ...), until the input ends.

#![no_main]

#[path = "../../crates/xs-core/tests/oracle/mod.rs"]
#[allow(clippy::all)]
mod oracle;

use libfuzzer_sys::fuzz_target;
use oracle::{run, Quotas, Seen, Source};
use xs_core::Profile;

/// The generator's choices, one byte each: `below(n)` is the next byte
/// modulo `n` (every `n` the generator asks for is at most 60), 0 once the
/// input is used up.
struct Bytes<'a> {
    data: &'a [u8],
}

impl Source for Bytes<'_> {
    fn below(&mut self, n: usize) -> usize {
        match self.data.split_first() {
            Some((b, rest)) => {
                self.data = rest;
                *b as usize % n
            }
            None => 0,
        }
    }

    fn done(&self) -> bool {
        self.data.is_empty()
    }
}

const DEFAULT: Quotas = Quotas {
    entity_max: 1000,
    watch_max: 100,
    transaction_max: 10,
    request_max: 1024,
    acl_max: 256,
};

/// The model test's tight quotas.
const TIGHT: Quotas = Quotas {
    entity_max: 4,
    watch_max: 2,
    transaction_max: 1,
    request_max: 5,
    acl_max: 1,
};

const KEYS: [[u64; 2]; 4] = [
    [0, 0],
    [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210],
    [u64::MAX, 1],
    [0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa],
];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let q = if mode & 1 == 0 { DEFAULT } else { TIGHT };
    let key = KEYS[(mode >> 1) as usize % KEYS.len()];
    let profile = if mode & 8 == 0 {
        Profile::Oxenstored
    } else {
        Profile::Native
    };
    let mut src = Bytes { data: rest };
    let mut seen = Seen::default();
    run(&mut src, 0, key, 4000, q, profile, &mut seen);
});
