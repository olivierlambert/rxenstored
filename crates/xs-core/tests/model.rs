// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Random request sequences on several connections, run by the core and by
//! a deliberately naive model of oxenstored's behaviour: the store is a
//! flat map from path to node, watches are a list scanned in full, a
//! transaction is a full copy of the store, and a commit re-executes every
//! request of the transaction on the current store and compares the reply
//! bytes (as the connection was when it made them if the store's root was
//! not replaced since the transaction started, as it is now otherwise). Two of the connections are sockets (domain 0), two are guests,
//! and every access check is spelled out on the flat map as oxenstored's
//! `store.ml` spells it. Replies, watch events and the final store must
//! agree. The quotas too: a node count is a scan of the flat map, and the
//! core's own counts are audited after every step.
//!
//! The model, the generator and the loop are in `oracle/`, which the fuzz
//! target `core_vs_model` shares; this file runs them on seeded sequences,
//! in both profiles: oxenstored's, and the native one, whose rules the
//! model follows when asked (`oracle` module documentation).

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

mod oracle;

use oracle::{run, Msg, Pair, Quotas, Recorder, Rng, Seen};
use std::hash::BuildHasher;
use xs_core::Profile;
use xs_wire::MsgType;

/// One seeded sequence of `steps` steps.
fn run_seed(seed: u64, steps: usize, q: Quotas, profile: Profile, seen: &mut Seen) {
    let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    // A random key for the watch index, as the daemon draws it. A failed
    // test shows the key of each seed it ran (the harness prints what a
    // failed test printed): `XS_TEST_HASH_KEY=A,B` replays it.
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
    println!("seed {seed}: XS_TEST_HASH_KEY={:#x},{:#x}", key[0], key[1]);
    run(&mut rng, seed, key, steps, q, profile, seen);
}

/// `Config::default()`'s.
const DEFAULT: Quotas = Quotas {
    entity_max: 1000,
    watch_max: 100,
    transaction_max: 10,
    request_max: 1024,
    acl_max: 256,
};

/// The seeds and steps of a test: its own, or fewer for a slow run (Miri,
/// a sanitizer), or more for a longer one: `XS_MODEL_SEEDS=N` runs N seeds
/// from its first, `XS_MODEL_STEPS=N` N steps each. A run with fewer
/// seeds or other steps still checks that the core and the model agree,
/// but not the counts at the end of each test, which check that the full
/// run's sequences reach every outcome.
fn budget(seeds: std::ops::Range<u64>, steps: usize) -> (std::ops::Range<u64>, usize, bool) {
    let var = |name: &str| std::env::var(name).ok().map(|v| v.parse::<u64>().expect(name));
    let (n, s) = (var("XS_MODEL_SEEDS"), var("XS_MODEL_STEPS"));
    let end = n.map_or(seeds.end, |n| seeds.start + n);
    (
        seeds.start..end,
        s.map_or(steps, |s| s as usize),
        end >= seeds.end && s.is_none(),
    )
}

#[test]
fn core_agrees_with_the_naive_model() {
    agrees(Profile::Oxenstored);
}

#[test]
fn core_agrees_with_the_naive_model_in_the_native_profile() {
    agrees(Profile::Native);
}

fn agrees(profile: Profile) {
    let mut seen = Seen::default();
    let (seeds, steps, full) = budget(0..300, 400);
    for seed in seeds {
        run_seed(seed, steps, DEFAULT, profile, &mut seen);
    }
    let Seen {
        commits,
        conflicts,
        denied,
        guest_writes,
        guest_events,
        ..
    } = seen;
    println!("{commits} commits, {conflicts} conflicts, {denied} EACCES, {guest_writes} guest writes, {guest_events} guest events");
    if !full {
        return;
    }
    // The sequences exercise both outcomes of a commit, and of a check.
    assert!(commits > 500, "{commits} commits");
    assert!(conflicts > 50, "{conflicts} conflicts");
    assert!(denied > 1000, "{denied} EACCES");
    assert!(guest_writes > 1000, "{guest_writes} guest writes");
    assert!(guest_events > 1000, "{guest_events} guest events");
}

#[test]
fn core_agrees_with_the_naive_model_under_tight_quotas() {
    agrees_under_tight_quotas(Profile::Oxenstored);
}

#[test]
fn core_agrees_with_the_naive_model_under_tight_quotas_in_the_native_profile() {
    agrees_under_tight_quotas(Profile::Native);
}

fn agrees_under_tight_quotas(profile: Profile) {
    let q = Quotas {
        entity_max: 4,
        watch_max: 2,
        transaction_max: 1,
        request_max: 5,
        acl_max: 1,
    };
    let mut seen = Seen::default();
    let (seeds, steps, full) = budget(1000..1150, 400);
    for seed in seeds {
        run_seed(seed, steps, q, profile, &mut seen);
    }
    let Seen {
        commits,
        conflicts,
        quota,
        guest_writes,
        ..
    } = seen;
    println!("{commits} commits, {conflicts} conflicts, {quota} refused by a quota, {guest_writes} guest writes");
    if !full {
        return;
    }
    assert!(quota > 1000, "{quota} refused by a quota");
    assert!(
        commits > 100 && conflicts > 10 && guest_writes > 500,
        "{commits} {conflicts} {guest_writes}"
    );
}

/// Fixed requests (connection of `DOMIDS`, type, transaction, payload) made
/// to both, which must agree at each; what the last one's connection got.
fn script(steps: &[(usize, MsgType, u32, &[u8])]) -> Vec<Msg> {
    let mut pair = Pair::new(DEFAULT, Profile::Oxenstored, [1, 2]);
    let mut last = Vec::new();
    for (i, (ci, ty, tx, payload)) in steps.iter().enumerate() {
        last = pair.step("script", i, *ci, *ty as u32, *tx, payload, &mut Seen::default());
    }
    pair.check_store("script at the end");
    last
}

/// Domain 5 makes a node in a transaction, and its target is changed
/// before it commits; nothing was committed meanwhile, so the commit
/// publishes the transaction's store as it ran
/// (`ox/connection.ml:402`, `ox/transaction.ml:238-246`).
#[test]
fn a_commit_with_nothing_committed_since_publishes_the_transaction_as_it_ran() {
    let got = script(&[
        (0, MsgType::SetTarget, 0, b"5\x000\0"),
        (2, MsgType::TransactionStart, 0, b"\0"),
        (2, MsgType::Mkdir, 1, b"/b\0"),
        (0, MsgType::SetTarget, 0, b"5\x007\0"),
        (2, MsgType::TransactionEnd, 1, b"T\0"),
    ]);
    assert_eq!(got, [(MsgType::TransactionEnd as u32, 4, 1, b"OK\0".to_vec())]);
}

/// As above, but domain 0 writes a node with the value it has before the
/// commit: the root was replaced all the same (`ox/store.ml:272-289`), so
/// the requests run again as the connection is now (`ox/process.ml:463-487`)
/// and the MKDIR, refused this time, makes the commit fail.
#[test]
fn a_commit_after_a_write_of_the_same_value_runs_its_requests_again() {
    let got = script(&[
        (0, MsgType::SetTarget, 0, b"5\x000\0"),
        (2, MsgType::TransactionStart, 0, b"\0"),
        (2, MsgType::Mkdir, 1, b"/b\0"),
        (1, MsgType::Write, 0, b"/tool/xenstored\0rxenstored"),
        (0, MsgType::SetTarget, 0, b"5\x007\0"),
        (2, MsgType::TransactionEnd, 1, b"T\0"),
    ]);
    assert_eq!(got, [(MsgType::Error as u32, 5, 1, b"EAGAIN\0".to_vec())]);
}

/// A transaction makes `/e/m`, which another connection writes before the
/// commit: run again, the MKDIR changes nothing, and the commit fires for
/// it all the same (`ox/process.ml:60-72, 567`); before its reply, root
/// first, each path's watches newest first (`ox/connections.ml:138, 165`).
#[test]
fn a_commit_run_again_fires_for_its_requests_as_they_ran() {
    let got = script(&[
        (1, MsgType::Watch, 0, b"/e\0old\0"),
        (1, MsgType::Watch, 0, b"/\0root\0"),
        (1, MsgType::Watch, 0, b"/e\0new\0"),
        (1, MsgType::TransactionStart, 0, b"\0"),
        (1, MsgType::Mkdir, 1, b"/e/m\0"),
        (0, MsgType::Write, 0, b"/e/m\0v"),
        (1, MsgType::TransactionEnd, 1, b"T\0"),
    ]);
    let ev = |t: &str| {
        (
            MsgType::WatchEvent as u32,
            0,
            0,
            [&b"/e/m\0"[..], t.as_bytes(), b"\0"].concat(),
        )
    };
    assert_eq!(
        got,
        [
            ev("root"),
            ev("new"),
            ev("old"),
            (MsgType::TransactionEnd as u32, 6, 1, b"OK\0".to_vec())
        ]
    );
}

/// Seeds for the fuzz target `core_vs_model` (fuzz/): the choices of the
/// first sequences of the four tests above, each after the target's mode
/// byte (bit 0: tight quotas; bit 3: the native profile; key 0).
#[test]
#[ignore = "writes fuzz seeds: XS_FUZZ_SEEDS=DIR cargo test -p xs-core --test model -- --ignored"]
fn write_fuzz_seeds() {
    let dir = std::path::PathBuf::from(std::env::var("XS_FUZZ_SEEDS").expect("XS_FUZZ_SEEDS=DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let tight = Quotas {
        entity_max: 4,
        watch_max: 2,
        transaction_max: 1,
        request_max: 5,
        acl_max: 1,
    };
    for (mode, q, seeds) in [
        (0u8, DEFAULT, 0..8u64),
        (1, tight, 1000..1008),
        (8, DEFAULT, 0..8),
        (9, tight, 1000..1008),
    ] {
        let (profile, prefix) = if mode & 8 == 0 {
            (Profile::Oxenstored, "model-seed")
        } else {
            (Profile::Native, "model-native-seed")
        };
        for seed in seeds {
            let mut rec = Recorder {
                inner: Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1),
                choices: vec![mode],
            };
            run(&mut rec, seed, [0, 0], 400, q, profile, &mut Seen::default());
            std::fs::write(dir.join(format!("{prefix}-{seed}")), &rec.choices).unwrap();
        }
    }
}
