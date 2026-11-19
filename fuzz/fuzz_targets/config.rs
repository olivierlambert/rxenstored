// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! xs-daemon's `oxenstored.conf` parser (`src/config.rs`, a module of the
//! binary, included here as it is), then everything the daemon does with
//! its result: the core's configuration as `main.rs` `start_of` builds it,
//! the quotas, the conflict keys, the log settings, the warnings, the ring
//! scan; then a core built with that configuration serves a few requests
//! on a socket and a guest ring and passes its own audit.
//!
//! Asserts: no panic anywhere on any text (dom0-controlled input, but a
//! panic at start is a host without xenstore); the problems come in line
//! order with line numbers within the file; parsing is deterministic.

#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[path = "../../crates/xs-daemon/src/compat/config.rs"]
mod config;

use config::FileConfig;
use xs_core::{Config, Core};
use xs_wire::{write_header, MsgType};

/// `start_of` in `crates/xs-daemon/src/main.rs`, the part that reads `cf`.
fn core_config(cf: &FileConfig) -> Config {
    let mut config = Config {
        path_max: cf.quota_path_max as usize,
        value_max: if cf.quota_activate {
            cf.quota_maxsize as usize
        } else {
            usize::MAX
        },
        perms_activate: cf.perms_activate,
        perms_watch_activate: cf.perms_watch_activate,
        ..Config::default()
    };
    cf.apply_quotas(&mut config);
    cf.apply_conflicts(&mut config);
    config
}

fn request(core: &mut Core, id: xs_core::ConnId, ty: MsgType, tx: u32, payload: &[u8]) {
    let mut b = Vec::new();
    write_header(&mut b, ty as u32, 1, tx, payload.len() as u32);
    b.extend_from_slice(payload);
    core.feed(id, &b);
    core.process(id, 4);
    let n = core.output(id).len();
    core.consume(id, n);
}

fn exercise(cf: &FileConfig) {
    let _ = cf.log_settings(true, "rxenstored");
    let _ = cf.log_settings(false, "");
    let _ = cf.not_honoured();
    if let Some(d) = cf.ring_scan() {
        assert!(d >= Duration::from_secs(1) && d <= Duration::from_secs(u32::MAX.into()));
    }
    let cfg = core_config(cf);
    let mut core = Core::new(cfg, [1, 2]);
    let sock = core.open();
    let guest = core.open_domain(7);
    for id in [sock, guest] {
        request(&mut core, id, MsgType::Write, 0, b"/local/domain/7/a\0value");
        request(&mut core, id, MsgType::Write, 0, b"data/x\0yy");
        request(&mut core, id, MsgType::Mkdir, 0, b"/local/domain/7/b/c\0");
        request(&mut core, id, MsgType::Watch, 0, b"/local\0tok\0");
        request(&mut core, id, MsgType::TransactionStart, 0, b"\0");
        request(&mut core, id, MsgType::Write, 1, b"data/t\0v");
        request(&mut core, id, MsgType::TransactionEnd, 1, b"T\0");
        request(&mut core, id, MsgType::Read, 0, b"/local/domain/7/a\0");
        request(&mut core, id, MsgType::Directory, 0, b"/local/domain/7\0");
        request(&mut core, id, MsgType::Control, 0, b"quota\x007\0");
    }
    core.tick(Duration::from_secs(1));
    core.tick(Duration::from_secs(1000));
    let _ = core.next_tick();
    if let Err(e) = core.audit() {
        panic!("audit: {e}");
    }
}

fuzz_target!(|data: &[u8]| {
    let texts = [
        String::from_utf8_lossy(data).into_owned(),
        // The daemon reads the file as UTF-8 (lossy where it is not): also
        // the valid prefix alone.
        match std::str::from_utf8(data) {
            Ok(s) => s.to_string(),
            Err(e) => String::from_utf8_lossy(&data[..e.valid_up_to()]).into_owned(),
        },
    ];
    for text in &texts {
        let (cf, problems) = config::parse(text);
        let lines = text.split('\n').count();
        let mut last = 0;
        for p in &problems {
            assert!(p.line >= 1 && p.line <= lines, "line {} of {lines}", p.line);
            assert!(p.line >= last, "problems out of order");
            last = p.line;
            let _ = p.to_string();
        }
        // Debug, not ==: a float key may be NaN.
        assert_eq!(format!("{:?}", config::parse(text)), format!("{:?}", (&cf, &problems)));
        exercise(&cf);
    }
});
