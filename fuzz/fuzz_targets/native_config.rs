// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! xs-daemon's own configuration file, `rxenstored.conf`
//! (`src/native/config.rs`, a module of the binary, included here as it
//! is), then what the daemon does with its result (`native/mod.rs`
//! `start_of`): the core's configuration, the conflict settings, the log
//! settings, the ring scan; then a core built with it serves a few
//! requests on a socket and a guest ring and passes its own audit. The
//! input is also read as `-Q NAME=VALUE` arguments, which the same module
//! checks.
//!
//! Asserts, on any text (domain 0's input; a panic at start is a host
//! without xenstore):
//! - no panic; parsing is deterministic;
//! - errors: each is `line N: ...`, N within the file, at most one per
//!   line, in line order, never for a blank or comment line;
//! - what parses is within what the module promises: whole numbers for
//!   the quotas; the conflict settings finite and not negative, the burst
//!   limit above 0; a log file an absolute path with no blank at either
//!   end and no newline; `syslog:local0` to `local7` only; and it writes
//!   back: the settings printed as a file read to the same settings;
//! - the quotas reach the core as documented: 0 is no limit, any other
//!   value is the limit; the transaction byte quota, when not set, what
//!   one transaction of the longest path and value needs (never 0);
//! - `-Q NAME=VALUE`: accepted exactly for a known name and a whole
//!   number that fits 64 bits, and then sets that quota and no other;
//!   an error starts with `-Q ` and quotes the argument.

#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;
use std::time::Duration;

#[path = "../../crates/xs-daemon/src/native/config.rs"]
mod config;

use config::{FileConfig, Quotas, ACCESS_LINE_MAX, QUOTA_NAMES};
use xs_core::{Config, Core};
use xs_daemon::log::{Dest, Facility, Level};
use xs_wire::{write_header, MsgType};

const BLANK: &[char] = &[' ', '\t', '\r'];

/// `start_of` in `crates/xs-daemon/src/native/mod.rs`, the part that reads `cf`.
fn core_config(cf: &FileConfig) -> Config {
    let mut config = Config {
        profile: xs_core::Profile::Native,
        perms_activate: true,
        perms_watch_activate: true,
        ..Config::default()
    };
    cf.quotas.apply(&mut config);
    cf.apply_conflicts(&mut config);
    config
}

/// The quotas, in `QUOTA_NAMES` order, as the file sets them (None: the
/// transaction byte quota left to its default).
fn quota_values(q: &Quotas) -> [Option<u64>; 10] {
    [
        Some(q.nodes),
        Some(q.watches),
        Some(q.transactions),
        Some(q.outstanding),
        Some(q.path_max),
        Some(q.value_size),
        Some(q.node_permissions),
        Some(q.transaction_requests),
        Some(q.watch_events),
        q.transaction_bytes,
    ]
}

fn check_quotas_reach_the_core(q: &Quotas) {
    let mut c = Config {
        quota_activate: false,
        ..Config::default()
    };
    q.apply(&mut c);
    assert!(c.quota_activate);
    let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    let limit = |v: u64| if v == 0 { usize::MAX } else { size(v) };
    let some = |v: u64| if v == 0 { None } else { Some(size(v)) };
    assert_eq!(c.entity_max, limit(q.nodes));
    assert_eq!(c.watch_max, some(q.watches));
    assert_eq!(c.transaction_max, some(q.transactions));
    assert_eq!(c.outstanding_max, limit(q.outstanding));
    assert_eq!(c.path_max, limit(q.path_max));
    assert_eq!(c.value_max, limit(q.value_size));
    // Its owner's entry is counted, as C counts it; the core counts the others.
    assert_eq!(
        c.acl_max,
        limit(q.node_permissions).saturating_sub(usize::from(q.node_permissions != 0))
    );
    assert_eq!(c.request_max, some(q.transaction_requests));
    assert_eq!(c.watch_event_max, limit(q.watch_events));
    match q.transaction_bytes {
        Some(n) => assert_eq!(c.transaction_bytes_max, some(n)),
        None => {
            let p = xs_wire::PAYLOAD_MAX;
            let or_payload = |v: u64| if v == 0 { p } else { size(v) };
            let want = Config::transaction_bytes_for(
                some(q.transaction_requests).unwrap_or(1024),
                or_payload(q.path_max),
                or_payload(q.value_size),
            );
            assert_eq!(c.transaction_bytes_max, Some(want));
            assert!(want > 0, "a derived transaction byte quota of 0");
        }
    }
}

fn check_dest(d: &Dest) {
    match d {
        Dest::File(p) => {
            let s = p.to_str().expect("a path read from text is text");
            assert!(s.starts_with('/'), "a log file not absolute: {s:?}");
            assert!(!s.contains('\n'), "a log file with a newline: {s:?}");
            assert_eq!(s, s.trim_matches(BLANK), "a log file with blanks at an end: {s:?}");
        }
        Dest::Syslog(Facility::Local(n)) => assert!(*n <= 7, "local{n}"),
        Dest::Syslog(_) => {}
    }
}

fn dest_text(d: &Option<Dest>) -> String {
    let f = |f: &Facility| match f {
        Facility::Auth => "auth".to_string(),
        Facility::Authpriv => "authpriv".into(),
        Facility::Cron => "cron".into(),
        Facility::Daemon => "daemon".into(),
        Facility::Ftp => "ftp".into(),
        Facility::Kern => "kern".into(),
        Facility::Local(n) => format!("local{n}"),
        Facility::Lpr => "lpr".into(),
        Facility::Mail => "mail".into(),
        Facility::News => "news".into(),
        Facility::Syslog => "syslog".into(),
        Facility::User => "user".into(),
        Facility::Uucp => "uucp".into(),
    };
    match d {
        None => "none".into(),
        Some(Dest::Syslog(x)) => format!("syslog:{}", f(x)),
        Some(Dest::File(p)) => p.to_str().unwrap().into(),
    }
}

/// Every setting, by the key that sets it, as text (this mapping is the
/// harness's own, from the module's documentation; `{}` of an f64 prints
/// digits and a point, no exponent). None: the transaction byte quota
/// left to its default.
fn fields(cf: &FileConfig) -> Vec<(String, Option<String>)> {
    let mut f: Vec<(String, Option<String>)> = QUOTA_NAMES
        .iter()
        .zip(quota_values(&cf.quotas))
        .map(|(name, v)| (format!("quota-{name}"), v.map(|v| v.to_string())))
        .collect();
    let level = match cf.log_level {
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
        Level::Null => panic!("log-level null read from a file"),
    };
    for (k, v) in [
        ("log", dest_text(&cf.log)),
        ("log-level", level.to_string()),
        ("access-log", dest_text(&cf.access_log)),
        ("access-log-read-ops", cf.access_log_read_ops.to_string()),
        (
            "access-log-transactions-ops",
            cf.access_log_transactions_ops.to_string(),
        ),
        ("access-log-special-ops", cf.access_log_special_ops.to_string()),
        ("conflict-burst-limit", cf.conflict_burst_limit.to_string()),
        (
            "conflict-max-history-seconds",
            cf.conflict_max_history_seconds.to_string(),
        ),
        (
            "conflict-rate-limit-is-aggregate",
            cf.conflict_rate_limit_is_aggregate.to_string(),
        ),
        ("ring-scan-interval", cf.ring_scan_interval.to_string()),
    ] {
        f.push((k.to_string(), Some(v)));
    }
    f
}

/// The settings as a file that sets every key.
fn write_back(cf: &FileConfig) -> String {
    let mut s = String::new();
    for (k, v) in fields(cf) {
        if let Some(v) = v {
            writeln!(s, "{k} = {v}").unwrap();
        }
    }
    s
}

/// What a line `key = v` the parser accepted must have set, read here
/// from the module's documentation: a whole number in decimal digits for
/// the quotas and the ring scan, a decimal (digits and points) for the
/// conflict settings, the text itself for the others.
fn canonical(key: &str, v: &str) -> String {
    let digits = |extra: u8| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == extra);
    if key.starts_with("quota-") || key == "ring-scan-interval" {
        assert!(digits(b'0'), "{key} = {v:?} accepted: not a whole number");
        v.parse::<u64>()
            .unwrap_or_else(|_| panic!("{key} = {v:?} accepted: too large"))
            .to_string()
    } else if key.starts_with("conflict-") && key != "conflict-rate-limit-is-aggregate" {
        assert!(digits(b'.'), "{key} = {v:?} accepted: not a decimal");
        v.parse::<f64>()
            .unwrap_or_else(|_| panic!("{key} = {v:?} accepted: not a decimal"))
            .to_string()
    } else {
        v.to_string()
    }
}

/// Lines that are neither blank nor comments: (number, key, value), or
/// (number, line) without `=`.
fn content_lines(text: &str) -> Vec<(usize, Result<(&str, &str), &str>)> {
    text.split('\n')
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.trim_matches(BLANK);
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            Some((
                i + 1,
                line.split_once('=')
                    .map(|(k, v)| (k.trim_matches(BLANK), v.trim_matches(BLANK)))
                    .ok_or(line),
            ))
        })
        .collect()
}

/// The lines that must be refused: one without `=`, a key set on an
/// earlier line, a line that is refused on its own.
fn expected_errors(text: &str) -> Vec<usize> {
    let mut seen = Vec::new();
    let mut bad = Vec::new();
    for (n, kv) in content_lines(text) {
        match kv {
            Err(_) => bad.push(n),
            Ok((k, v)) => {
                if seen.contains(&k) {
                    bad.push(n);
                } else {
                    seen.push(k);
                    if config::parse(&format!("{k} = {v}")).is_err() {
                        bad.push(n);
                    }
                }
            }
        }
    }
    bad
}

fn check_settings(text: &str, cf: &FileConfig) {
    let b = cf.conflict_burst_limit;
    let h = cf.conflict_max_history_seconds;
    assert!(b.is_finite() && b > 0.0, "conflict-burst-limit {b}");
    assert!(h.is_finite() && h >= 0.0, "conflict-max-history-seconds {h}");
    // Each setting is what its line says, or the default.
    let mut want = fields(&FileConfig::default());
    for (n, kv) in content_lines(text) {
        let (k, v) = kv.unwrap_or_else(|l| panic!("line {n} {l:?} without '=' accepted"));
        let slot = want
            .iter_mut()
            .find(|(key, _)| key == k)
            .unwrap_or_else(|| panic!("line {n}: unknown key {k:?} accepted"));
        slot.1 = Some(canonical(k, v));
    }
    assert_eq!(fields(cf), want, "the settings are not what the lines say");
    for d in [&cf.log, &cf.access_log].into_iter().flatten() {
        check_dest(d);
    }
    assert_ne!(cf.log_level, Level::Null);
    match cf.ring_scan() {
        None => assert_eq!(cf.ring_scan_interval, 0),
        Some(d) => assert_eq!(d, Duration::from_secs(cf.ring_scan_interval)),
    }
    // The log settings: no rotation, access lines cut at 180, no access log
    // with --no-access-log.
    for access in [true, false] {
        let s = cf.log_settings(access, "rxenstored");
        match (&s.daemon, &cf.log) {
            (None, None) => {}
            (Some((o, level)), Some(d)) => {
                assert_eq!((&o.dest, o.nb_files, o.nb_lines, o.nb_chars), (d, 1, i64::MAX, -1));
                assert_eq!(*level, cf.log_level);
            }
            other => panic!("daemon log {other:?}"),
        }
        match (&s.access, &cf.access_log) {
            (None, None) => {}
            (None, Some(_)) => assert!(!access),
            (Some((o, sw)), Some(d)) => {
                assert!(access);
                assert_eq!((&o.dest, o.nb_files, o.nb_chars), (d, 1, ACCESS_LINE_MAX));
                assert_eq!(
                    (sw.read_ops, sw.transaction_ops, sw.special_ops),
                    (
                        cf.access_log_read_ops,
                        cf.access_log_transactions_ops,
                        cf.access_log_special_ops
                    )
                );
            }
            other => panic!("access log {other:?}"),
        }
    }
    let mut c = Config::default();
    cf.apply_conflicts(&mut c);
    assert_eq!(c.conflict_burst_limit, b);
    assert_eq!(c.conflict_rate_limit_is_aggregate, cf.conflict_rate_limit_is_aggregate);
    match Duration::try_from_secs_f64(h) {
        Ok(d) => assert_eq!(c.conflict_max_history, d),
        Err(_) => assert_eq!(c.conflict_max_history, Duration::MAX),
    }
    check_quotas_reach_the_core(&cf.quotas);
    // It writes back to itself.
    let text = write_back(cf);
    match config::parse(&text) {
        Ok(again) => assert_eq!(&again, cf, "written back as:\n{text}"),
        Err(e) => panic!("written back as:\n{text}\nit does not read: {e:?}"),
    }
}

fn check_errors(text: &str, errors: &[String]) {
    assert!(!errors.is_empty(), "Err with no error");
    let lines: Vec<&str> = text.split('\n').collect();
    let mut last = 0;
    let mut numbers = Vec::new();
    for e in errors {
        let rest = e.strip_prefix("line ").unwrap_or_else(|| panic!("error {e:?}"));
        let (n, what) = rest.split_once(": ").unwrap_or_else(|| panic!("error {e:?}"));
        let n: usize = n.parse().unwrap_or_else(|_| panic!("error {e:?}"));
        assert!(n >= 1 && n <= lines.len(), "line {n} of {}", lines.len());
        assert!(n > last, "errors out of order, or two for one line: {errors:?}");
        last = n;
        assert!(!what.is_empty(), "error {e:?}");
        let line = lines[n - 1].trim_matches(BLANK);
        assert!(
            !line.is_empty() && !line.starts_with('#'),
            "an error for a blank or comment line {n}: {e:?}"
        );
        numbers.push(n);
    }
    assert_eq!(numbers, expected_errors(text), "errors on these lines: {errors:?}");
}

/// `-Q NAME=VALUE`: the expected quota, by an independent reading.
fn check_quota_arg(arg: &str) {
    let mut q = Quotas::default();
    let before = q.clone();
    let r = q.set_arg(arg);
    let expected = arg.split_once('=').and_then(|(name, v)| {
        let i = QUOTA_NAMES.iter().position(|n| *n == name)?;
        let ok = !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
        let n: u64 = if ok { v.parse().ok()? } else { return None };
        Some((i, n))
    });
    match (r, expected) {
        (Ok(()), Some((i, n))) => {
            let mut want = quota_values(&before);
            want[i] = Some(n);
            assert_eq!(quota_values(&q), want, "-Q {arg}");
        }
        (Err(e), None) => {
            assert!(e.starts_with("-Q "), "{e}");
            assert!(e.contains(arg), "{e}");
            assert_eq!(q, before, "-Q {arg} refused but changed the quotas");
        }
        (r, want) => panic!("-Q {arg:?}: {r:?}, expected {want:?}"),
    }
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

fn run_core(cf: &FileConfig) {
    let mut core = Core::new(core_config(cf), [1, 2]);
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
    // The daemon refuses a file that is not UTF-8: the valid prefix.
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&data[..e.valid_up_to()]).unwrap(),
    };
    let r = config::parse(text);
    assert_eq!(r, config::parse(text), "not deterministic");
    match &r {
        Ok(cf) => {
            assert_eq!(expected_errors(text), Vec::<usize>::new(), "accepted");
            check_settings(text, cf);
            run_core(cf);
        }
        Err(errors) => check_errors(text, errors),
    }
    // Each line as a -Q argument.
    for line in text.split('\n').take(16) {
        check_quota_arg(line);
    }
});
