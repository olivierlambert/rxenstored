// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! `rxenstored.conf`: one `KEY = VALUE` per line. Spaces, tabs and a
//! carriage return around the key and the value are ignored; a line that
//! is empty or starts with `#` is a comment. Every problem is an error,
//! reported with its line: a line without `=`, an unknown key, a key set
//! twice, a value that does not read.
//!
//! Values: whole numbers in decimal; `true` or `false`; decimal numbers
//! for the conflict keys; a log destination is `none`, `syslog:FACILITY`
//! or an absolute path. A quota of 0 is no limit, as in C xenstored
//! (`cx/domain.c:419`).

use std::path::PathBuf;
use std::time::Duration;
use xs_daemon::log::{Dest, Facility, Level, Output};

/// The quotas, by name: those C xenstored has (`cx/domain.c:56-110`) under
/// its names, the others under names of their own. 0: no limit. A quota
/// of N allows N (the core's native rules, `xs_core::Rules`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quotas {
    /// Nodes a domain other than 0 owns.
    pub nodes: u64,
    /// Watches of one connection.
    pub watches: u64,
    /// Open transactions of one connection.
    pub transactions: u64,
    /// Replies a connection has not read before no more of its requests
    /// are processed.
    pub outstanding: u64,
    /// Length of a path, or of its part below `/local/domain/<domid>/`.
    pub path_max: u64,
    /// Length of a node's value (C's `node-size` counts more).
    pub value_size: u64,
    /// Entries of the permissions a guest may give a node, its owner's
    /// included, as C counts them (`cx417/xenstored_core.c:1770-1773`).
    pub node_permissions: u64,
    /// Requests in one transaction (C's `transaction-nodes` counts nodes).
    pub transaction_requests: u64,
    /// Watch events a connection has not read before the guest causing
    /// more is held.
    pub watch_events: u64,
    /// Bytes a connection's open transactions may keep. None: one
    /// transaction of `transaction_requests` requests of the longest path
    /// and value.
    pub transaction_bytes: Option<u64>,
}

impl Default for Quotas {
    /// C xenstored 4.17's defaults (`cx417/xenstored_core.c:105-112`, the
    /// same upstream, `cx/domain.c:96-109`) where it has the quota; the
    /// core's otherwise (`xs_core::Config`). C's memory quota (2.5 MB a
    /// domain) and the 20 s after which it drops a guest's unsent watch
    /// events have no counterpart here.
    fn default() -> Self {
        let c = xs_core::Config::default();
        let n = |v: usize| v as u64;
        Quotas {
            // `quota_nb_entry_per_domain`
            nodes: 1000,
            // `quota_nb_watch_per_domain`
            watches: 128,
            // `quota_max_transaction`
            transactions: 10,
            // `quota_req_outstanding`
            outstanding: 20,
            // `quota_max_path_len`, XENSTORE_REL_PATH_MAX (`xs_wire.h:120`)
            path_max: 2048,
            // `quota_max_entry_size`
            value_size: 2048,
            // `quota_nb_perms_per_node`
            node_permissions: 5,
            // `quota_trans_nodes`
            transaction_requests: 1024,
            watch_events: n(c.watch_event_max),
            transaction_bytes: None,
        }
    }
}

/// The names `-Q` and the `quota-NAME` keys take.
pub const QUOTA_NAMES: &[&str] = &[
    "nodes",
    "watches",
    "transactions",
    "outstanding",
    "path-max",
    "value-size",
    "node-permissions",
    "transaction-requests",
    "watch-events",
    "transaction-bytes",
];

impl Quotas {
    fn get_mut(&mut self, name: &str) -> Option<&mut u64> {
        Some(match name {
            "nodes" => &mut self.nodes,
            "watches" => &mut self.watches,
            "transactions" => &mut self.transactions,
            "outstanding" => &mut self.outstanding,
            "path-max" => &mut self.path_max,
            "value-size" => &mut self.value_size,
            "node-permissions" => &mut self.node_permissions,
            "transaction-requests" => &mut self.transaction_requests,
            "watch-events" => &mut self.watch_events,
            "transaction-bytes" => self.transaction_bytes.insert(0),
            _ => return None,
        })
    }

    /// `NAME=VALUE`, as `-Q` takes it.
    pub fn set_arg(&mut self, arg: &str) -> Result<(), String> {
        let (name, value) = arg
            .split_once('=')
            .ok_or_else(|| format!("-Q {arg}: expected NAME=VALUE"))?;
        let n = whole(value).map_err(|e| format!("-Q {arg}: {e}"))?;
        *self
            .get_mut(name)
            .ok_or_else(|| format!("-Q {arg}: unknown quota '{name}' (known: {})", QUOTA_NAMES.join(", ")))? = n;
        Ok(())
    }

    /// Sets the core's limits.
    pub fn apply(&self, cfg: &mut xs_core::Config) {
        let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        let limit = |v: u64| if v == 0 { usize::MAX } else { size(v) };
        let some = |v: u64| (v != 0).then(|| size(v));
        cfg.quota_activate = true;
        cfg.entity_max = limit(self.nodes);
        cfg.watch_max = some(self.watches);
        cfg.transaction_max = some(self.transactions);
        cfg.outstanding_max = limit(self.outstanding);
        cfg.path_max = limit(self.path_max);
        cfg.value_max = limit(self.value_size);
        // The core counts the entries after its owner's.
        cfg.acl_max = match self.node_permissions {
            0 => usize::MAX,
            n => size(n).saturating_sub(1),
        };
        cfg.request_max = some(self.transaction_requests);
        cfg.watch_event_max = limit(self.watch_events);
        // Without a limit, the most one request may carry.
        let or_payload = |v: u64| if v == 0 { xs_wire::PAYLOAD_MAX } else { size(v) };
        cfg.transaction_bytes_max = match self.transaction_bytes {
            None => Some(xs_core::Config::transaction_bytes_for(
                some(self.transaction_requests).unwrap_or(1024),
                or_payload(self.path_max),
                or_payload(self.value_size),
            )),
            Some(n) => some(n),
        };
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileConfig {
    pub quotas: Quotas,
    /// The daemon log; None: none.
    pub log: Option<Dest>,
    pub log_level: Level,
    /// The access log; None: none.
    pub access_log: Option<Dest>,
    pub access_log_read_ops: bool,
    pub access_log_transactions_ops: bool,
    pub access_log_special_ops: bool,
    pub conflict_burst_limit: f64,
    pub conflict_max_history_seconds: f64,
    pub conflict_rate_limit_is_aggregate: bool,
    /// Seconds; 0: no periodic scan.
    pub ring_scan_interval: u64,
}

impl Default for FileConfig {
    fn default() -> Self {
        FileConfig {
            quotas: Quotas::default(),
            // Where C xenstored writes its own messages (`openlog` with
            // LOG_DAEMON, `cx/posix.c:349`) and XCP-ng's oxenstored.conf sends
            // oxenstored's.
            log: Some(Dest::Syslog(Facility::Daemon)),
            log_level: Level::Warn,
            // C xenstored writes none.
            access_log: None,
            access_log_read_ops: false,
            access_log_transactions_ops: false,
            access_log_special_ops: false,
            conflict_burst_limit: 5.0,
            conflict_max_history_seconds: 0.05,
            conflict_rate_limit_is_aggregate: true,
            ring_scan_interval: 20,
        }
    }
}

/// An access-log line in a file shows at most this many bytes, as
/// oxenstored's default `access-log-nb-chars`.
pub const ACCESS_LINE_MAX: i64 = 180;

impl FileConfig {
    /// The logs: no rotation by the daemon (SIGHUP reopens the files, for
    /// logrotate), access-log lines cut as oxenstored cuts them.
    pub fn log_settings(&self, access: bool, ident: &str) -> xs_daemon::log::Settings {
        let output = |dest: &Dest, nb_chars| Output {
            dest: dest.clone(),
            nb_files: 1,
            nb_lines: i64::MAX,
            nb_chars,
        };
        let switches = xs_core::log::Switches {
            read_ops: self.access_log_read_ops,
            transaction_ops: self.access_log_transactions_ops,
            special_ops: self.access_log_special_ops,
        };
        xs_daemon::log::Settings {
            daemon: self.log.as_ref().map(|d| (output(d, -1), self.log_level)),
            access: self
                .access_log
                .as_ref()
                .filter(|_| access)
                .map(|d| (output(d, ACCESS_LINE_MAX), switches)),
            ident: ident.into(),
            syslog_socket: "/dev/log".into(),
            queue_lines: xs_daemon::log::QUEUE_LINES,
            queue_bytes: xs_daemon::log::QUEUE_BYTES,
        }
    }

    pub fn apply_conflicts(&self, cfg: &mut xs_core::Config) {
        cfg.conflict_burst_limit = self.conflict_burst_limit;
        // Checked finite and not negative when read: only a value too large
        // for a Duration does not convert.
        cfg.conflict_max_history =
            Duration::try_from_secs_f64(self.conflict_max_history_seconds).unwrap_or(Duration::MAX);
        cfg.conflict_rate_limit_is_aggregate = self.conflict_rate_limit_is_aggregate;
    }

    pub fn ring_scan(&self) -> Option<Duration> {
        (self.ring_scan_interval != 0).then(|| Duration::from_secs(self.ring_scan_interval))
    }
}

/// oxenstored.conf's keys, and the key of this file that does the same,
/// if any: said in the error for such a key.
const OXENSTORED_KEYS: &[(&str, Option<&str>)] = &[
    ("quota-maxentity", Some("quota-nodes")),
    ("quota-maxwatch", Some("quota-watches")),
    ("quota-transaction", Some("quota-transactions")),
    ("quota-maxoutstanding", Some("quota-outstanding")),
    ("quota-maxsize", Some("quota-value-size")),
    ("quota-maxrequests", Some("quota-transaction-requests")),
    ("quota-maxwatchevents", Some("quota-watch-events")),
    ("xenstored-log-file", Some("log")),
    ("xenstored-log-level", Some("log-level")),
    ("access-log-file", Some("access-log")),
    ("pid-file", Some("the --pid-file option")),
    ("quota-activate", None),
    ("perms-activate", None),
    ("perms-watch-activate", None),
    ("merge-activate", None),
    ("gc-max-overhead", None),
    ("test-eagain", None),
    ("persistent", None),
    ("allow-debug", None),
    ("xenstored-kva", None),
    ("xenstored-port", None),
    ("xenstored-log-nb-files", None),
    ("xenstored-log-nb-lines", None),
    ("xenstored-log-nb-chars", None),
    ("access-log-nb-files", None),
    ("access-log-nb-lines", None),
    ("access-log-nb-chars", None),
];

fn unknown(key: &str) -> String {
    match OXENSTORED_KEYS.iter().find(|(k, _)| *k == key) {
        Some((_, Some(native))) => format!("unknown key {key} (an oxenstored.conf key: here, {native})"),
        Some((_, None)) => format!(
            "unknown key {key} (an oxenstored.conf key, which this file does not have; oxenstored.conf is read with --compat=oxenstored)"
        ),
        None => format!("unknown key {key}"),
    }
}

fn whole(v: &str) -> Result<u64, String> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("'{v}' is not a whole number"));
    }
    v.parse().map_err(|_| format!("'{v}' is too large"))
}

fn boolean(v: &str) -> Result<bool, String> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("'{v}' is not true or false")),
    }
}

/// A decimal number, finite and not negative.
fn decimal(v: &str) -> Result<f64, String> {
    let ok = !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    match v.parse::<f64>() {
        Ok(x) if ok && x.is_finite() => Ok(x),
        _ => Err(format!("'{v}' is not a decimal number")),
    }
}

fn level(v: &str) -> Result<Level, String> {
    Ok(match v {
        "debug" => Level::Debug,
        "info" => Level::Info,
        "warn" => Level::Warn,
        "error" => Level::Error,
        _ => return Err(format!("'{v}' is not a level (debug, info, warn, error)")),
    })
}

/// `none`, `syslog:FACILITY` or an absolute path.
fn dest(v: &str) -> Result<Option<Dest>, String> {
    if v == "none" {
        return Ok(None);
    }
    if let Some(name) = v.strip_prefix("syslog:") {
        let f = match name {
            "auth" => Facility::Auth,
            "authpriv" => Facility::Authpriv,
            "cron" => Facility::Cron,
            "daemon" => Facility::Daemon,
            "ftp" => Facility::Ftp,
            "kern" => Facility::Kern,
            "lpr" => Facility::Lpr,
            "mail" => Facility::Mail,
            "news" => Facility::News,
            "syslog" => Facility::Syslog,
            "user" => Facility::User,
            "uucp" => Facility::Uucp,
            _ => match name.strip_prefix("local").and_then(|n| n.parse::<u8>().ok()) {
                Some(n) if n <= 7 && name.len() == 6 => Facility::Local(n),
                _ => return Err(format!("'{name}' is not a syslog facility")),
            },
        };
        return Ok(Some(Dest::Syslog(f)));
    }
    if !v.starts_with('/') {
        return Err(format!("'{v}' is not none, syslog:FACILITY or an absolute path"));
    }
    Ok(Some(Dest::File(PathBuf::from(v))))
}

/// Why a line is refused: its key, or its value.
enum Bad {
    Key(String),
    Value(String),
}

fn set(cf: &mut FileConfig, key: &str, v: &str) -> Result<(), Bad> {
    if let Some(slot) = key.strip_prefix("quota-").and_then(|name| cf.quotas.get_mut(name)) {
        *slot = whole(v).map_err(Bad::Value)?;
        return Ok(());
    }
    let r = match key {
        "log" => dest(v).map(|d| cf.log = d),
        "log-level" => level(v).map(|l| cf.log_level = l),
        "access-log" => dest(v).map(|d| cf.access_log = d),
        "access-log-read-ops" => boolean(v).map(|b| cf.access_log_read_ops = b),
        "access-log-transactions-ops" => boolean(v).map(|b| cf.access_log_transactions_ops = b),
        "access-log-special-ops" => boolean(v).map(|b| cf.access_log_special_ops = b),
        "conflict-burst-limit" => decimal(v)
            .ok()
            .filter(|x| *x > 0.0)
            .map(|x| cf.conflict_burst_limit = x)
            .ok_or_else(|| format!("'{v}' is not a decimal number above 0")),
        "conflict-max-history-seconds" => decimal(v).map(|x| cf.conflict_max_history_seconds = x),
        "conflict-rate-limit-is-aggregate" => boolean(v).map(|b| cf.conflict_rate_limit_is_aggregate = b),
        "ring-scan-interval" => whole(v).map(|n| cf.ring_scan_interval = n),
        _ => return Err(Bad::Key(unknown(key))),
    };
    r.map_err(Bad::Value)
}

const BLANK: &[char] = &[' ', '\t', '\r'];

/// Parses a whole file; the errors come in file order, each as
/// `line N: ...`.
pub fn parse(text: &str) -> Result<FileConfig, Vec<String>> {
    let mut cf = FileConfig::default();
    let mut errors = Vec::new();
    let mut seen: Vec<(String, usize)> = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let n = i + 1;
        let line = raw.trim_matches(BLANK);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            errors.push(format!("line {n}: expected KEY = VALUE"));
            continue;
        };
        let (key, value) = (key.trim_matches(BLANK), value.trim_matches(BLANK));
        if let Some((_, first)) = seen.iter().find(|(k, _)| k == key) {
            errors.push(format!("line {n}: {key} is set twice (first on line {first})"));
            continue;
        }
        seen.push((key.into(), n));
        match set(&mut cf, key, value) {
            Ok(()) => {}
            Err(Bad::Key(e)) => errors.push(format!("line {n}: {e}")),
            Err(Bad::Value(e)) => errors.push(format!("line {n}: {key}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(cf)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_too_long_to_be_finite_is_refused() {
        let v = "9".repeat(400);
        assert!(decimal(&v).is_err());
        assert_eq!(decimal(&"9".repeat(300)).map(f64::is_finite), Ok(true));
    }

    fn errors(text: &str) -> Vec<String> {
        parse(text).unwrap_err()
    }

    #[test]
    fn defaults() {
        let d = FileConfig::default();
        assert_eq!(parse("").unwrap(), d);
        assert_eq!(parse("\n# only a comment\n\n").unwrap(), d);
        assert_eq!(d.log, Some(Dest::Syslog(Facility::Daemon)));
        assert_eq!((d.log_level, d.access_log.as_ref()), (Level::Warn, None));
        assert!(!d.access_log_read_ops && !d.access_log_transactions_ops && !d.access_log_special_ops);
        assert_eq!(d.ring_scan(), Some(Duration::from_secs(20)));
        // The quotas are C xenstored 4.17's (`cx417/xenstored_core.c:105-112`),
        // the core's for those C does not have.
        let q = &d.quotas;
        assert_eq!(
            (q.nodes, q.watches, q.transactions, q.outstanding, q.path_max),
            (1000, 128, 10, 20, 2048)
        );
        assert_eq!(
            (
                q.value_size,
                q.node_permissions,
                q.transaction_requests,
                q.watch_events,
                q.transaction_bytes
            ),
            (2048, 5, 1024, 1024, None)
        );
        let mut c = xs_core::Config {
            quota_activate: false,
            ..xs_core::Config::default()
        };
        q.apply(&mut c);
        let core = xs_core::Config::default();
        assert!(c.quota_activate);
        assert_eq!(
            (
                c.entity_max,
                c.watch_max,
                c.transaction_max,
                c.outstanding_max,
                c.path_max
            ),
            (1000, Some(128), Some(10), 20, 2048)
        );
        // Five entries, its owner's and four more.
        assert_eq!(
            (
                c.value_max,
                c.acl_max,
                c.request_max,
                c.watch_event_max,
                c.transaction_bytes_max
            ),
            (2048, 4, Some(1024), core.watch_event_max, core.transaction_bytes_max)
        );
        let mut c = xs_core::Config::default();
        d.apply_conflicts(&mut c);
        assert_eq!(
            (
                c.conflict_burst_limit,
                c.conflict_max_history,
                c.conflict_rate_limit_is_aggregate
            ),
            (5.0, Duration::from_millis(50), true)
        );
    }

    #[test]
    fn every_key() {
        let text = "\
quota-nodes = 1
quota-watches = 2
quota-transactions = 3
quota-outstanding = 4
quota-path-max = 5
quota-value-size = 6
quota-node-permissions = 7
quota-transaction-requests = 8
quota-watch-events = 9
quota-transaction-bytes = 10
log = /var/log/xen/rxenstored.log
log-level = debug
access-log = syslog:local3
access-log-read-ops = true
access-log-transactions-ops = true
access-log-special-ops = true
conflict-burst-limit = 2.5
conflict-max-history-seconds = 1.5
conflict-rate-limit-is-aggregate = false
ring-scan-interval = 0
";
        let cf = parse(text).unwrap();
        let expected = FileConfig {
            quotas: Quotas {
                nodes: 1,
                watches: 2,
                transactions: 3,
                outstanding: 4,
                path_max: 5,
                value_size: 6,
                node_permissions: 7,
                transaction_requests: 8,
                watch_events: 9,
                transaction_bytes: Some(10),
            },
            log: Some(Dest::File("/var/log/xen/rxenstored.log".into())),
            log_level: Level::Debug,
            access_log: Some(Dest::Syslog(Facility::Local(3))),
            access_log_read_ops: true,
            access_log_transactions_ops: true,
            access_log_special_ops: true,
            conflict_burst_limit: 2.5,
            conflict_max_history_seconds: 1.5,
            conflict_rate_limit_is_aggregate: false,
            ring_scan_interval: 0,
        };
        assert_eq!(cf, expected);
        assert_eq!(text.lines().count(), 20, "every key once");
        assert_eq!(QUOTA_NAMES.len(), 10);
        for name in QUOTA_NAMES {
            assert!(text.contains(&format!("quota-{name} = ")), "{name}");
        }
        // And on to the core and the logs.
        let mut c = xs_core::Config::default();
        cf.quotas.apply(&mut c);
        cf.apply_conflicts(&mut c);
        assert_eq!(
            (
                c.entity_max,
                c.watch_max,
                c.transaction_max,
                c.outstanding_max,
                c.path_max
            ),
            (1, Some(2), Some(3), 4, 5)
        );
        assert_eq!(
            (
                c.value_max,
                c.acl_max,
                c.request_max,
                c.watch_event_max,
                c.transaction_bytes_max
            ),
            (6, 6, Some(8), 9, Some(10))
        );
        assert_eq!(
            (
                c.conflict_burst_limit,
                c.conflict_max_history,
                c.conflict_rate_limit_is_aggregate
            ),
            (2.5, Duration::from_millis(1500), false)
        );
        assert_eq!(cf.ring_scan(), None);
        let s = cf.log_settings(true, "rx");
        let out = |dest, nb_chars| Output {
            dest,
            nb_files: 1,
            nb_lines: i64::MAX,
            nb_chars,
        };
        assert_eq!(
            s.daemon,
            Some((out(Dest::File("/var/log/xen/rxenstored.log".into()), -1), Level::Debug))
        );
        assert_eq!(
            s.access,
            Some((
                out(Dest::Syslog(Facility::Local(3)), 180),
                xs_core::log::Switches {
                    read_ops: true,
                    transaction_ops: true,
                    special_ops: true
                }
            ))
        );
        assert_eq!((s.ident.as_str(), s.syslog_socket.to_str()), ("rx", Some("/dev/log")));
        assert_eq!(
            (s.queue_lines, s.queue_bytes),
            (xs_daemon::log::QUEUE_LINES, xs_daemon::log::QUEUE_BYTES)
        );
        // --no-access-log.
        assert_eq!(cf.log_settings(false, "rx").access, None);
        let none = parse("log = none\naccess-log = none\n")
            .unwrap()
            .log_settings(true, "rx");
        assert_eq!((none.daemon, none.access), (None, None));
    }

    #[test]
    fn a_quota_of_0_is_no_limit() {
        let mut q = Quotas {
            nodes: 0,
            watches: 0,
            transactions: 0,
            outstanding: 0,
            path_max: 0,
            value_size: 0,
            node_permissions: 0,
            transaction_requests: 0,
            watch_events: 0,
            transaction_bytes: Some(0),
        };
        let mut c = xs_core::Config::default();
        q.apply(&mut c);
        let m = usize::MAX;
        assert_eq!(
            (
                c.entity_max,
                c.watch_max,
                c.transaction_max,
                c.outstanding_max,
                c.path_max
            ),
            (m, None, None, m, m)
        );
        assert_eq!(
            (
                c.value_max,
                c.acl_max,
                c.request_max,
                c.watch_event_max,
                c.transaction_bytes_max
            ),
            (m, m, None, m, None)
        );
        // Derived without the others' limits: 1,024 requests of the most
        // a request carries.
        q.transaction_bytes = None;
        q.apply(&mut c);
        assert_eq!(c.transaction_bytes_max, Some(1024 * 2 * xs_wire::PAYLOAD_MAX));
        q.transaction_requests = 3;
        q.path_max = 5;
        q.value_size = 7;
        q.apply(&mut c);
        assert_eq!(c.transaction_bytes_max, Some(36));
        q.nodes = u64::MAX;
        q.apply(&mut c);
        assert_eq!(c.entity_max, usize::try_from(u64::MAX).unwrap_or(usize::MAX));
        // Its owner's entry alone, or one more.
        for (n, acl) in [(1, 0), (2, 1), (u64::MAX, usize::MAX - 1)] {
            q.node_permissions = n;
            q.apply(&mut c);
            assert_eq!(c.acl_max, acl, "{n}");
        }
    }

    #[test]
    fn quotas_from_the_command_line() {
        let mut q = Quotas::default();
        for name in QUOTA_NAMES {
            q.set_arg(&format!("{name}=7")).unwrap();
        }
        assert_eq!(
            q,
            Quotas {
                nodes: 7,
                watches: 7,
                transactions: 7,
                outstanding: 7,
                path_max: 7,
                value_size: 7,
                node_permissions: 7,
                transaction_requests: 7,
                watch_events: 7,
                transaction_bytes: Some(7),
            }
        );
        q.set_arg("nodes=0").unwrap();
        assert_eq!(q.nodes, 0);
        for (arg, e) in [
            ("nodes", "-Q nodes: expected NAME=VALUE"),
            ("nodes=", "-Q nodes=: '' is not a whole number"),
            ("nodes=-1", "-Q nodes=-1: '-1' is not a whole number"),
            ("nodes=1k", "-Q nodes=1k: '1k' is not a whole number"),
            (
                "nodes=99999999999999999999",
                "-Q nodes=99999999999999999999: '99999999999999999999' is too large",
            ),
            (
                "memory=1",
                "-Q memory=1: unknown quota 'memory' (known: nodes, watches, transactions, outstanding, path-max, value-size, node-permissions, transaction-requests, watch-events, transaction-bytes)",
            ),
        ] {
            assert_eq!(q.set_arg(arg), Err(e.to_string()), "{arg}");
        }
    }

    #[test]
    fn grammar() {
        let cf = parse("  # indented comment\n\tquota-nodes\t=\t5 \r\nlog-level=info\r\nlog = /a = b\n").unwrap();
        assert_eq!((cf.quotas.nodes, cf.log_level), (5, Level::Info));
        assert_eq!(cf.log, Some(Dest::File("/a = b".into())), "split at the first '='");
        assert_eq!(
            errors("quota-nodes = 1\nnot a setting\n= 3\nquota-nodes = 2\nlog-level = loud\nlog = x # comment\n"),
            [
                "line 2: expected KEY = VALUE",
                "line 3: unknown key ",
                "line 4: quota-nodes is set twice (first on line 1)",
                "line 5: log-level: 'loud' is not a level (debug, info, warn, error)",
                "line 6: log: 'x # comment' is not none, syslog:FACILITY or an absolute path",
            ]
        );
    }

    #[test]
    fn values_that_do_not_read() {
        for (text, e) in [
            ("quota-nodes = ", "quota-nodes: '' is not a whole number"),
            ("quota-nodes = +1", "quota-nodes: '+1' is not a whole number"),
            ("quota-nodes = 0x10", "quota-nodes: '0x10' is not a whole number"),
            ("quota-nodes = 1_000", "quota-nodes: '1_000' is not a whole number"),
            (
                "ring-scan-interval = -1",
                "ring-scan-interval: '-1' is not a whole number",
            ),
            (
                "access-log-read-ops = yes",
                "access-log-read-ops: 'yes' is not true or false",
            ),
            (
                "conflict-rate-limit-is-aggregate = 1",
                "conflict-rate-limit-is-aggregate: '1' is not true or false",
            ),
            (
                "access-log-transactions-ops = True",
                "access-log-transactions-ops: 'True' is not true or false",
            ),
            (
                "access-log-special-ops = ",
                "access-log-special-ops: '' is not true or false",
            ),
            (
                "conflict-burst-limit = 0",
                "conflict-burst-limit: '0' is not a decimal number above 0",
            ),
            (
                "conflict-burst-limit = inf",
                "conflict-burst-limit: 'inf' is not a decimal number above 0",
            ),
            (
                "conflict-max-history-seconds = -1",
                "conflict-max-history-seconds: '-1' is not a decimal number",
            ),
            (
                "conflict-max-history-seconds = nan",
                "conflict-max-history-seconds: 'nan' is not a decimal number",
            ),
            (
                "conflict-max-history-seconds = 1e3",
                "conflict-max-history-seconds: '1e3' is not a decimal number",
            ),
            (
                "conflict-max-history-seconds = 1..0",
                "conflict-max-history-seconds: '1..0' is not a decimal number",
            ),
            ("log = syslog:local8", "log: 'local8' is not a syslog facility"),
            (
                "access-log = syslog:local07",
                "access-log: 'local07' is not a syslog facility",
            ),
            (
                "access-log = var/log/a",
                "access-log: 'var/log/a' is not none, syslog:FACILITY or an absolute path",
            ),
            ("log = ", "log: '' is not none, syslog:FACILITY or an absolute path"),
            (
                "log-level = null",
                "log-level: 'null' is not a level (debug, info, warn, error)",
            ),
        ] {
            assert_eq!(errors(text), [format!("line 1: {e}")], "{text}");
        }
        // Accepted forms.
        let cf = parse("conflict-max-history-seconds = 0\nconflict-burst-limit = .5\n").unwrap();
        assert_eq!((cf.conflict_max_history_seconds, cf.conflict_burst_limit), (0.0, 0.5));
        let mut c = xs_core::Config::default();
        cf.apply_conflicts(&mut c);
        assert_eq!(c.conflict_max_history, Duration::ZERO);
        let cf = parse("conflict-max-history-seconds = 99999999999999999999999\n").unwrap();
        cf.apply_conflicts(&mut c);
        assert_eq!(c.conflict_max_history, Duration::MAX, "beyond a Duration");
        use Facility::*;
        for (name, f) in [
            ("auth", Auth),
            ("authpriv", Authpriv),
            ("cron", Cron),
            ("daemon", Daemon),
            ("ftp", Ftp),
            ("kern", Kern),
            ("local0", Local(0)),
            ("local7", Local(7)),
            ("lpr", Lpr),
            ("mail", Mail),
            ("news", News),
            ("syslog", Syslog),
            ("user", User),
            ("uucp", Uucp),
        ] {
            assert_eq!(dest(&format!("syslog:{name}")), Ok(Some(Dest::Syslog(f))));
        }
        for (name, l) in [
            ("debug", Level::Debug),
            ("info", Level::Info),
            ("warn", Level::Warn),
            ("error", Level::Error),
        ] {
            assert_eq!(level(name), Ok(l));
        }
    }

    #[test]
    fn oxenstored_keys_say_what_to_use() {
        assert_eq!(
            errors("quota-maxentity = 8192\nquota-transaction = 10\npersistent = false\nfrob = 1\n"),
            [
                "line 1: unknown key quota-maxentity (an oxenstored.conf key: here, quota-nodes)",
                "line 2: unknown key quota-transaction (an oxenstored.conf key: here, quota-transactions)",
                "line 3: unknown key persistent (an oxenstored.conf key, which this file does not have; oxenstored.conf is read with --compat=oxenstored)",
                "line 4: unknown key frob",
            ]
        );
        // The keys of XCP-ng 8.3's oxenstored.conf: those this file shares
        // read, the others are refused with a hint.
        for key in [
            "pid-file",
            "test-eagain",
            "merge-activate",
            "conflict-burst-limit",
            "conflict-max-history-seconds",
            "conflict-rate-limit-is-aggregate",
            "perms-activate",
            "perms-watch-activate",
            "quota-activate",
            "quota-maxentity",
            "quota-maxsize",
            "quota-maxwatch",
            "quota-transaction",
            "quota-maxrequests",
            "quota-path-max",
            "quota-maxoutstanding",
            "quota-maxwatchevents",
            "persistent",
            "xenstored-log-file",
            "access-log-file",
            "xenstored-kva",
            "xenstored-port",
        ] {
            let value = if key.ends_with("-aggregate") { "true" } else { "1" };
            let r = parse(&format!("{key} = {value}"));
            if key.starts_with("conflict-") || key == "quota-path-max" {
                assert!(r.is_ok(), "{key}: {r:?}");
            } else {
                assert!(r.unwrap_err()[0].contains("an oxenstored.conf key"), "{key}");
            }
        }
    }
}
