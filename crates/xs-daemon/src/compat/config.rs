// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! `oxenstored.conf`: the grammar of `ox/config.ml:56-75` and the keys
//! and defaults of `ox/xenstored.ml:91-139` (Xen 4.17).
//!
//! A line is trimmed of spaces and tabs; empty lines and lines starting
//! with `#` are skipped; the rest splits at the first `=` into a key
//! (trimmed at its end) and a value (trimmed at its start). A line without
//! `=` is skipped (oxenstored skips it silently; we report it). A later
//! line overrides an earlier one. Values are read as OCaml reads them
//! (`bool_of_string`, `int_of_string`, `float_of_string`); a value that
//! does not read leaves the default in place and is reported, as is an
//! unknown key.

use std::path::PathBuf;
use std::time::Duration;
use xs_core::perms::int_of_string;
pub use xs_daemon::log::{Dest as LogDest, Facility, Level as LogLevel};
use xs_daemon::log::{Output, Settings};

/// Every key of 4.17, with its default when absent. Fields are the keys,
/// with `_` for `-`.
#[derive(Debug, Clone, PartialEq)]
pub struct FileConfig {
    pub merge_activate: bool,
    pub conflict_burst_limit: f64,
    pub conflict_max_history_seconds: f64,
    pub conflict_rate_limit_is_aggregate: bool,
    pub perms_activate: bool,
    pub perms_watch_activate: bool,
    pub quota_activate: bool,
    pub quota_maxwatch: i64,
    pub quota_transaction: i64,
    pub quota_maxentity: i64,
    pub quota_maxsize: i64,
    pub quota_maxrequests: i64,
    pub quota_maxoutstanding: i64,
    pub quota_maxwatchevents: i64,
    pub quota_path_max: i64,
    /// `quota-transaction-bytes`, rxenstored's own: the bytes a guest's
    /// open transactions may keep (`xs_core::Config::transaction_bytes_max`).
    /// None (the key is absent, as in every `oxenstored.conf`): derived from
    /// the other quotas; negative: no limit.
    pub quota_transaction_bytes: Option<i64>,
    pub gc_max_overhead: i64,
    pub test_eagain: bool,
    pub persistent: bool,
    pub xenstored_log_file: LogDest,
    pub xenstored_log_level: LogLevel,
    pub xenstored_log_nb_files: i64,
    pub xenstored_log_nb_lines: i64,
    pub xenstored_log_nb_chars: i64,
    pub access_log_file: LogDest,
    pub access_log_nb_files: i64,
    pub access_log_nb_lines: i64,
    pub access_log_nb_chars: i64,
    pub access_log_read_ops: bool,
    pub access_log_transactions_ops: bool,
    pub access_log_special_ops: bool,
    pub allow_debug: bool,
    pub ring_scan_interval: i64,
    /// Empty: none (oxenstored tries to write "" and ignores the failure).
    pub pid_file: PathBuf,
    pub xenstored_kva: PathBuf,
    pub xenstored_port: PathBuf,
}

pub const DEFAULT_PID_FILE: &str = "/var/run/xen/xenstored.pid";

impl Default for FileConfig {
    /// The defaults of the code (`ox/define.ml`, `ox/quota.ml`,
    /// `ox/logging.ml`, ...), not those of the shipped file. The two
    /// device paths are empty in the code and set by configure; they
    /// default here to what configure sets on Linux.
    fn default() -> Self {
        FileConfig {
            merge_activate: true,
            conflict_burst_limit: 5.0,
            conflict_max_history_seconds: 0.05,
            conflict_rate_limit_is_aggregate: true,
            perms_activate: true,
            perms_watch_activate: true,
            quota_activate: true,
            quota_maxwatch: 100,
            quota_transaction: 10,
            quota_maxentity: 1000,
            quota_maxsize: 2048,
            quota_maxrequests: 1024,
            quota_maxoutstanding: 1024,
            quota_maxwatchevents: 1024,
            quota_path_max: 2048,
            quota_transaction_bytes: None,
            gc_max_overhead: 120,
            test_eagain: false,
            persistent: false,
            xenstored_log_file: LogDest::File("/var/log/xen/xenstored.log".into()),
            xenstored_log_level: LogLevel::Warn,
            xenstored_log_nb_files: 10,
            xenstored_log_nb_lines: 13215,
            xenstored_log_nb_chars: -1,
            access_log_file: LogDest::File("/var/log/xen/xenstored-access.log".into()),
            access_log_nb_files: 20,
            access_log_nb_lines: 13215,
            access_log_nb_chars: 180,
            access_log_read_ops: false,
            access_log_transactions_ops: false,
            access_log_special_ops: false,
            allow_debug: false,
            ring_scan_interval: 20,
            pid_file: DEFAULT_PID_FILE.into(),
            xenstored_kva: "/proc/xen/xsd_kva".into(),
            xenstored_port: "/proc/xen/xsd_port".into(),
        }
    }
}

impl FileConfig {
    /// Sets the core's quotas from the `quota-*` keys, read as oxenstored
    /// reads them (`ox/connection.ml:278, 383`, `ox/transaction.ml:151`):
    /// `quota-maxwatch` and `quota-transaction` limit nothing unless
    /// positive, `quota-maxrequests` unless not negative; a negative node,
    /// reply or event limit acts as 0. (`quota-maxsize` and
    /// `quota-path-max` are applied where the configuration is built.)
    pub fn apply_quotas(&self, cfg: &mut xs_core::Config) {
        let count = |v: i64| usize::try_from(v).unwrap_or(0);
        cfg.quota_activate = self.quota_activate;
        cfg.entity_max = count(self.quota_maxentity);
        cfg.watch_max = (self.quota_maxwatch > 0).then(|| count(self.quota_maxwatch));
        cfg.transaction_max = (self.quota_transaction > 0).then(|| count(self.quota_transaction));
        cfg.request_max = (self.quota_maxrequests >= 0).then(|| count(self.quota_maxrequests));
        cfg.outstanding_max = count(self.quota_maxoutstanding);
        cfg.watch_event_max = count(self.quota_maxwatchevents);
        // Absent: what one transaction of `quota-maxrequests` requests (the
        // code's 1,024 if there is no limit) of the longest path and value
        // needs: 3 MiB with XCP-ng 8.3's file.
        let requests = if self.quota_maxrequests >= 0 {
            self.quota_maxrequests
        } else {
            1024
        };
        cfg.transaction_bytes_max = match self.quota_transaction_bytes {
            None => Some(xs_core::Config::transaction_bytes_for(
                count(requests),
                count(self.quota_path_max),
                count(self.quota_maxsize),
            )),
            Some(n) => (n >= 0).then(|| count(n)),
        };
    }

    /// The XSA-206 keys, as the core takes them. A period that is no
    /// duration (negative, NaN) is none: credit at every pass.
    pub fn apply_conflicts(&self, cfg: &mut xs_core::Config) {
        let secs = self.conflict_max_history_seconds;
        cfg.conflict_burst_limit = self.conflict_burst_limit;
        cfg.conflict_max_history =
            Duration::try_from_secs_f64(secs).unwrap_or(if secs > 0.0 { Duration::MAX } else { Duration::ZERO });
        cfg.conflict_rate_limit_is_aggregate = self.conflict_rate_limit_is_aggregate;
    }

    /// The logs as oxenstored sets them up (`ox/logging.ml:175-184,
    /// 278-287`): a daemon log in a file only with a level other than
    /// `null` and `xenstored-log-nb-files` positive, an access log in a
    /// file only with `access-log-nb-files` positive and without
    /// `--no-access-log` (`access`); a syslog destination always.
    pub fn log_settings(&self, access: bool, ident: &str) -> Settings {
        let file = |d: &LogDest| matches!(d, LogDest::File(_));
        let output = |dest: &LogDest, nb_files, nb_lines, nb_chars| Output {
            dest: dest.clone(),
            nb_files,
            nb_lines,
            nb_chars,
        };
        let daemon_on = !file(&self.xenstored_log_file)
            || (self.xenstored_log_level != LogLevel::Null && self.xenstored_log_nb_files > 0);
        let access_on = access && (!file(&self.access_log_file) || self.access_log_nb_files > 0);
        let switches = xs_core::log::Switches {
            read_ops: self.access_log_read_ops,
            transaction_ops: self.access_log_transactions_ops,
            special_ops: self.access_log_special_ops,
        };
        Settings {
            daemon: daemon_on.then(|| {
                (
                    output(
                        &self.xenstored_log_file,
                        self.xenstored_log_nb_files,
                        self.xenstored_log_nb_lines,
                        self.xenstored_log_nb_chars,
                    ),
                    self.xenstored_log_level,
                )
            }),
            access: access_on.then(|| {
                (
                    output(
                        &self.access_log_file,
                        self.access_log_nb_files,
                        self.access_log_nb_lines,
                        self.access_log_nb_chars,
                    ),
                    switches,
                )
            }),
            ident: ident.into(),
            syslog_socket: "/dev/log".into(),
            queue_lines: xs_daemon::log::QUEUE_LINES,
            queue_bytes: xs_daemon::log::QUEUE_BYTES,
        }
    }

    /// A warning for each key set to a value that rxenstored does not
    /// honour. They are accepted, as oxenstored accepts them, so that its
    /// file still reads; at their defaults they change nothing.
    pub fn not_honoured(&self) -> Vec<String> {
        let d = FileConfig::default();
        let mut w = Vec::new();
        if self.merge_activate != d.merge_activate {
            w.push(format!(
                "config: merge-activate = {} is not honoured: transactions commit as with the default",
                self.merge_activate
            ));
        }
        if self.gc_max_overhead != d.gc_max_overhead {
            w.push(format!(
                "config: gc-max-overhead = {} is not honoured: it tunes OCaml's garbage collector",
                self.gc_max_overhead
            ));
        }
        if self.test_eagain != d.test_eagain {
            w.push(format!(
                "config: test-eagain = {} is not honoured: no commit fails for testing",
                self.test_eagain
            ));
        }
        if self.allow_debug != d.allow_debug {
            w.push(format!(
                "config: allow-debug = {} is not honoured: rxenstored never lets a guest use CONTROL (debug) commands, only domain 0 and sockets",
                self.allow_debug
            ));
        }
        w
    }

    /// `ring-scan-interval` as the event loop takes it. oxenstored scans
    /// when it is `>= 0` (`ox/xenstored.ml:502`), from its periodic
    /// operations, which run at most every 15 s (`period_ops_interval`,
    /// lines 541, 579-582): negative disables the scan, and 0 is every
    /// 15 s there, so here too. Other values are taken as they are; below
    /// 15 s that is more often than oxenstored, which only helps a lazy
    /// guest. Clamped to 2^32 - 1 s, which is never.
    pub fn ring_scan(&self) -> Option<Duration> {
        match self.ring_scan_interval {
            n if n < 0 => None,
            0 => Some(Duration::from_secs(15)),
            n => Some(Duration::from_secs(n.min(u32::MAX.into()) as u64)),
        }
    }
}

/// What kind of trouble a line is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trouble {
    /// No `=`: skipped.
    NoEquals,
    UnknownKey,
    /// The value does not read as the key's type.
    BadValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// From 1.
    pub line: usize,
    pub key: String,
    pub trouble: Trouble,
    /// As oxenstored words it: "unknown key", "expect int arg", ...
    pub what: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.trouble {
            Trouble::NoEquals => write!(f, "config: line {}: no '=', ignored", self.line),
            Trouble::UnknownKey => write!(f, "config: line {}: unknown key {}", self.line, self.key),
            Trouble::BadValue => write!(f, "config: line {}: {}: {}", self.line, self.key, self.what),
        }
    }
}

const BLANK: &[char] = &[' ', '\t'];

/// Parses a whole file; the problems come in file order.
pub fn parse(text: &str) -> (FileConfig, Vec<Problem>) {
    let mut cf = FileConfig::default();
    let mut problems = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.trim_matches(BLANK);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let problem = |key: &str, trouble, what: &str| Problem {
            line: i + 1,
            key: key.into(),
            trouble,
            what: what.into(),
        };
        let Some((key, value)) = line.split_once('=') else {
            problems.push(problem("", Trouble::NoEquals, ""));
            continue;
        };
        let (key, value) = (key.trim_end_matches(BLANK), value.trim_start_matches(BLANK));
        match set(&mut cf, key, value) {
            Ok(()) => {}
            Err(None) => problems.push(problem(key, Trouble::UnknownKey, "unknown key")),
            Err(Some(what)) => problems.push(problem(key, Trouble::BadValue, &what)),
        }
    }
    (cf, problems)
}

/// Sets one key: Err(None) if unknown, Err(Some(why)) if its value does not read.
fn set(cf: &mut FileConfig, key: &str, v: &str) -> Result<(), Option<String>> {
    let b = |r: &mut bool| {
        ocaml_bool(v)
            .map(|x| *r = x)
            .ok_or_else(|| Some("expect bool arg".to_string()))
    };
    let i = |r: &mut i64| {
        int_of_string(v.as_bytes())
            .map(|x| *r = x)
            .ok_or_else(|| Some("expect int arg".to_string()))
    };
    let f = |r: &mut f64| {
        ocaml_float(v)
            .map(|x| *r = x)
            .ok_or_else(|| Some("expect float arg".to_string()))
    };
    match key {
        "merge-activate" => b(&mut cf.merge_activate),
        "conflict-burst-limit" => f(&mut cf.conflict_burst_limit),
        "conflict-max-history-seconds" => f(&mut cf.conflict_max_history_seconds),
        "conflict-rate-limit-is-aggregate" => b(&mut cf.conflict_rate_limit_is_aggregate),
        "perms-activate" => b(&mut cf.perms_activate),
        "perms-watch-activate" => b(&mut cf.perms_watch_activate),
        "quota-activate" => b(&mut cf.quota_activate),
        "quota-maxwatch" => i(&mut cf.quota_maxwatch),
        "quota-transaction" => i(&mut cf.quota_transaction),
        "quota-maxentity" => i(&mut cf.quota_maxentity),
        "quota-maxsize" => i(&mut cf.quota_maxsize),
        "quota-maxrequests" => i(&mut cf.quota_maxrequests),
        "quota-maxoutstanding" => i(&mut cf.quota_maxoutstanding),
        "quota-maxwatchevents" => i(&mut cf.quota_maxwatchevents),
        "quota-path-max" => i(&mut cf.quota_path_max),
        "quota-transaction-bytes" => {
            let mut n = 0;
            i(&mut n).map(|()| cf.quota_transaction_bytes = Some(n))
        }
        "gc-max-overhead" => i(&mut cf.gc_max_overhead),
        "test-eagain" => b(&mut cf.test_eagain),
        "persistent" => b(&mut cf.persistent),
        "xenstored-log-file" => log_dest(v).map(|d| cf.xenstored_log_file = d),
        "xenstored-log-level" => log_level(v).map(|l| cf.xenstored_log_level = l),
        "xenstored-log-nb-files" => i(&mut cf.xenstored_log_nb_files),
        "xenstored-log-nb-lines" => i(&mut cf.xenstored_log_nb_lines),
        "xenstored-log-nb-chars" => i(&mut cf.xenstored_log_nb_chars),
        "access-log-file" => log_dest(v).map(|d| cf.access_log_file = d),
        "access-log-nb-files" => i(&mut cf.access_log_nb_files),
        "access-log-nb-lines" => i(&mut cf.access_log_nb_lines),
        "access-log-nb-chars" => i(&mut cf.access_log_nb_chars),
        "access-log-read-ops" => b(&mut cf.access_log_read_ops),
        "access-log-transactions-ops" => b(&mut cf.access_log_transactions_ops),
        "access-log-special-ops" => b(&mut cf.access_log_special_ops),
        "allow-debug" => b(&mut cf.allow_debug),
        "ring-scan-interval" => i(&mut cf.ring_scan_interval),
        "pid-file" => {
            cf.pid_file = v.into();
            Ok(())
        }
        "xenstored-kva" => {
            cf.xenstored_kva = v.into();
            Ok(())
        }
        "xenstored-port" => {
            cf.xenstored_port = v.into();
            Ok(())
        }
        _ => Err(None),
    }
}

fn log_dest(v: &str) -> Result<LogDest, Option<String>> {
    let Some(name) = v.strip_prefix("syslog:") else {
        return Ok(LogDest::File(v.into()));
    };
    let facility = match name {
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
            // As OCaml prints the exception it raises.
            _ => return Err(Some(format!("Syslog.Unknown_facility(\"{name}\")"))),
        },
    };
    Ok(LogDest::Syslog(facility))
}

fn log_level(v: &str) -> Result<LogLevel, Option<String>> {
    Ok(match v {
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        "null" => LogLevel::Null,
        _ => return Err(Some(format!("Logging.Unknown_level(\"{v}\")"))),
    })
}

/// `bool_of_string`.
fn ocaml_bool(v: &str) -> Option<bool> {
    match v {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// `float_of_string`, decimal forms: `_` is dropped, `nan`, `inf` and
/// `infinity` are accepted. (Hexadecimal floats are not.)
fn ocaml_float(v: &str) -> Option<f64> {
    v.replace('_', "").parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// /etc/xen/oxenstored.conf as an XCP-ng 8.3 host has it.
    const HOST: &str = "\
# oxenstored configuration file

pid-file = /var/run/xen/xenstored.pid
test-eagain = false
merge-activate = true
conflict-burst-limit = 5.0
conflict-max-history-seconds = 0.05
conflict-rate-limit-is-aggregate = true
perms-activate = true
perms-watch-activate = true
quota-activate = true
quota-maxentity = 8192
quota-maxsize = 2048
quota-maxwatch = 512
quota-transaction = 10
quota-maxrequests = 1024
quota-path-max = 1024
quota-maxoutstanding = 1024
quota-maxwatchevents = 1024
persistent = false
# Logs
xenstored-log-file = syslog:daemon
access-log-file = syslog:local3
xenstored-kva = /proc/xen/xsd_kva
xenstored-port = /proc/xen/xsd_port
";

    #[test]
    fn the_host_file() {
        let (cf, problems) = parse(HOST);
        assert_eq!(problems, []);
        let expected = FileConfig {
            quota_maxentity: 8192,
            quota_maxwatch: 512,
            quota_path_max: 1024,
            xenstored_log_file: LogDest::Syslog(Facility::Daemon),
            access_log_file: LogDest::Syslog(Facility::Local(3)),
            ..FileConfig::default()
        };
        assert_eq!(cf, expected);
        // The host's file sets the keys rxenstored ignores to their defaults.
        assert_eq!(cf.not_honoured(), Vec::<String>::new());
    }

    #[test]
    fn keys_that_are_not_honoured_are_accepted_with_a_warning() {
        for (text, want) in [
            ("merge-activate = false", "config: merge-activate = false is not honoured: transactions commit as with the default"),
            ("gc-max-overhead = 50", "config: gc-max-overhead = 50 is not honoured: it tunes OCaml's garbage collector"),
            ("test-eagain = true", "config: test-eagain = true is not honoured: no commit fails for testing"),
            (
                "allow-debug = true",
                "config: allow-debug = true is not honoured: rxenstored never lets a guest use CONTROL (debug) commands, only domain 0 and sockets",
            ),
        ] {
            let (cf, problems) = parse(text);
            assert_eq!(problems, [], "{text}");
            assert_eq!(cf.not_honoured(), [want], "{text}");
        }
        // At their defaults, nothing; all four at once, one line each.
        let (cf, _) = parse("merge-activate = true\ngc-max-overhead = 120\ntest-eagain = false\nallow-debug = false\n");
        assert_eq!(cf.not_honoured(), Vec::<String>::new());
        let (cf, _) = parse("merge-activate = false\ngc-max-overhead = 0\ntest-eagain = true\nallow-debug = true\n");
        assert_eq!(cf.not_honoured().len(), 4);
    }

    #[test]
    fn the_logs_as_oxenstored_sets_them_up() {
        use xs_core::log::Switches;
        use xs_daemon::log::Output;
        let (cf, _) = parse(HOST);
        let s = cf.log_settings(true, "rxenstored");
        let out = |dest, nb_files, nb_lines, nb_chars| Output {
            dest,
            nb_files,
            nb_lines,
            nb_chars,
        };
        assert_eq!(
            s.daemon,
            Some((out(LogDest::Syslog(Facility::Daemon), 10, 13215, -1), LogLevel::Warn))
        );
        assert_eq!(
            s.access,
            Some((
                out(LogDest::Syslog(Facility::Local(3)), 20, 13215, 180),
                Switches::default()
            ))
        );
        assert_eq!(
            (s.ident.as_str(), s.syslog_socket.to_str().unwrap()),
            ("rxenstored", "/dev/log")
        );
        assert_eq!((s.queue_lines, s.queue_bytes), (1 << 16, 8 << 20));
        // --no-access-log.
        assert_eq!(cf.log_settings(false, "x").access, None);
        // Files, and the switches.
        let (cf, _) =
            parse("access-log-read-ops = true\naccess-log-transactions-ops = true\naccess-log-special-ops = true\n");
        let s = cf.log_settings(true, "x");
        assert_eq!(
            s.access,
            Some((
                out(
                    LogDest::File("/var/log/xen/xenstored-access.log".into()),
                    20,
                    13215,
                    180
                ),
                Switches {
                    read_ops: true,
                    transaction_ops: true,
                    special_ops: true
                }
            ))
        );
        assert_eq!(
            s.daemon.unwrap().0.dest,
            LogDest::File("/var/log/xen/xenstored.log".into())
        );
        // A file needs files, and the daemon log a level; syslog does not.
        for (text, daemon, access) in [
            ("xenstored-log-level = null\n", false, true),
            ("xenstored-log-nb-files = 0\naccess-log-nb-files = 0\n", false, false),
            (
                "xenstored-log-file = syslog:daemon\nxenstored-log-level = null\nxenstored-log-nb-files = 0\n",
                true,
                true,
            ),
            (
                "access-log-file = syslog:local3\naccess-log-nb-files = -1\n",
                true,
                true,
            ),
        ] {
            let s = parse(text).0.log_settings(true, "x");
            assert_eq!((s.daemon.is_some(), s.access.is_some()), (daemon, access), "{text}");
        }
    }

    #[test]
    fn the_host_quotas_reach_the_core() {
        let (cf, _) = parse(HOST);
        let mut c = xs_core::Config::default();
        cf.apply_quotas(&mut c);
        assert!(c.quota_activate);
        assert_eq!(
            (c.entity_max, c.watch_max, c.transaction_max, c.request_max),
            (8192, Some(512), Some(10), Some(1024))
        );
        assert_eq!((c.outstanding_max, c.watch_event_max), (1024, 1024));
        // Not in the file: one transaction of 1,024 requests of 1,024 + 2,048 bytes.
        assert_eq!(c.transaction_bytes_max, Some(3 << 20));
        for (text, want) in [
            ("quota-transaction-bytes = 65536", Some(65536)),
            ("quota-transaction-bytes = 0", Some(0)),
            ("quota-transaction-bytes = -1", None),
            (
                "quota-maxrequests = -1\nquota-path-max = 2\nquota-maxsize = 2",
                Some(4096),
            ),
            ("quota-maxrequests = 3\nquota-path-max = 2\nquota-maxsize = 2", Some(12)),
        ] {
            let mut c = xs_core::Config::default();
            parse(text).0.apply_quotas(&mut c);
            assert_eq!(c.transaction_bytes_max, want, "{text}");
        }
        // The code's defaults are the core's.
        let mut d = xs_core::Config::default();
        FileConfig::default().apply_quotas(&mut d);
        assert_eq!(d.transaction_bytes_max, Some(4 << 20));
        let core = xs_core::Config::default();
        assert_eq!(
            (d.entity_max, d.watch_max, d.transaction_max, d.request_max),
            (core.entity_max, core.watch_max, core.transaction_max, core.request_max)
        );
        assert_eq!(
            (d.outstanding_max, d.watch_event_max, d.quota_activate),
            (core.outstanding_max, core.watch_event_max, core.quota_activate)
        );
    }

    #[test]
    fn the_conflict_keys_reach_the_core() {
        let (cf, _) = parse(HOST);
        let mut c = xs_core::Config {
            conflict_burst_limit: 0.0,
            conflict_rate_limit_is_aggregate: false,
            ..xs_core::Config::default()
        };
        cf.apply_conflicts(&mut c);
        assert_eq!(
            (
                c.conflict_burst_limit,
                c.conflict_max_history,
                c.conflict_rate_limit_is_aggregate
            ),
            (5.0, Duration::from_millis(50), true)
        );
        let core = xs_core::Config::default();
        assert_eq!(
            (
                core.conflict_burst_limit,
                core.conflict_max_history,
                core.conflict_rate_limit_is_aggregate
            ),
            (5.0, Duration::from_millis(50), true)
        );
        for (v, want) in [
            ("1e30", Duration::MAX),
            ("-1", Duration::ZERO),
            ("nan", Duration::ZERO),
            ("2.5", Duration::from_millis(2500)),
        ] {
            let (cf, _) = parse(&format!("conflict-max-history-seconds = {v}\nconflict-burst-limit = inf\nconflict-rate-limit-is-aggregate = false"));
            cf.apply_conflicts(&mut c);
            assert_eq!(
                (
                    c.conflict_burst_limit,
                    c.conflict_max_history,
                    c.conflict_rate_limit_is_aggregate
                ),
                (f64::INFINITY, want, false),
                "{v}"
            );
        }
    }

    #[test]
    fn quotas_that_limit_nothing_as_oxenstored_reads_them() {
        for (v, limits) in [
            (-1, (None, None, None, 0)),
            (0, (None, None, Some(0), 0)),
            (1, (Some(1), Some(1), Some(1), 1)),
        ] {
            let cf = FileConfig {
                quota_activate: false,
                quota_maxwatch: v,
                quota_transaction: v,
                quota_maxrequests: v,
                quota_maxentity: v,
                quota_maxoutstanding: v,
                quota_maxwatchevents: v,
                ..FileConfig::default()
            };
            let mut c = xs_core::Config::default();
            cf.apply_quotas(&mut c);
            assert!(!c.quota_activate);
            assert_eq!(
                (c.watch_max, c.transaction_max, c.request_max, c.entity_max),
                limits,
                "{v}"
            );
            assert_eq!((c.outstanding_max, c.watch_event_max), (limits.3, limits.3), "{v}");
        }
    }

    #[test]
    fn every_key_and_its_type() {
        let text = "\
merge-activate = false
conflict-burst-limit = 1.5
conflict-max-history-seconds = 2
conflict-rate-limit-is-aggregate = false
perms-activate = false
perms-watch-activate = false
quota-activate = false
quota-maxwatch = 1
quota-transaction = 2
quota-maxentity = 3
quota-maxsize = 4
quota-maxrequests = 5
quota-maxoutstanding = 6
quota-maxwatchevents = 7
quota-path-max = 8
quota-transaction-bytes = 16
gc-max-overhead = 9
test-eagain = true
persistent = true
xenstored-log-file = /var/log/x.log
xenstored-log-level = debug
xenstored-log-nb-files = 10
xenstored-log-nb-lines = 11
xenstored-log-nb-chars = 12
access-log-file = syslog:user
access-log-nb-files = 13
access-log-nb-lines = 14
access-log-nb-chars = 15
access-log-read-ops = true
access-log-transactions-ops = true
access-log-special-ops = true
allow-debug = true
ring-scan-interval = -1
pid-file = /p
xenstored-kva = /k
xenstored-port = /q
";
        let (cf, problems) = parse(text);
        assert_eq!(problems, []);
        let expected = FileConfig {
            merge_activate: false,
            conflict_burst_limit: 1.5,
            conflict_max_history_seconds: 2.0,
            conflict_rate_limit_is_aggregate: false,
            perms_activate: false,
            perms_watch_activate: false,
            quota_activate: false,
            quota_maxwatch: 1,
            quota_transaction: 2,
            quota_maxentity: 3,
            quota_maxsize: 4,
            quota_maxrequests: 5,
            quota_maxoutstanding: 6,
            quota_maxwatchevents: 7,
            quota_path_max: 8,
            quota_transaction_bytes: Some(16),
            gc_max_overhead: 9,
            test_eagain: true,
            persistent: true,
            xenstored_log_file: LogDest::File("/var/log/x.log".into()),
            xenstored_log_level: LogLevel::Debug,
            xenstored_log_nb_files: 10,
            xenstored_log_nb_lines: 11,
            xenstored_log_nb_chars: 12,
            access_log_file: LogDest::Syslog(Facility::User),
            access_log_nb_files: 13,
            access_log_nb_lines: 14,
            access_log_nb_chars: 15,
            access_log_read_ops: true,
            access_log_transactions_ops: true,
            access_log_special_ops: true,
            allow_debug: true,
            ring_scan_interval: -1,
            pid_file: "/p".into(),
            xenstored_kva: "/k".into(),
            xenstored_port: "/q".into(),
        };
        assert_eq!(cf, expected);
        // Every key once (oxenstored 4.17's 35 and rxenstored's
        // `quota-transaction-bytes`), and nothing else.
        assert_eq!(text.lines().count(), 36);
    }

    #[test]
    fn every_type_refuses_what_ocaml_refuses() {
        let keys = [
            ("merge-activate", "expect bool arg"),
            ("quota-maxsize", "expect int arg"),
            ("quota-transaction-bytes", "expect int arg"),
            ("conflict-burst-limit", "expect float arg"),
        ];
        for (key, what) in keys {
            for bad in ["", "maybe", "1x", "True", "0x"] {
                let (cf, problems) = parse(&format!("{key} = {bad}"));
                assert_eq!(cf, FileConfig::default(), "{key} = {bad}");
                assert_eq!(
                    problems,
                    [Problem {
                        line: 1,
                        key: key.into(),
                        trouble: Trouble::BadValue,
                        what: what.into()
                    }],
                    "{key} = {bad}"
                );
            }
        }
        let (_, p) =
            parse("xenstored-log-level = loud\naccess-log-file = syslog:local8\nxenstored-log-file = syslog:local");
        let what: Vec<_> = p.iter().map(|p| p.what.as_str()).collect();
        assert_eq!(
            what,
            [
                "Logging.Unknown_level(\"loud\")",
                "Syslog.Unknown_facility(\"local8\")",
                "Syslog.Unknown_facility(\"local\")"
            ]
        );
        assert_eq!(parse("access-log-file = syslog:local07").1.len(), 1);
        use Facility::*;
        let names = [
            "auth", "authpriv", "cron", "daemon", "ftp", "kern", "local0", "local7", "lpr", "mail", "news", "syslog",
            "user", "uucp",
        ];
        let facilities = [
            Auth,
            Authpriv,
            Cron,
            Daemon,
            Ftp,
            Kern,
            Local(0),
            Local(7),
            Lpr,
            Mail,
            News,
            Syslog,
            User,
            Uucp,
        ];
        for (name, facility) in names.into_iter().zip(facilities) {
            assert_eq!(log_dest(&format!("syslog:{name}")), Ok(LogDest::Syslog(facility)));
        }
        for (name, level) in [
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warn", LogLevel::Warn),
            ("error", LogLevel::Error),
            ("null", LogLevel::Null),
        ] {
            assert_eq!(log_level(name), Ok(level));
        }
        assert_eq!(log_dest("sys:daemon"), Ok(LogDest::File("sys:daemon".into())));
    }

    #[test]
    fn values_read_as_ocaml_reads_them() {
        let int = |text: &str| int_of_string(text.as_bytes());
        for (text, n) in [
            ("0", 0),
            ("-5", -5),
            ("+5", 5),
            ("1_000", 1000),
            ("0x1F", 31),
            ("0XfF", 255),
            ("0o17", 15),
            ("0b101", 5),
            ("0u12", 12),
            ("-0x10", -16),
            ("4611686018427387903", (1 << 62) - 1),
            ("-4611686018427387904", -(1 << 62)),
        ] {
            assert_eq!(int(text), Some(n), "{text}");
        }
        for text in [
            "",
            "-",
            "x",
            "0x",
            "0xg",
            "1.0",
            " 1",
            "_1",
            "0b2",
            "4611686018427387904",
            "99999999999999999999",
            "0x8000000000000000",
        ] {
            assert_eq!(int(text), None, "{text}");
        }
        // A prefixed value from 2^62 is read as OCaml's int holds it.
        assert_eq!(int("0x4000000000000000"), Some(-(1 << 62)));
        assert_eq!(int("0x7fffffffffffffff"), Some(-1));
        let (cf, problems) = parse("quota-maxentity = 0x7fffffffffffffff\n");
        assert_eq!(
            (cf.quota_maxentity, problems),
            (-1, vec![]),
            "as oxenstored, a limit of -1"
        );
        for (text, x) in [
            ("5.0", 5.0),
            ("5", 5.0),
            ("5.", 5.0),
            (".5", 0.5),
            ("1e3", 1000.0),
            ("-1_000.5", -1000.5),
            ("_1", 1.0),
            ("inf", f64::INFINITY),
        ] {
            assert_eq!(ocaml_float(text), Some(x), "{text}");
        }
        assert!(ocaml_float("nan").unwrap().is_nan());
        for text in ["", "_", "x", "1..0", "0x1p3"] {
            assert_eq!(ocaml_float(text), None, "{text}");
        }
        assert_eq!(ocaml_bool("true"), Some(true));
        assert_eq!(ocaml_bool("false"), Some(false));
        assert_eq!(ocaml_bool("1"), None);
    }

    #[test]
    fn grammar() {
        let text = "\
\t # indented comment
quota-maxsize=1
  quota-maxwatch\t=\t 2 \t
pid-file = /a = b
xenstored-kva =
quota-maxsize = 3
not a setting
= orphan
quota maxentity = 4
perms-activate = true # not a comment
quota-maxentity = 5\r
";
        let (cf, problems) = parse(text);
        assert_eq!(cf.quota_maxsize, 3, "a later line wins");
        assert_eq!(cf.quota_maxwatch, 2);
        assert_eq!(cf.pid_file, PathBuf::from("/a = b"), "split at the first '='");
        assert_eq!(cf.xenstored_kva, PathBuf::from(""));
        assert!(cf.perms_activate);
        assert_eq!(cf.quota_maxentity, 1000);
        let p = |line, key: &str, trouble, what: &str| Problem {
            line,
            key: key.into(),
            trouble,
            what: what.into(),
        };
        assert_eq!(
            problems,
            [
                p(7, "", Trouble::NoEquals, ""),
                p(8, "", Trouble::UnknownKey, "unknown key"),
                p(9, "quota maxentity", Trouble::UnknownKey, "unknown key"),
                p(10, "perms-activate", Trouble::BadValue, "expect bool arg"),
                // Only spaces and tabs are trimmed, as OCaml does.
                p(11, "quota-maxentity", Trouble::BadValue, "expect int arg"),
            ]
        );
        let shown: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
        assert_eq!(shown[0], "config: line 7: no '=', ignored");
        assert_eq!(shown[2], "config: line 9: unknown key quota maxentity");
        assert_eq!(shown[3], "config: line 10: perms-activate: expect bool arg");
        assert_eq!(parse(""), (FileConfig::default(), vec![]));
    }

    #[test]
    fn ring_scan_interval_as_oxenstored_uses_it() {
        let scan = |n| {
            FileConfig {
                ring_scan_interval: n,
                ..FileConfig::default()
            }
            .ring_scan()
        };
        assert_eq!(FileConfig::default().ring_scan(), Some(Duration::from_secs(20)));
        assert_eq!(scan(-1), None);
        assert_eq!(scan(i64::MIN), None);
        assert_eq!(scan(0), Some(Duration::from_secs(15)));
        assert_eq!(scan(1), Some(Duration::from_secs(1)));
        assert_eq!(scan(1 << 62), Some(Duration::from_secs(u32::MAX.into())));
    }
}
