// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored's own front end, the default: its command line (`options`)
//! and `/etc/xen/rxenstored.conf` (`config`). Every problem is an error;
//! the command line's settings win over the file's.

pub mod config;
pub mod options;

use crate::settings::{ident, Failure, Plan, Settings};
use config::FileConfig;
use options::{Args, DEFAULT_CONFIG, USAGE};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use xs_daemon::reactor;
use xs_sys::xen::XenOptions;

/// Reads the command line and the configuration; what deserves a warning
/// on stderr goes to `warn`.
pub fn plan(argv: &[OsString], notify_socket: Option<OsString>, warn: &mut Vec<String>) -> Result<Plan, Failure> {
    let args = options::parse(argv).map_err(|e| Failure::Usage(e, USAGE))?;
    if args.help {
        return Ok(Plan::Usage(USAGE));
    }
    if args.version {
        return Ok(Plan::Version);
    }
    let path = args.config_file.clone().unwrap_or_else(|| DEFAULT_CONFIG.into());
    let cf = read_config(&path, args.config_file.is_some(), args.config_test, warn).and_then(|mut cf| {
        let errors: Vec<String> = args.quotas.iter().filter_map(|q| cf.quotas.set_arg(q).err()).collect();
        if errors.is_empty() {
            Ok(cf)
        } else {
            Err(errors.join("\n"))
        }
    });
    let cf = match cf {
        Ok(cf) => cf,
        Err(e) if args.config_test => {
            return Err(Failure::Fatal(format!(
                "{e}\nconfiguration not valid at {}",
                path.display()
            )))
        }
        Err(e) => return Err(Failure::Fatal(e)),
    };
    if args.trace_file.is_some() {
        warn.push("-T: trace files are not implemented, ignored".into());
    }
    if args.config_test {
        return Ok(Plan::ConfigValid(path));
    }
    Ok(Plan::Start(Box::new(start_of(&args, &cf, notify_socket))))
}

/// Reads the configuration file. The default file may be missing (the
/// defaults apply, said under `--config-test` only); a file named with
/// `--config-file` may not.
fn read_config(path: &Path, explicit: bool, testing: bool, warn: &mut Vec<String>) -> Result<FileConfig, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound && !explicit => {
            if testing {
                warn.push(format!("config: {}: not found, the defaults apply", path.display()));
            }
            return Ok(FileConfig::default());
        }
        Err(e) => return Err(format!("config: {}: {e}", path.display())),
    };
    let text = String::from_utf8(bytes).map_err(|_| format!("config: {}: not UTF-8 text", path.display()))?;
    config::parse(&text).map_err(|errors| {
        errors
            .iter()
            .map(|e| format!("config: {}: {e}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn start_of(args: &Args, cf: &FileConfig, notify_socket: Option<OsString>) -> Settings {
    let mut config = xs_core::Config {
        profile: xs_core::Profile::Native,
        perms_activate: true,
        perms_watch_activate: true,
        ..xs_core::Config::default()
    };
    cf.quotas.apply(&mut config);
    cf.apply_conflicts(&mut config);
    // dom0's ring: the xenbus backend device, then /proc/xen.
    let xen = XenOptions::default();
    Settings {
        options: reactor::Options {
            socket: args.socket.clone(),
            // Owner only, as C xenstored makes it.
            socket_mode: Some(0o600),
            disable_socket: args.disable_socket,
            domain_init: args.domain_init,
            ring_scan: cf.ring_scan(),
            xsd_kva: xen.xsd_kva,
            xsd_port: xen.xsd_port,
            config,
        },
        daemonize: args.daemonize,
        extra_pid_file: None,
        pid_file: args.pid_file.clone(),
        notify_socket,
        log: cf.log_settings(args.access_log, &ident()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::Dir;
    use crate::xen_options;
    use std::path::PathBuf;
    use std::time::Duration;
    use xs_daemon::log::{Dest, Facility};

    fn run_plan(argv: &[&str]) -> (Result<Plan, Failure>, Vec<String>) {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let mut warn = Vec::new();
        let p = plan(&argv, Some("/notify".into()), &mut warn);
        (p, warn)
    }

    fn started(argv: &[&str]) -> (Settings, Vec<String>) {
        match run_plan(argv) {
            (Ok(Plan::Start(s)), w) => (*s, w),
            (other, _) => panic!("{other:?}"),
        }
    }

    fn fatal(argv: &[&str]) -> String {
        match run_plan(argv).0 {
            Err(Failure::Fatal(e)) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_defaults_reach_the_reactor() {
        let d = Dir::new();
        let empty = d.file("empty", "");
        let (s, warn) = started(&["--config-file", empty.to_str().unwrap()]);
        assert_eq!(warn, Vec::<String>::new());
        assert!(s.daemonize);
        assert_eq!((s.pid_file, s.extra_pid_file), (None, None));
        assert_eq!(s.notify_socket, Some("/notify".into()));
        let o = &s.options;
        assert_eq!(o.socket, PathBuf::from("/var/run/xenstored/socket"));
        assert_eq!(o.socket_mode, Some(0o600), "owner only");
        assert!(o.domain_init && !o.disable_socket);
        assert_eq!(o.ring_scan, Some(Duration::from_secs(20)));
        // dom0's ring: the device first, then /proc/xen.
        assert_eq!(xen_options(o), XenOptions::default());
        let c = &o.config;
        assert_eq!(c.profile, xs_core::Profile::Native);
        assert!(c.perms_activate && c.perms_watch_activate && c.quota_activate);
        let core = xs_core::Config::default();
        // C xenstored's quotas (`config::Quotas::default`).
        assert_eq!(
            (c.entity_max, c.watch_max, c.transaction_max, c.value_max, c.path_max),
            (1000, Some(128), Some(10), 2048, 2048)
        );
        assert_eq!((c.outstanding_max, c.acl_max, c.request_max), (20, 4, Some(1024)));
        assert_eq!(
            (c.conflict_burst_limit, c.conflict_max_history),
            (core.conflict_burst_limit, core.conflict_max_history)
        );
        // The daemon log to syslog, no access log.
        assert_eq!(
            s.log.daemon.as_ref().map(|(o, _)| &o.dest),
            Some(&Dest::Syslog(Facility::Daemon))
        );
        assert_eq!(s.log.access, None);
    }

    #[test]
    fn every_option_reaches_the_reactor() {
        let d = Dir::new();
        let conf = d.file("c", "access-log = /var/log/a\nquota-nodes = 5\n");
        let (s, warn) = started(&[
            "-c",
            conf.to_str().unwrap(),
            "-N",
            "-F",
            "/p",
            "-D",
            "--disable-socket",
            "--socket",
            "/s",
            "-Q",
            "watches=3",
            "-T",
            "/t",
        ]);
        assert_eq!(warn, ["-T: trace files are not implemented, ignored"]);
        assert!(!s.daemonize);
        assert_eq!(s.pid_file, Some("/p".into()));
        assert!(!s.options.domain_init && s.options.disable_socket);
        assert_eq!(s.options.socket, PathBuf::from("/s"));
        assert_eq!((s.options.config.entity_max, s.options.config.watch_max), (5, Some(3)));
        assert_eq!(
            s.log.access.as_ref().map(|(o, _)| &o.dest),
            Some(&Dest::File("/var/log/a".into()))
        );
        let (s, _) = started(&["-c", conf.to_str().unwrap(), "--no-access-log"]);
        assert_eq!(s.log.access, None);
    }

    #[test]
    fn the_command_line_wins_over_the_file() {
        let d = Dir::new();
        let conf = d.file("c", "quota-nodes = 5\nquota-watches = 6\naccess-log = syslog:local3\n");
        let c = conf.to_str().unwrap();
        let (s, _) = started(&[
            "--config-file",
            c,
            "-Q",
            "nodes=50",
            "--quota=nodes=70",
            "--no-access-log",
        ]);
        let cfg = &s.options.config;
        assert_eq!((cfg.entity_max, cfg.watch_max), (70, Some(6)), "the last -Q wins");
        assert_eq!(s.log.access, None);
        assert_eq!(
            fatal(&["--config-file", c, "-Q", "nodes=x", "-Q", "frob=1"]),
            "-Q nodes=x: 'x' is not a whole number\n-Q frob=1: unknown quota 'frob' (known: nodes, watches, transactions, outstanding, path-max, value-size, node-permissions, transaction-requests, watch-events, transaction-bytes)"
        );
    }

    #[test]
    fn every_problem_of_the_file_is_an_error() {
        let d = Dir::new();
        let bad = d.file("bad", "quota-nodes = big\nfrob = 1\nquota-maxentity = 8192\n");
        let b = bad.to_str().unwrap();
        assert_eq!(
            fatal(&["--config-file", b]),
            format!(
                "config: {b}: line 1: quota-nodes: 'big' is not a whole number\n\
                 config: {b}: line 2: unknown key frob\n\
                 config: {b}: line 3: unknown key quota-maxentity (an oxenstored.conf key: here, quota-nodes)"
            )
        );
        // Not UTF-8.
        let raw = d.0.join("raw");
        fs::write(&raw, b"log = /\xff\n").unwrap();
        assert_eq!(
            fatal(&["--config-file", raw.to_str().unwrap()]),
            format!("config: {}: not UTF-8 text", raw.display())
        );
        // A file named that is not there, or cannot be read.
        let missing = d.0.join("missing");
        assert!(fatal(&["--config-file", missing.to_str().unwrap()]).contains("No such file"));
        assert!(fatal(&["--config-file", d.0.to_str().unwrap()]).starts_with(&format!("config: {}: ", d.0.display())));
    }

    #[test]
    fn config_test() {
        let d = Dir::new();
        let good = d.file("good", "# fine\nquota-nodes = 10\n");
        let (p, warn) = run_plan(&["--config-test", "--config-file", good.to_str().unwrap()]);
        assert!(matches!(p, Ok(Plan::ConfigValid(ref path)) if *path == good), "{p:?}");
        assert_eq!(warn, Vec::<String>::new());
        for (text, args) in [("frob = 1\n", &[][..]), ("", &["-Q", "frob=1"])] {
            let bad = d.file("bad", text);
            let mut argv = vec!["--config-test", "--config-file", bad.to_str().unwrap()];
            argv.extend(args);
            let e = fatal(&argv);
            assert!(
                e.ends_with(&format!("\nconfiguration not valid at {}", bad.display())),
                "{text}: {e}"
            );
        }
        let e = fatal(&["--config-test", "--config-file", d.0.join("missing").to_str().unwrap()]);
        assert!(
            e.contains("No such file") && e.contains("configuration not valid at"),
            "{e}"
        );
        // The default path, which this machine does not have: the defaults.
        if !Path::new(DEFAULT_CONFIG).exists() {
            let (p, warn) = run_plan(&["--config-test"]);
            assert!(matches!(p, Ok(Plan::ConfigValid(ref path)) if path == Path::new(DEFAULT_CONFIG)));
            assert_eq!(
                warn,
                [format!("config: {DEFAULT_CONFIG}: not found, the defaults apply")]
            );
            let (_, warn) = started(&[]);
            assert_eq!(warn, Vec::<String>::new(), "said under --config-test only");
        }
    }

    #[test]
    fn help_and_version_before_the_file() {
        assert!(matches!(
            run_plan(&["--help", "-c", "/nonexistent"]).0,
            Ok(Plan::Usage(USAGE))
        ));
        assert!(matches!(
            run_plan(&["--version", "-c", "/nonexistent"]).0,
            Ok(Plan::Version)
        ));
        assert!(matches!(run_plan(&["--bogus"]).0, Err(Failure::Usage(e, USAGE)) if e == "unknown option '--bogus'"));
    }
}
