// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The oxenstored front end, `--compat=oxenstored`: oxenstored 4.17's
//! command line (`options`) and `oxenstored.conf` (`config`), read as
//! oxenstored reads them, with oxenstored 4.17's behaviour profile.

pub mod config;
pub mod options;

use crate::settings::{ident, Failure, Plan, Settings};
use config::{FileConfig, Trouble};
use options::{Args, USAGE};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use xs_daemon::reactor;

/// Reads the command line (without `--compat=oxenstored`) and the
/// configuration; what deserves a warning on stderr goes to `warn`.
pub fn plan(argv: &[OsString], notify_socket: Option<OsString>, warn: &mut Vec<String>) -> Result<Plan, Failure> {
    let args = options::parse(argv).map_err(|e| Failure::Usage(e, USAGE))?;
    // Before --help: oxenstored checks a live update by running the new
    // binary with `--live --restart <its arguments> --help` and goes ahead
    // on exit 0 (`ox/process.ml:123-141`). It would then exec us with a
    // dump we cannot load and the host would lose its store: refuse here,
    // so that oxenstored keeps running.
    if args.live || args.restart {
        return Err(Failure::Fatal(
            "--live and --restart (live update) are not supported: refusing to take over".into(),
        ));
    }
    if args.help {
        return Ok(Plan::Usage(USAGE));
    }
    if args.trace_file.is_some() {
        warn.push("-T: trace files are not implemented yet, ignored".into());
    }
    for a in &args.ignored {
        warn.push(format!("ignoring argument '{}'", a.to_string_lossy()));
    }
    let path = args
        .config_file
        .clone()
        .unwrap_or_else(|| options::DEFAULT_CONFIG.into());
    if args.config_test {
        read_config(&path, true, true, warn)
            .map_err(|e| Failure::Fatal(format!("{e}\nconfiguration not valid at {}", path.display())))?;
        return Ok(Plan::ConfigValid(path));
    }
    let cf = read_config(&path, args.config_file.is_some(), false, warn).map_err(Failure::Fatal)?;
    Ok(Plan::Start(Box::new(start_of(&args, cf, notify_socket))))
}

/// Reads the configuration file. `strict` (`--config-test`): every
/// problem is an error, and so is a missing file. Otherwise, as oxenstored
/// does, problems are warnings and the defaults stand in for what could
/// not be read, a missing file included. Either way `persistent = true`
/// is an error: the store is in memory only, and a key rxenstored accepts
/// but does not honour, set to other than its default, is a warning.
fn read_config(path: &Path, explicit: bool, strict: bool, warn: &mut Vec<String>) -> Result<FileConfig, String> {
    let text = match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if strict => return Err(format!("config: {}: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound && !explicit => return Ok(FileConfig::default()),
        Err(e) => {
            warn.push(format!("config: {}: {e}; using the defaults", path.display()));
            return Ok(FileConfig::default());
        }
    };
    let (mut cf, problems) = config::parse(&text);
    let mut errors = Vec::new();
    for p in problems {
        if strict && p.trouble != Trouble::NoEquals {
            errors.push(p.to_string());
        } else {
            warn.push(p.to_string());
        }
    }
    // Sizes: OCaml would take a negative one; here it cannot be a limit.
    let default = FileConfig::default();
    for (key, value, fallback) in [
        ("quota-maxsize", &mut cf.quota_maxsize, default.quota_maxsize),
        ("quota-path-max", &mut cf.quota_path_max, default.quota_path_max),
    ] {
        if *value < 0 {
            let p = format!("config: {key}: expect a non-negative int");
            if strict {
                errors.push(p);
            } else {
                warn.push(p);
            }
            *value = fallback;
        }
    }
    warn.extend(cf.not_honoured());
    if cf.persistent {
        errors.push("config: persistent = true is not supported: the store is kept in memory only".into());
    }
    if errors.is_empty() {
        Ok(cf)
    } else {
        Err(errors.join("\n"))
    }
}

fn start_of(args: &Args, cf: FileConfig, notify_socket: Option<OsString>) -> Settings {
    let mut config = xs_core::Config {
        profile: xs_core::Profile::Oxenstored,
        path_max: cf.quota_path_max as usize,
        // Without quotas oxenstored does not check sizes (`ox/quota.ml:56-58`).
        value_max: if cf.quota_activate {
            cf.quota_maxsize as usize
        } else {
            usize::MAX
        },
        perms_activate: cf.perms_activate,
        perms_watch_activate: cf.perms_watch_activate,
        ..xs_core::Config::default()
    };
    cf.apply_quotas(&mut config);
    cf.apply_conflicts(&mut config);
    let log = cf.log_settings(args.access_log, &ident());
    Settings {
        options: reactor::Options {
            socket: args.socket.clone(),
            // What the umask leaves, as oxenstored.
            socket_mode: None,
            disable_socket: args.disable_socket,
            domain_init: args.domain_init,
            ring_scan: cf.ring_scan(),
            xsd_kva: cf.xenstored_kva,
            xsd_port: cf.xenstored_port,
            config,
        },
        daemonize: args.daemonize,
        // The configuration's `pid-file`: a failure to write it is only
        // reported (`ox/xenstored.ml:362`); `--pid-file`'s is fatal
        // (`ox/xenstored.ml:364-367`).
        extra_pid_file: (!cf.pid_file.as_os_str().is_empty()).then_some(cf.pid_file),
        pid_file: args.pid_file.clone(),
        notify_socket,
        log,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testdir::Dir;
    use crate::xen_options;
    use std::path::PathBuf;
    use xs_sys::xen::XenOptions;

    fn run_plan(argv: &[&str]) -> (Result<Plan, Failure>, Vec<String>) {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let mut warn = Vec::new();
        let p = plan(&argv, Some("/notify".into()), &mut warn);
        (p, warn)
    }

    pub(crate) fn started(argv: &[&str]) -> (Settings, Vec<String>) {
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
    fn the_host_start() {
        let d = Dir::new();
        let conf = d.file("oxenstored.conf", "pid-file = /var/run/xen/xenstored.pid\nquota-maxsize = 2048\nquota-path-max = 1024\nquota-maxentity = 8192\nquota-maxwatch = 512\nperms-watch-activate = false\nxenstored-kva = /k\nxenstored-port = /p\n");
        let (s, warn) = started(&[
            "--config-file",
            conf.to_str().unwrap(),
            "--pid-file",
            "/var/run/xen/xenstored.pid",
        ]);
        assert_eq!(warn, Vec::<String>::new());
        assert!(s.daemonize);
        assert_eq!(s.extra_pid_file, Some("/var/run/xen/xenstored.pid".into()));
        assert_eq!(s.pid_file, Some("/var/run/xen/xenstored.pid".into()));
        assert_eq!(s.notify_socket, Some("/notify".into()));
        let o = &s.options;
        assert_eq!(o.config.profile, xs_core::Profile::Oxenstored);
        assert_eq!(o.socket, PathBuf::from(options::DEFAULT_SOCKET));
        assert_eq!(o.socket_mode, None, "what the umask leaves, as oxenstored");
        assert!(o.domain_init && !o.disable_socket);
        assert_eq!(
            (o.xsd_kva.as_path(), o.xsd_port.as_path()),
            (Path::new("/k"), Path::new("/p"))
        );
        // And on to the devices, the others at their usual places.
        let xo = xen_options(o);
        assert_eq!((xo.xsd_kva, xo.xsd_port), ("/k".into(), "/p".into()));
        assert_eq!(
            xo.xenbus_backend, None,
            "files named in the configuration are used as given"
        );
        assert_eq!(xo.evtchn, XenOptions::default().evtchn);
        assert_eq!((o.config.value_max, o.config.path_max), (2048, 1024));
        assert!(o.config.perms_activate && !o.config.perms_watch_activate);
        // The quotas of the file, not the code's defaults.
        assert_eq!((o.config.entity_max, o.config.watch_max), (8192, Some(512)));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "under Miri the program name (argv[0]) is the source file's, which the test checks"
    )]
    fn options_reach_the_reactor() {
        let d = Dir::new();
        let conf = d.file("c", "quota-activate = false\nperms-activate = false\npid-file =\n");
        let (s, warn) = started(&[
            "--config-file",
            conf.to_str().unwrap(),
            "--no-fork",
            "--no-domain-init",
            "--disable-socket",
            "--socket",
            "/s",
            "-T",
            "/t",
            "stray",
            "--no-access-log",
            "--reraise-top-level",
        ]);
        assert!(!s.daemonize);
        assert_eq!(s.extra_pid_file, None);
        assert_eq!(s.pid_file, None);
        assert!(!s.options.domain_init && s.options.disable_socket);
        assert_eq!(s.options.socket, PathBuf::from("/s"));
        assert_eq!(s.options.config.value_max, usize::MAX);
        assert!(!s.options.config.perms_activate);
        assert_eq!(s.options.xsd_kva, PathBuf::from("/proc/xen/xsd_kva"));
        // The default files: the xenbus backend device first.
        assert_eq!(xen_options(&s.options), XenOptions::default());
        assert_eq!(
            warn,
            [
                "-T: trace files are not implemented yet, ignored",
                "ignoring argument 'stray'"
            ]
        );
        assert_eq!(s.log.access, None, "--no-access-log");
        assert!(s.log.daemon.is_some());
        assert!(ident().starts_with("rxenstored"), "{}", ident());
    }

    #[test]
    fn help_usage_and_live_update() {
        assert!(matches!(run_plan(&["--help"]).0, Ok(Plan::Usage(USAGE))));
        assert!(
            matches!(run_plan(&["--help", "--live"]).0, Ok(Plan::Usage(_))),
            "not read after --help"
        );
        assert!(matches!(run_plan(&["--bogus"]).0, Err(Failure::Usage(e, USAGE)) if e.contains("--bogus")));
        for argv in [
            &["--live", "--restart", "--pid-file", "/p", "--help"][..],
            &["--restart"],
            &["--live"],
            &["--live", "--config-test"],
        ] {
            assert!(fatal(argv).contains("not supported"), "{argv:?}");
        }
    }

    #[test]
    fn config_files() {
        let d = Dir::new();
        let missing = d.0.join("missing");
        let m = missing.to_str().unwrap();
        // A missing file: the defaults, with a warning if it was named.
        let (s, warn) = started(&["--config-file", m]);
        assert_eq!(s.extra_pid_file, Some(config::DEFAULT_PID_FILE.into()));
        assert_eq!(warn.len(), 1);
        assert!(warn[0].starts_with(&format!("config: {m}: ")), "{warn:?}");
        let mut warn = Vec::new();
        assert_eq!(
            read_config(&missing, false, false, &mut warn),
            Ok(FileConfig::default())
        );
        assert!(warn.is_empty());
        // Unreadable: a directory.
        let (_, warn) = started(&["--config-file", d.0.to_str().unwrap()]);
        assert!(warn[0].ends_with("; using the defaults"), "{warn:?}");
        // Problems are warnings; the defaults stand.
        let bad = d.file(
            "bad",
            "quota-maxsize = big\nfrob = 1\nnonsense\nquota-path-max = -1\nquota-maxsize = -3\n",
        );
        let (s, warn) = started(&["--config-file", bad.to_str().unwrap()]);
        assert_eq!(
            warn,
            [
                "config: line 1: quota-maxsize: expect int arg",
                "config: line 2: unknown key frob",
                "config: line 3: no '=', ignored",
                "config: quota-maxsize: expect a non-negative int",
                "config: quota-path-max: expect a non-negative int",
            ]
        );
        assert_eq!((s.options.config.value_max, s.options.config.path_max), (2048, 2048));
        // 0 is a size like any other.
        let zero = d.file("zero", "quota-maxsize = 0\nquota-path-max = 0\n");
        let (s, warn) = started(&["--config-file", zero.to_str().unwrap()]);
        assert_eq!(warn, Vec::<String>::new());
        assert_eq!((s.options.config.value_max, s.options.config.path_max), (0, 0));
        // Keys rxenstored does not honour: a warning, and the start goes on.
        let dbg = d.file("dbg", "allow-debug = true\nquota-maxentity = 8192\n");
        let (s, warn) = started(&["--config-file", dbg.to_str().unwrap()]);
        assert_eq!(warn.len(), 1);
        assert!(
            warn[0].starts_with("config: allow-debug = true is not honoured: rxenstored never lets a guest"),
            "{warn:?}"
        );
        assert_eq!(s.options.config.entity_max, 8192);
        // But persistence is refused.
        let p = d.file("p", "persistent = true\n");
        assert!(fatal(&["--config-file", p.to_str().unwrap()]).contains("persistent = true is not supported"));
    }

    #[test]
    fn config_test() {
        let d = Dir::new();
        let good = d.file("good", "# fine\nquota-maxsize = 10\nno equals here\n");
        let (p, warn) = run_plan(&["--config-test", "--config-file", good.to_str().unwrap()]);
        assert!(matches!(p, Ok(Plan::ConfigValid(ref path)) if *path == good), "{p:?}");
        assert_eq!(warn, ["config: line 3: no '=', ignored"]);
        // A key that is not honoured: said so, and the file is still valid.
        let dbg = d.file("dbg", "allow-debug = true\ntest-eagain = true\n");
        let (p, warn) = run_plan(&["--config-test", "--config-file", dbg.to_str().unwrap()]);
        assert!(matches!(p, Ok(Plan::ConfigValid(_))), "{p:?}");
        assert_eq!(warn.len(), 2);
        assert!(
            warn[0].starts_with("config: test-eagain = true is not honoured"),
            "{warn:?}"
        );
        assert!(
            warn[1].starts_with("config: allow-debug = true is not honoured"),
            "{warn:?}"
        );
        for text in [
            "frob = 1\n",
            "quota-maxsize = x\n",
            "quota-path-max = -1\n",
            "persistent = true\n",
        ] {
            let bad = d.file("bad", text);
            let e = fatal(&["--config-test", "--config-file", bad.to_str().unwrap()]);
            assert!(
                e.ends_with(&format!("\nconfiguration not valid at {}", bad.display())),
                "{text}: {e}"
            );
        }
        let e = fatal(&["--config-test", "--config-file", d.0.join("missing").to_str().unwrap()]);
        assert!(e.contains("No such file"), "{e}");
        // The default path, which this machine does not have.
        if !Path::new(options::DEFAULT_CONFIG).exists() {
            assert!(fatal(&["--config-test"]).contains(options::DEFAULT_CONFIG));
        }
    }
}
