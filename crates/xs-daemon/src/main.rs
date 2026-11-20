// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored: serves the xenstore protocol.
//!
//! Start-up: read the command line and the configuration (warnings on
//! stderr) with one of two front ends, rxenstored's own (`native`) or,
//! with `--compat=oxenstored`, oxenstored's (`compat`); both give a
//! `settings::Settings`. Then become a daemon unless `--no-fork`, then in
//! the daemon bind
//! the socket (unless `--disable-socket`) and create the core, open Xen
//! and serve dom0's ring (unless `--no-domain-init`; the event loop is
//! `xs_daemon::reactor`), write the pid files, send `READY=1` to
//! `$NOTIFY_SOCKET`, and only then let the process that was started exit
//! 0. A failure before that point makes it exit 1 with the error. The pid
//! files are removed when the daemon stops, so that launch-xenstore will
//! start a new one (`ox/xenstored.ml:607-609`).

#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
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
    )
)]

mod compat;
mod native;
mod settings;

use settings::{Failure, Plan, Settings};
use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use xs_daemon::log::{self, Logger};
use xs_daemon::reactor;
use xs_sys::process::{self, Daemonized, Readiness};
use xs_sys::xen::{RealXen, XenOptions};

/// The front end that reads the command line and the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Front {
    Native,
    /// `--compat=oxenstored`.
    Oxenstored,
}

/// `--compat=oxenstored` or `--compat oxenstored`, anywhere before a `--`,
/// selects oxenstored's front end, and is taken out of what it reads;
/// without it, rxenstored's own. The value is checked: any other is an
/// error, so that a typo cannot start the other front end.
fn select(argv: &[OsString]) -> Result<(Front, Vec<OsString>), String> {
    let mut front = Front::Native;
    let mut rest = Vec::new();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let value = if arg == "--" {
            rest.push(arg.clone());
            rest.extend(it.by_ref().cloned());
            break;
        } else if arg == "--compat" {
            it.next().cloned().ok_or("option '--compat' needs a value")?
        } else if let Some(v) = arg.as_encoded_bytes().strip_prefix(b"--compat=") {
            OsString::from(String::from_utf8_lossy(v).into_owned())
        } else {
            rest.push(arg.clone());
            continue;
        };
        if value != "oxenstored" {
            return Err(format!(
                "option '--compat': unknown value '{}' (known: oxenstored)",
                value.to_string_lossy()
            ));
        }
        front = Front::Oxenstored;
    }
    Ok((front, rest))
}

/// Reads the command line and the configuration with the front end it
/// selects; what deserves a warning on stderr goes to `warn`.
fn plan(argv: &[OsString], notify_socket: Option<OsString>, warn: &mut Vec<String>) -> Result<Plan, Failure> {
    match select(argv).map_err(|e| Failure::Usage(e, native::options::USAGE))? {
        (Front::Native, rest) => native::plan(&rest, notify_socket, warn),
        (Front::Oxenstored, rest) => compat::plan(&rest, notify_socket, warn),
    }
}

/// As oxenstored writes it (`ox/stdext.ml:141-153`), creating the missing
/// directories with mode 0755 as it does for the configuration's pid file
/// (`ox/xenstored.ml:342-347`).
fn write_pid_file(path: &Path, pid: u32) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(path)?;
    f.write_all(format!("{pid}\n").as_bytes())
}

/// Called by the reactor once initialised: pid files, systemd, then the
/// waiting parent. `written` collects the pid files to remove at the end.
fn announce(s: &Settings, written: &mut Vec<PathBuf>, pending: &mut Option<Readiness>) -> io::Result<()> {
    let pid = std::process::id();
    if let Some(p) = &s.extra_pid_file {
        match write_pid_file(p, pid) {
            Ok(()) => written.push(p.clone()),
            Err(e) => xs_daemon::echo!(Always, Warn, "xenstored", "pid file {}: {e}", p.display()),
        }
    }
    if let Some(p) = &s.pid_file {
        write_pid_file(p, pid).map_err(|e| io::Error::new(e.kind(), format!("pid file {}: {e}", p.display())))?;
        written.push(p.clone());
    }
    if let Some(socket) = &s.notify_socket {
        // oxenstored sends READY=1 only (`ox/systemd_stubs.c:34`); MAINPID
        // makes systemd follow the daemon rather than the launcher.
        if let Err(e) = process::notify(socket, &format!("READY=1\nMAINPID={pid}\n")) {
            xs_daemon::echo!(
                Always,
                Warn,
                "xenstored",
                "NOTIFY_SOCKET {}: {e}",
                socket.to_string_lossy()
            );
        }
    }
    if let Some(r) = pending.take() {
        // A parent that is gone has nobody to tell: serve anyway.
        let _ = r.ready();
    }
    Ok(())
}

/// The devices of a dom0, at their usual places; dom0's ring where the
/// configuration says (`XenOptions::with_dom0_files`).
fn xen_options(o: &reactor::Options) -> XenOptions {
    XenOptions::default().with_dom0_files(o.xsd_kva.clone(), o.xsd_port.clone())
}

fn open_xen(o: &reactor::Options) -> io::Result<RealXen> {
    let xo = xen_options(o);
    let xen = RealXen::open(&xo)?;
    // cov:excl-start xen-opened
    xs_daemon::echo!(
        Always,
        Info,
        "xenstored",
        "Xen devices opened: {} and {xen:?}",
        xo.evtchn.display()
    );
    Ok(xen)
} // cov:excl-stop xen-opened

/// Runs the daemon in this process, reporting to `readiness`. The logs
/// start here: after the fork, which a thread would not survive, and
/// before anything worth logging.
fn serve(s: &Settings, readiness: Readiness) -> ExitCode {
    // The signals the event loop reads (`reactor::run`) are blocked from
    // here, before the log thread and the start: one that comes meanwhile
    // waits for the loop instead of acting by default (SIGHUP would end
    // the process). Were this to fail, the loop's own blocking reports it.
    let _ = xs_sys::block_signals(&[xs_sys::SIGTERM, xs_sys::SIGINT, xs_sys::log::SIGHUP]);
    let logger = match Logger::start(&s.log) {
        Ok(l) => Some(l),
        Err(e) => {
            log::stderr(format_args!("cannot start the log thread: {e}: logging to stderr"));
            None
        }
    };
    if let Some(l) = &logger {
        l.install();
    }
    let mut pending = Some(readiness);
    let mut written = Vec::new();
    let result = reactor::run(
        &s.options,
        || open_xen(&s.options),
        None,
        || announce(s, &mut written, &mut pending),
    );
    for p in &written {
        let _ = fs::remove_file(p);
    }
    if let Err(e) = &result {
        xs_daemon::error!("xenstored", "{e}");
    }
    // What is queued is written before the process ends.
    log::uninstall();
    drop(logger);
    let Err(e) = result else { return ExitCode::SUCCESS };
    let message = e.to_string();
    // Not yet ready: the parent prints it, if there is one to tell.
    let told = match pending {
        Some(r) if r.is_piped() => r.failed(&message).is_ok(),
        _ => false,
    };
    if !told {
        log::stderr(format_args!("{message}"));
    }
    ExitCode::from(1)
}

fn main() -> ExitCode {
    xs_daemon::fatal::install_panic_hook();
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut warnings = Vec::new();
    let plan = plan(&argv, std::env::var_os("NOTIFY_SOCKET"), &mut warnings);
    for w in &warnings {
        log::stderr(format_args!("{w}"));
    }
    let s = match plan {
        Err(Failure::Usage(e, usage)) => {
            log::stderr(format_args!("{e}\n\n{usage}"));
            return ExitCode::from(2);
        }
        Err(Failure::Fatal(e)) => {
            log::stderr(format_args!("{e}"));
            return ExitCode::from(1);
        }
        // What was asked was done; a stdout that cannot be written
        // changes nothing to it (`print!` would panic).
        Ok(Plan::Usage(usage)) => {
            let _ = io::stdout().write_all(usage.as_bytes());
            return ExitCode::SUCCESS;
        }
        Ok(Plan::Version) => {
            // The commit, when the build knew it (`build.rs`).
            let _ = match option_env!("RXENSTORED_COMMIT") {
                Some(c) => writeln!(io::stdout(), "rxenstored {} ({c})", env!("CARGO_PKG_VERSION")),
                None => writeln!(io::stdout(), "rxenstored {}", env!("CARGO_PKG_VERSION")),
            };
            return ExitCode::SUCCESS;
        }
        Ok(Plan::ConfigValid(path)) => {
            let _ = writeln!(io::stdout(), "Configuration valid at {}", path.display());
            return ExitCode::SUCCESS;
        }
        Ok(Plan::Start(s)) => s,
    };
    if !s.daemonize {
        return serve(&s, Readiness::unpiped());
    }
    // No thread has been started: nothing here or in the standard
    // library's start-up starts one, and the reactor, which may, runs
    // after this. stderr stays if it is not a terminal (the journal under
    // systemd, a file, a pipe): it is the daemon's only log for now.
    match process::daemonize(!io::stderr().is_terminal()) {
        Ok(Daemonized::Daemon(readiness)) => serve(&s, readiness),
        Ok(Daemonized::Parent(Ok(()))) => ExitCode::SUCCESS,
        Ok(Daemonized::Parent(Err(e))) => {
            log::stderr(format_args!("{e}"));
            ExitCode::from(1)
        }
        Err(e) => {
            log::stderr(format_args!("cannot become a daemon: {e}"));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod testdir;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixDatagram;
    use testdir::Dir;

    fn os(argv: &[&str]) -> Vec<OsString> {
        argv.iter().map(OsString::from).collect()
    }

    fn run_plan(argv: &[&str]) -> (Result<Plan, Failure>, Vec<String>) {
        let mut warn = Vec::new();
        let p = plan(&os(argv), Some("/notify".into()), &mut warn);
        (p, warn)
    }

    #[test]
    fn compat_oxenstored_selects_oxenstored_s_front_end() {
        let native = (Front::Native, vec![]);
        assert_eq!(select(&[]), Ok(native.clone()));
        let rest = os(&["--pid-file", "/p", "--no-fork"]);
        for argv in [
            &["--compat=oxenstored", "--pid-file", "/p", "--no-fork"][..],
            &["--pid-file", "/p", "--compat=oxenstored", "--no-fork"],
            &["--pid-file", "/p", "--no-fork", "--compat", "oxenstored"],
            &[
                "--compat=oxenstored",
                "--pid-file",
                "/p",
                "--compat=oxenstored",
                "--no-fork",
            ],
        ] {
            assert_eq!(select(&os(argv)), Ok((Front::Oxenstored, rest.clone())), "{argv:?}");
        }
        assert_eq!(select(&rest), Ok((Front::Native, rest.clone())));
        // After `--`, nothing is an option.
        let after = os(&["--", "--compat=oxenstored"]);
        assert_eq!(select(&after), Ok((Front::Native, after.clone())));
        for (argv, e) in [
            (
                &["--compat=native"][..],
                "option '--compat': unknown value 'native' (known: oxenstored)",
            ),
            (
                &["--compat="],
                "option '--compat': unknown value '' (known: oxenstored)",
            ),
            (
                &["--compat", "c"],
                "option '--compat': unknown value 'c' (known: oxenstored)",
            ),
            (&["--compat"], "option '--compat' needs a value"),
        ] {
            assert_eq!(select(&os(argv)), Err(e.to_string()), "{argv:?}");
        }
    }

    #[test]
    fn each_front_end_has_its_usage_and_profile() {
        let d = Dir::new();
        let native = native::options::USAGE;
        let compat = compat::options::USAGE;
        assert!(matches!(run_plan(&["--help"]).0, Ok(Plan::Usage(u)) if u == native));
        assert!(matches!(run_plan(&["-h"]).0, Ok(Plan::Usage(u)) if u == native));
        assert!(matches!(run_plan(&["--compat=oxenstored", "--help"]).0, Ok(Plan::Usage(u)) if u == compat));
        assert!(matches!(run_plan(&["--version"]).0, Ok(Plan::Version)));
        assert!(matches!(run_plan(&["--compat=x"]).0, Err(Failure::Usage(_, u)) if u == native));
        assert!(matches!(run_plan(&["--bogus"]).0, Err(Failure::Usage(_, u)) if u == native));
        assert!(matches!(run_plan(&["--compat=oxenstored", "--bogus"]).0, Err(Failure::Usage(_, u)) if u == compat));
        // oxenstored's options are not rxenstored's.
        assert!(matches!(run_plan(&["--live", "--help"]).0, Err(Failure::Usage(e, _)) if e.contains("--live")));
        let empty = d.file("empty", "");
        let empty = empty.to_str().unwrap();
        for (argv, profile) in [
            (
                &["--compat=oxenstored", "--config-file", empty][..],
                xs_core::Profile::Oxenstored,
            ),
            (&["--config-file", empty], xs_core::Profile::Native),
        ] {
            let (p, _) = run_plan(argv);
            let Ok(Plan::Start(s)) = p else { panic!("{p:?}") };
            assert_eq!(s.options.config.profile, profile, "{argv:?}");
        }
    }

    #[test]
    fn the_host_command_line_in_each_mode() {
        // launch-xenstore's `--pid-file` and XENSTORED_ARGS, with the
        // default configuration file of each mode, which this machine
        // does not have.
        for argv in [
            &["--pid-file", "/var/run/xen/xenstored.pid"][..],
            &["--pid-file", "/var/run/xen/xenstored.pid", "--compat=oxenstored"],
        ] {
            let (p, warn) = run_plan(argv);
            let Ok(Plan::Start(s)) = p else { panic!("{p:?}") };
            assert_eq!(s.pid_file, Some("/var/run/xen/xenstored.pid".into()));
            assert!(s.daemonize && s.options.domain_init);
            assert_eq!(xen_options(&s.options), XenOptions::default());
            if !Path::new(native::options::DEFAULT_CONFIG).exists()
                && !Path::new(compat::options::DEFAULT_CONFIG).exists()
            {
                assert_eq!(warn, Vec::<String>::new());
            }
        }
    }

    #[test]
    fn pid_files() {
        let d = Dir::new();
        let p = d.0.join("a/b/pid");
        write_pid_file(&p, 42).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "42\n");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(d.0.join("a")).unwrap().permissions().mode() & 0o777, 0o755);
        write_pid_file(&p, 7).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "7\n", "truncated");
        // A relative name with no directory part.
        let cwd_pid = PathBuf::from(format!("rxenstored-pid-{}", std::process::id()));
        write_pid_file(&cwd_pid, 1).unwrap();
        fs::remove_file(&cwd_pid).unwrap();
        assert!(write_pid_file(Path::new("/proc/rxenstored/pid"), 1).is_err());
        assert!(write_pid_file(&d.0, 1).is_err(), "a directory");
    }

    fn start_in(d: &Dir, notify: Option<OsString>) -> Settings {
        let (mut s, _) = compat::tests::started(&["--config-file", d.0.join("none").to_str().unwrap()]);
        s.extra_pid_file = Some(d.0.join("conf/pid"));
        s.pid_file = Some(d.0.join("arg/pid"));
        s.notify_socket = notify;
        s
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn announce_writes_notifies_and_releases() {
        let d = Dir::new();
        let sock = d.0.join("notify");
        let listener = UnixDatagram::bind(&sock).unwrap();
        let s = start_in(&d, Some(sock.clone().into()));
        let (r, w) = std::io::pipe().unwrap();
        drop(r);
        // A parent that is gone does not stop the daemon.
        let mut pending = Some(Readiness::on_pipe(w));
        let mut written = Vec::new();
        announce(&s, &mut written, &mut pending).unwrap();
        assert!(pending.is_none());
        assert_eq!(written, [d.0.join("conf/pid"), d.0.join("arg/pid")]);
        let me = format!("{}\n", std::process::id());
        assert_eq!(fs::read_to_string(&written[1]).unwrap(), me);
        let mut buf = [0u8; 128];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            format!("READY=1\nMAINPID={me}")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn announce_failures() {
        let d = Dir::new();
        // The configuration's pid file and the notification may fail.
        let mut s = start_in(&d, Some("/proc/rxenstored/notify".into()));
        s.extra_pid_file = Some("/proc/rxenstored/pid".into());
        let mut pending = Some(Readiness::unpiped());
        let mut written = Vec::new();
        announce(&s, &mut written, &mut pending).unwrap();
        assert_eq!(written, [d.0.join("arg/pid")]);
        // --pid-file may not; the parent is still owed a report.
        s.pid_file = Some("/proc/rxenstored/pid".into());
        let mut pending = Some(Readiness::unpiped());
        let e = announce(&s, &mut Vec::new(), &mut pending).unwrap_err();
        assert!(e.to_string().starts_with("pid file /proc/rxenstored/pid: "), "{e}");
        assert!(pending.is_some());
        s.pid_file = None;
        s.extra_pid_file = None;
        s.notify_socket = None;
        announce(&s, &mut Vec::new(), &mut Some(Readiness::unpiped())).unwrap();
    }
}
