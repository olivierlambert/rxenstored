// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Starting the daemon as launch-xenstore does: command line, configuration
//! file, becoming a daemon, pid file, systemd notification.

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

mod common;

use common::Client;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_rxenstored");

/// rxenstored with oxenstored's command line and oxenstored.conf.
fn rx() -> Command {
    let mut c = Command::new(BIN);
    c.arg("--compat=oxenstored");
    c
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A private directory with a configuration, removed on drop.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = std::env::temp_dir().join(format!(
            "rxenstored-startup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = Sandbox { dir };
        s.config(&format!("# as on the host, with private paths\npid-file = {}\nquota-maxsize = 2048\nquota-path-max = 1024\npersistent = false\n", s.path("conf-run/xenstored.pid").display()));
        s
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn config(&self, text: &str) -> PathBuf {
        let p = self.path("oxenstored.conf");
        std::fs::write(&p, text).unwrap();
        p
    }

    /// The command launch-xenstore runs, on private paths.
    fn command(&self) -> Command {
        let mut c = rx();
        c.arg("--no-domain-init")
            .arg("--config-file")
            .arg(self.path("oxenstored.conf"))
            .arg("--pid-file")
            .arg(self.path("run/xenstored.pid"))
            .arg("--socket")
            .arg(self.path("sock/socket"))
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        c
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A daemon that is not our child, stopped on drop.
struct DaemonPid(u32);

impl DaemonPid {
    /// Asks it to stop and waits until it has; false if it had to be killed.
    fn stop(&mut self) -> bool {
        if self.0 == 0 {
            return true;
        }
        signal("TERM", self.0);
        let stopped = wait_until(Duration::from_secs(10), || !alive(self.0));
        if !stopped {
            signal("KILL", self.0);
        }
        self.0 = 0;
        stopped
    }
}

impl Drop for DaemonPid {
    fn drop(&mut self) {
        // Asked first: a daemon built for coverage writes its profile on the way out.
        self.stop();
    }
}

/// A child, killed on drop.
struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            signal("TERM", self.0.id());
            if !wait_until(Duration::from_secs(10), || matches!(self.0.try_wait(), Ok(Some(_)))) {
                let _ = self.0.kill();
            }
        }
        let _ = self.0.wait();
    }
}

fn signal(name: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status();
}

/// Running, and not a zombie waiting for its parent to reap it.
fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !matches!(
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next()),
            Some('Z' | 'X')
        ),
        Err(_) => false,
    }
}

/// Fields 4 and 6 of /proc/PID/stat.
fn parent_and_session(pid: &str) -> (u32, u32) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
    (fields[1].parse().unwrap(), fields[3].parse().unwrap())
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while !done() {
        if Instant::now() > deadline {
            return false;
        }
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// Runs to the end, within 30 s.
fn finish(child: Child) -> ExitStatus {
    let mut kid = Kid(child);
    assert!(
        wait_until(Duration::from_secs(30), || matches!(kid.0.try_wait(), Ok(Some(_)))),
        "the command did not return"
    );
    kid.0.wait().unwrap()
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_exits_0() {
    for argv in [&["--help"][..], &["-help"], &["--no-fork", "--help", "--bogus"]] {
        let out = rx().args(argv).output().unwrap();
        assert!(out.status.success(), "{argv:?}");
        let (stdout, _) = text(&out);
        assert!(
            stdout.contains("--config-file") && stdout.contains("--socket"),
            "{stdout}"
        );
    }
}

#[test]
fn live_update_is_refused_even_with_help() {
    // What oxenstored runs to check a live update (ox/process.ml:123-141).
    for argv in [
        &["--live", "--restart", "--pid-file", "/nonexistent/pid", "--help"][..],
        &["--restart"],
        &["--live", "--no-fork"],
    ] {
        let out = rx().args(argv).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{argv:?}");
        assert!(text(&out).1.contains("live update) are not supported"), "{argv:?}");
    }
}

#[test]
fn option_errors() {
    for (argv, message) in [
        (&["--bogus"][..], "unknown option '--bogus'"),
        (&["--pid-file"], "option '--pid-file' needs an argument"),
        (&["--no-fork=1"], "expects no argument"),
    ] {
        let out = rx().args(argv).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{argv:?}");
        let (_, stderr) = text(&out);
        assert!(stderr.contains(message) && stderr.contains("usage:"), "{stderr}");
    }
}

#[test]
fn config_test() {
    let s = Sandbox::new();
    let good = s.path("oxenstored.conf");
    let out = rx()
        .arg("--config-test")
        .arg("--config-file")
        .arg(&good)
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", text(&out));
    assert_eq!(text(&out).0, format!("Configuration valid at {}\n", good.display()));
    for (conf, message) in [
        ("frob = 1\n", "config: line 1: unknown key frob"),
        (
            "perms-activate = yes\n",
            "config: line 1: perms-activate: expect bool arg",
        ),
        ("persistent = true\n", "persistent = true is not supported"),
    ] {
        let bad = s.config(conf);
        let out = rx()
            .args(["--config-test", "--config-file"])
            .arg(&bad)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{conf}");
        let (stdout, stderr) = text(&out);
        assert!(stdout.is_empty());
        assert!(
            stderr.contains(message) && stderr.contains("configuration not valid at"),
            "{stderr}"
        );
    }
    let out = rx()
        .args(["--config-test", "--config-file"])
        .arg(s.path("missing"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

/// The start launch-xenstore makes under systemd, on private paths.
#[test]
fn daemonised_start() {
    let s = Sandbox::new();
    // An unknown key is only a warning outside --config-test. The daemon
    // log at the host's level, in the sandbox.
    s.config(&format!(
        "pid-file = {}\nquota-maxsize = 100\nfrob = 1\nxenstored-log-file = {}\nxenstored-log-level = warn\naccess-log-file = {}\n",
        s.path("conf-run/xenstored.pid").display(),
        s.path("xenstored.log").display(),
        s.path("access.log").display()
    ));
    let notify_path = s.path("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let stderr = std::fs::File::create(s.path("stderr")).unwrap();
    let child = s
        .command()
        .arg("-T")
        .arg(s.path("trace"))
        .env("NOTIFY_SOCKET", &notify_path)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let launcher = child.id();
    let pid_file = s.path("run/xenstored.pid");
    // Whatever happens next, the daemon is stopped.
    let mut daemon = DaemonPid(0);
    let status = finish(child);
    if let Ok(t) = std::fs::read_to_string(&pid_file) {
        daemon.0 = t.trim().parse().unwrap_or(0);
    }
    let log = std::fs::read_to_string(s.path("stderr")).unwrap();
    assert!(status.success(), "{status:?}: {log}");

    // Returned only once the pid files were written, by the daemon.
    let t = std::fs::read_to_string(&pid_file).unwrap();
    assert!(t.ends_with('\n'));
    let pid: u32 = t.trim().parse().unwrap();
    assert_ne!(pid, launcher);
    assert!(alive(pid));
    assert_eq!(std::fs::read_to_string(s.path("conf-run/xenstored.pid")).unwrap(), t);
    // Orphaned in a new session, of which it is not the leader.
    let (ppid, session) = parent_and_session(&pid.to_string());
    assert_ne!(ppid, launcher);
    assert_ne!(session, pid);
    assert_ne!(session, parent_and_session("self").1);

    // systemd was told, by the daemon.
    let mut buf = [0u8; 256];
    let n = notify.recv(&mut buf).unwrap();
    let message = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(message.split('\n').any(|l| l == "READY=1"), "{message}");
    assert!(message.split('\n').any(|l| l == format!("MAINPID={pid}")), "{message}");

    // It serves.
    let mut c = Client::connect(&s.path("sock/socket"));
    assert!(c.read(0, "/tool/xenstored").unwrap().ends_with("rxenstored"));
    // The core has the configuration's limits.
    c.write(0, "/fits", &"x".repeat(100));
    let mut big = Vec::from(&b"/too-big\0"[..]);
    big.extend(std::iter::repeat_n(b'x', 101));
    assert_eq!(c.error(xs_wire::MsgType::Write, 0, &big), "E2BIG");

    // Warnings went to the stderr it was given, which it keeps.
    assert!(log.contains("unknown key frob"), "{log}");
    assert!(log.contains("-T: trace files are not implemented yet"), "{log}");

    // So did the start-up messages, which the daemon log at warn does not
    // show, and which tell how far a boot went.
    let started = log
        .lines()
        .position(|l| l.ends_with("|xenstored] Xen Storage Daemon, version 1.0"))
        .unwrap_or_else(|| panic!("{log}"));
    let listening = log
        .lines()
        .position(|l| {
            l.ends_with(&format!(
                " info|xenstored] listening on {}",
                s.path("sock/socket").display()
            ))
        })
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        started < listening && log.lines().all(|l| l.starts_with("rxenstored: ")),
        "{log}"
    );

    // SIGTERM stops it, and it removes its pid files.
    assert!(daemon.stop(), "SIGTERM did not stop the daemon");
    assert!(c.next().is_none(), "connection closed");
    assert!(!pid_file.exists());
    assert!(!s.path("conf-run/xenstored.pid").exists());
    let log = std::fs::read_to_string(s.path("stderr")).unwrap();
    assert!(
        log.lines()
            .last()
            .unwrap()
            .ends_with(" info|xenstored] stopped by signal 15"),
        "{log}"
    );
    // The daemon log has only what its level shows.
    let daemon_log = std::fs::read_to_string(s.path("xenstored.log")).unwrap();
    assert_eq!(
        daemon_log.lines().collect::<Vec<_>>(),
        ["Xen Storage Daemon, version 1.0"],
        "{daemon_log}"
    );
}

#[test]
fn a_failed_start_returns_non_zero_with_the_error() {
    let s = Sandbox::new();
    // The socket's directory cannot be created.
    let out = s
        .command()
        .args(["--socket", "/proc/rxenstored-cannot/socket"])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let (_, stderr) = text(&out);
    assert!(stderr.contains("/proc/rxenstored-cannot/socket"), "{stderr}");
    // Reported to the parent through the readiness pipe, which prints it:
    // not a daemon that died unheard.
    assert!(!stderr.contains("exited before it was ready"), "{stderr}");
    assert!(!s.path("run/xenstored.pid").exists());
    // --pid-file that cannot be written: the socket was bound, the start fails.
    let out = s
        .command()
        .args(["--pid-file", "/proc/rxenstored-cannot/pid"])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).1.contains("pid file /proc/rxenstored-cannot/pid"),
        "{:?}",
        text(&out)
    );
    assert!(
        !s.path("conf-run/xenstored.pid").exists(),
        "the one it wrote is removed"
    );
    // So does persistence.
    s.config("persistent = true\n");
    let out = s.command().stderr(Stdio::piped()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).1.contains("persistent = true is not supported"));
}

/// Without `--no-domain-init` and without Xen, the start fails before
/// READY=1, and the process that was started says why. The event channel
/// device is the first one opened: where it exists (a dom0) the test is
/// skipped, as it must not touch real devices; where it does not, nothing
/// else is opened.
#[test]
fn a_start_without_xen_devices_fails_clearly() {
    if std::path::Path::new("/dev/xen/evtchn").exists() {
        eprintln!("skipped: this machine has /dev/xen/evtchn");
        return;
    }
    let s = Sandbox::new();
    s.config(&format!(
        "pid-file = {}\nxenstored-kva = {}\nxenstored-port = {}\n",
        s.path("conf-run/pid").display(),
        s.path("no-kva").display(),
        s.path("no-port").display()
    ));
    for fork in [true, false] {
        let mut c = rx();
        c.arg("--config-file")
            .arg(s.path("oxenstored.conf"))
            .arg("--pid-file")
            .arg(s.path("run/pid"))
            .arg("--socket")
            .arg(s.path("sock/socket"));
        if !fork {
            c.arg("--no-fork");
        }
        let out = c
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("cannot open the Xen devices") && stderr.contains("/dev/xen/evtchn"),
            "{stderr}"
        );
        assert!(
            !s.path("run/pid").exists() && !s.path("conf-run/pid").exists(),
            "never ready"
        );
    }
}

#[test]
fn a_failed_start_in_the_foreground() {
    let s = Sandbox::new();
    let out = s
        .command()
        .args(["--no-fork", "--socket", "/proc/rxenstored-cannot/socket"])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).1.contains("rxenstored: /proc/rxenstored-cannot/socket"),
        "{:?}",
        text(&out)
    );
}

#[test]
fn a_failed_fork_is_reported() {
    let s = Sandbox::new();
    // No new process for this user, as launch-xenstore sets limits (root
    // is exempt: then it starts, and is stopped).
    let mut c = Command::new("prlimit");
    c.args(["--nproc=1", "--"])
        .arg(s.command().get_program())
        .args(s.command().get_args())
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // A file: a daemon that started would keep a pipe open.
    let status = finish(
        c.stderr(std::fs::File::create(s.path("stderr")).unwrap())
            .spawn()
            .unwrap(),
    );
    if let Ok(t) = std::fs::read_to_string(s.path("run/xenstored.pid")) {
        drop(DaemonPid(t.trim().parse().unwrap_or(0)));
        return;
    }
    let log = std::fs::read_to_string(s.path("stderr")).unwrap();
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(log.contains("rxenstored: cannot become a daemon: "), "{log}");
}

/// In the foreground, with an abstract notification socket.
#[test]
fn no_fork_start_with_an_abstract_notify_socket() {
    let s = Sandbox::new();
    let name = format!(
        "rxenstored-startup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let notify = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
    notify.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut kid = Kid(s
        .command()
        .arg("--no-fork")
        .env("NOTIFY_SOCKET", format!("@{name}"))
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    let mut buf = [0u8; 256];
    let n = notify.recv(&mut buf).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&buf[..n]),
        format!("READY=1\nMAINPID={}\n", kid.0.id())
    );
    assert_eq!(
        std::fs::read_to_string(s.path("run/xenstored.pid")).unwrap(),
        format!("{}\n", kid.0.id())
    );
    let mut c = Client::connect(&s.path("sock/socket"));
    assert!(c.read(0, "/tool/xenstored").is_ok());
    signal("TERM", kid.0.id());
    assert!(wait_until(Duration::from_secs(10), || matches!(
        kid.0.try_wait(),
        Ok(Some(_))
    )));
    assert!(kid.0.wait().unwrap().success());
    assert!(!s.path("run/xenstored.pid").exists());
}
