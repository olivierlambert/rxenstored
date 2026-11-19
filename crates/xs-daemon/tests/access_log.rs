// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The daemon writes its access log and daemon log where oxenstored.conf
//! says, and reopens them on SIGHUP.

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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use xs_wire::MsgType;

const BIN: &str = env!("CARGO_BIN_EXE_rxenstored");

/// rxenstored with oxenstored's command line and oxenstored.conf.
fn rx() -> Command {
    let mut c = Command::new(BIN);
    c.arg("--compat=oxenstored");
    c
}

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Run {
    dir: PathBuf,
    child: Child,
}

impl Run {
    fn start(conf: &str, args: &[&str]) -> Run {
        let dir = std::env::temp_dir().join(format!(
            "rxenstored-access-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = conf.replace("DIR", dir.to_str().unwrap());
        std::fs::write(
            dir.join("oxenstored.conf"),
            format!("pid-file = {}/pid\n{conf}", dir.display()),
        )
        .unwrap();
        let child = rx()
            .args(["--no-fork", "--no-domain-init", "--config-file"])
            .arg(dir.join("oxenstored.conf"))
            .arg("--socket")
            .arg(dir.join("socket"))
            .args(args)
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        let r = Run { dir, child };
        // Not by connecting: the access log would show that connection.
        wait_for(|| r.path("socket").exists());
        r
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn signal(&self, name: &str) {
        Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
    }

    fn stop(&mut self) {
        self.signal("TERM");
        wait_for(|| matches!(self.child.try_wait(), Ok(Some(_))));
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_for(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The lines of a log, their dates replaced by `DATE`.
fn lines(p: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(p).unwrap_or_default();
    text.lines()
        .map(|l| {
            if l.starts_with("[20") {
                format!("[DATE{}", &l[23..])
            } else {
                l.to_string()
            }
        })
        .collect()
}

/// Waits until the log has `n` lines.
fn wait_lines(p: &Path, n: usize) -> Vec<String> {
    wait_for(|| lines(p).len() >= n);
    lines(p)
}

#[test]
fn requests_reach_the_access_log_and_sighup_reopens_it() {
    let mut r = Run::start(
        "access-log-file = DIR/access.log\nxenstored-log-file = DIR/xenstored.log\nxenstored-log-level = info\n",
        &[],
    );
    let log = r.path("access.log");
    let mut c = Client::connect(&r.path("socket"));
    c.write(0, "/a", "v");
    assert_eq!(c.read(0, "/a").unwrap(), "v");
    c.ok(MsgType::Mkdir, 0, b"/b\0");
    c.ok(MsgType::SetPerms, 0, b"/b\0n0\0r5\0");
    c.ok(MsgType::Rm, 0, b"/b\0");
    assert_eq!(c.error(MsgType::Rm, 0, b"/b/c\0"), "ENOENT");
    assert_eq!(c.error(MsgType::Write, 0, b"bad//path\0"), "EINVAL");
    c.watch("/a", "tok");
    c.wait_events(1);
    let tx = c.start();
    c.write(tx, "/t", "x");
    c.end(tx, true).unwrap();
    let want = [
        "[DATE]  A1           newconn   ",
        "[DATE]  A1           write     /a v",
        "[DATE]  A1           mkdir     /b ",
        "[DATE]  A1           setperms  /b n0 r5 ",
        "[DATE]  A1           rm        /b ",
        "[DATE]  A1           rm        /b/c ",
        "[DATE]  A1           write     bad//path ",
        "[DATE]  A1           error     EINVAL ",
        "[DATE]  A1           watch     /a tok ",
        "[DATE]  A1           w event   /a tok ",
        "[DATE]  A1.1         write     /t x",
        "[DATE]  A1.1         commit    ",
    ];
    assert_eq!(wait_lines(&log, want.len()), want);

    // logrotate's way: rename, then SIGHUP; the daemon opens a new file.
    std::fs::rename(&log, r.path("access.log.1")).unwrap();
    r.signal("HUP");
    wait_for(|| log.exists());
    c.write(0, "/after", "hup");
    assert_eq!(wait_lines(&log, 1), ["[DATE]  A1           write     /after hup"]);
    assert_eq!(lines(&r.path("access.log.1")), want, "the old file is left as it was");

    let daemon = r.path("xenstored.log");
    r.stop();
    assert!(r.child.wait().unwrap().success());
    let d = lines(&daemon);
    assert_eq!(d[0], "Xen Storage Daemon, version 1.0");
    assert!(
        d.contains(&format!(
            "[DATE| info|xenstored] listening on {}",
            r.path("socket").display()
        )),
        "{d:?}"
    );
    assert_eq!(d.last().unwrap(), "[DATE| info|xenstored] stopped by signal 15");
    // On stderr, the start-up and the stop only.
    let err = lines(&r.path("stderr"));
    let err: Vec<String> = err
        .iter()
        .map(|l| format!("rxenstored: [DATE{}", &l["rxenstored: [20200123T12:34:56.512Z".len()..]))
        .collect();
    assert_eq!(
        err,
        [
            "rxenstored: [DATE| info|xenstored] Xen Storage Daemon, version 1.0".to_string(),
            format!(
                "rxenstored: [DATE| info|xenstored] listening on {}",
                r.path("socket").display()
            ),
            "rxenstored: [DATE| info|xenstored] stopped by signal 15".to_string(),
        ]
    );
}

#[test]
fn the_switches_and_no_access_log() {
    let mut r = Run::start(
        "access-log-file = DIR/access.log\naccess-log-read-ops = true\naccess-log-transactions-ops = true\naccess-log-special-ops = true\nxenstored-log-file = DIR/xenstored.log\nxenstored-log-level = null\naccess-log-nb-chars = 60\n",
        &[],
    );
    let mut c = Client::connect(&r.path("socket"));
    assert!(c.read(0, "/missing").is_err());
    c.ok(MsgType::GetDomainPath, 0, b"3\0");
    let tx = c.start();
    c.end(tx, false).unwrap();
    c.write(0, "/long", &"x".repeat(100));
    let want = [
        "[DATE]  A1           newconn   ",
        "[DATE]  A1           read      /missing ",
        "[DATE]  A1           error     ENOENT ",
        "[DATE]  A1           getdomain 3 ",
        "[DATE]  A1.1         t start   ",
        "[DATE]  A1.1         t end     ",
        "[DATE]  A1           write     /long xx..",
    ];
    assert_eq!(wait_lines(&r.path("access.log"), want.len()), want);
    r.stop();
    // `null`: no daemon log at all (`ox/logging.ml:177`).
    assert!(!r.path("xenstored.log").exists());

    let mut r = Run::start(
        "access-log-file = DIR/access.log\nxenstored-log-file = DIR/xenstored.log\n",
        &["--no-access-log"],
    );
    let mut c = Client::connect(&r.path("socket"));
    c.write(0, "/a", "v");
    r.stop();
    assert!(!r.path("access.log").exists());
    // `warn` by default: only the first line.
    assert_eq!(lines(&r.path("xenstored.log")), ["Xen Storage Daemon, version 1.0"]);
}

#[test]
fn logs_that_cannot_be_opened_go_to_stderr() {
    let mut r = Run::start(
        "access-log-file = DIR/no/access.log\nxenstored-log-file = DIR/no/xenstored.log\nxenstored-log-level = info\n",
        &[],
    );
    let mut c = Client::connect(&r.path("socket"));
    c.write(0, "/a", "v");
    r.stop();
    let err = std::fs::read_to_string(r.path("stderr")).unwrap();
    assert!(
        err.contains("rxenstored: [logging] daemon log ") && err.contains("logging to stderr"),
        "{err}"
    );
    assert!(
        err.contains("rxenstored: [logging] access log ") && err.contains("no access log"),
        "{err}"
    );
    assert!(err.contains("rxenstored: [xenstored] listening on "), "{err}");
}
