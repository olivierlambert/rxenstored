// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The binary with its own command line and `rxenstored.conf`: it starts,
//! serves, writes its pid file and logs where the file says, the command
//! line wins over the file, and every problem stops the start with a
//! message and the exit code of its kind.

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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use xs_wire::MsgType;

const BIN: &str = env!("CARGO_BIN_EXE_rxenstored");

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A private directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        let d = std::env::temp_dir().join(format!(
            "rxenstored-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `rxenstored.conf`, with `DIR` replaced by the directory.
    fn conf(&self, text: &str) -> PathBuf {
        let p = self.path("rxenstored.conf");
        std::fs::write(&p, text.replace("DIR", self.0.to_str().unwrap())).unwrap();
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = Command::new("kill").arg(self.0.id().to_string()).status();
            let deadline = Instant::now() + Duration::from_secs(10);
            while matches!(self.0.try_wait(), Ok(None)) && Instant::now() < deadline {
                // sleep-ok: polls, within the deadline above.
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("NOTIFY_SOCKET")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn wait_for(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn starts_serves_and_logs_where_the_file_says() {
    let d = Dir::new();
    let conf = d.conf(
        "# rxenstored.conf\n\
         log = DIR/daemon.log\n\
         log-level = info\n\
         access-log = DIR/access.log\n\
         quota-value-size = 8\n\
         quota-path-max = 100\n",
    );
    let socket = d.path("run/socket");
    let kid = Kid(Command::new(BIN)
        .arg("-N")
        .arg("-D")
        .arg("--config-file")
        .arg(&conf)
        .arg("--socket")
        .arg(&socket)
        .arg("-F")
        .arg(d.path("pid"))
        // The command line wins over the file.
        .args(["-Q", "value-size=4"])
        .env_remove("NOTIFY_SOCKET")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    wait_for(|| d.path("pid").exists());
    assert_eq!(
        std::fs::read_to_string(d.path("pid")).unwrap(),
        format!("{}\n", kid.0.id())
    );
    // Owner only, whatever the umask.
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o7777, 0o600);
    let mut c = Client::connect(&socket);
    c.ok(MsgType::Write, 0, b"/a\0abcd");
    assert_eq!(c.ok(MsgType::Read, 0, b"/a\0"), b"abcd");
    let r = c.call(MsgType::Write, 0, b"/b\0abcde");
    assert_eq!((r.is_error(), r.text().as_str()), (true, "E2BIG\0"), "-Q value-size=4");
    let long = format!("/{}\0x", "p".repeat(100));
    let r = c.call(MsgType::Write, 0, long.as_bytes());
    assert!(r.is_error(), "quota-path-max = 100: {}", r.text());
    drop(c);
    drop(kid);
    // Stopped: the pid file is gone, the logs are written.
    assert!(!d.path("pid").exists());
    let daemon = std::fs::read_to_string(d.path("daemon.log")).unwrap();
    assert!(daemon.contains("Xen Storage Daemon, version 1.0"), "{daemon}");
    let access = std::fs::read_to_string(d.path("access.log")).unwrap();
    assert!(access.contains(" write     /a abcd\n"), "{access}");
}

#[test]
fn defaults_without_a_file() {
    // The default file, which this machine does not have, and a log
    // written nowhere: the daemon starts on the defaults.
    if Path::new("/etc/xen/rxenstored.conf").exists() {
        return;
    }
    let d = Dir::new();
    let socket = d.path("socket");
    let _kid = Kid(Command::new(BIN)
        .args(["--no-fork", "--no-domain-init", "--socket"])
        .arg(&socket)
        .env_remove("NOTIFY_SOCKET")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    // The socket's file exists from bind(2) on: wait for it before connecting.
    wait_for(|| socket.exists());
    let mut c = Client::connect(&socket);
    // The default value size: 2,048 bytes.
    let mut w = b"/v\0".to_vec();
    w.extend(vec![b'x'; 2048]);
    c.ok(MsgType::Write, 0, &w);
    w.push(b'x');
    assert_eq!(c.call(MsgType::Write, 0, &w).text(), "E2BIG\0");
}

#[test]
fn every_problem_stops_the_start() {
    let d = Dir::new();
    let socket = d.path("socket");
    let s = socket.to_str().unwrap();
    // A bad command line: exit 2, with the usage.
    for (args, want) in [
        (&["--bogus"][..], "unknown option '--bogus'"),
        (&["stray"], "unexpected argument 'stray'"),
        (&["--compat=bogus"], "option '--compat': unknown value 'bogus'"),
        // oxenstored's live-update check: `--live --restart ARGS --help`.
        (&["--live", "--restart", "--help"], "unknown option '--live'"),
        // C xenstored's.
        (&["-E", "1000"], "unknown option '-E'"),
    ] {
        let o = run(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        let e = stderr(&o);
        assert!(
            e.contains(want) && e.contains("usage: rxenstored [OPTION]..."),
            "{args:?}: {e}"
        );
    }
    // A bad file or -Q: exit 1, every problem said, nothing started.
    let conf = d.conf("quota-maxentity = 8192\nfrob = 1\nlog-level = loud\n");
    let c = conf.to_str().unwrap();
    let o = run(&["-N", "-D", "--socket", s, "-c", c]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        stderr(&o),
        format!(
            "rxenstored: config: {c}: line 1: unknown key quota-maxentity (an oxenstored.conf key: here, quota-nodes)\n\
             config: {c}: line 2: unknown key frob\n\
             config: {c}: line 3: log-level: 'loud' is not a level (debug, info, warn, error)\n"
        )
    );
    assert!(!socket.exists());
    let conf = d.conf("");
    let o = run(&[
        "-N",
        "-D",
        "--socket",
        s,
        "-c",
        conf.to_str().unwrap(),
        "-Q",
        "memory=1",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("-Q memory=1: unknown quota 'memory'"),
        "{}",
        stderr(&o)
    );
    let o = run(&["-N", "-D", "--socket", s, "-c", d.path("missing").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("No such file"), "{}", stderr(&o));
    assert!(!socket.exists());
}

#[test]
fn help_version_and_config_test() {
    let o = run(&["--help"]);
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.starts_with("usage: rxenstored [OPTION]..."), "{out}");
    assert!(out.contains("--compat=oxenstored"), "{out}");
    let o = run(&["--compat=oxenstored", "--help"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("usage: rxenstored --compat=oxenstored"));
    let o = run(&["--version"]);
    assert!(o.status.success());
    // The version, then the commit in brackets when the build knew it.
    let v = String::from_utf8_lossy(&o.stdout).into_owned();
    let rest = v
        .strip_prefix(&format!("rxenstored {}", env!("CARGO_PKG_VERSION")))
        .expect(&v);
    assert!(
        rest == "\n" || (rest.starts_with(" (") && rest.ends_with(")\n") && rest.lines().count() == 1),
        "{v}"
    );
    let d = Dir::new();
    let good = d.conf("quota-nodes = 8192\n");
    let o = run(&["--config-test", "-c", good.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        format!("Configuration valid at {}\n", good.display())
    );
    let o = run(&["--config-test", "-c", good.to_str().unwrap(), "-Q", "nodes=x"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).ends_with(&format!("configuration not valid at {}\n", good.display())),
        "{}",
        stderr(&o)
    );
}
