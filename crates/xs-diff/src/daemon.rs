// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Starts a fresh daemon on its own socket, configuration and logs.
//!
//! rxenstored takes `--socket`. oxenstored's socket path is compiled in
//! (`/var/run/xenstored/socket`), so the oxenstored command is a launcher
//! that runs it with the directory named by `RXS_OX_RUNDIR` standing for
//! `/run` (a private mount namespace): the socket is then
//! `$RXS_OX_RUNDIR/xenstored/socket`.

use std::fmt::Write as _;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ox,
    Rx,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Ox => "oxenstored",
            Kind::Rx => "rxenstored",
        }
    }
}

/// The quotas and limits of XCP-ng 8.3's `/etc/xen/oxenstored.conf`, as
/// the package installs it.
pub const XCPNG_CONF: &str = "\
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
";

#[derive(Debug, Clone)]
pub struct Spec {
    pub kind: Kind,
    /// The daemon (rxenstored), or the launcher described above (oxenstored).
    pub exe: PathBuf,
    /// Configuration lines added after `XCPNG_CONF`.
    pub conf_extra: String,
}

pub struct Daemon {
    pub kind: Kind,
    child: Child,
    pub dir: PathBuf,
    pub socket: PathBuf,
    /// Keep the directory (logs) when dropped: set if `RXS_DIFF_KEEP` is.
    pub keep: bool,
}

static NEXT: AtomicU32 = AtomicU32::new(0);
const SETPRIV: &str = "/usr/bin/setpriv";

impl Daemon {
    pub fn start(spec: &Spec) -> io::Result<Daemon> {
        let dir = std::env::temp_dir().join(format!(
            "xs-diff-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            spec.kind.name()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let mut conf = String::from(XCPNG_CONF);
        let _ = writeln!(conf, "pid-file = {}", dir.join("xenstored.pid").display());
        let _ = writeln!(conf, "xenstored-log-file = {}", dir.join("xenstored.log").display());
        let _ = writeln!(conf, "access-log-file = {}", dir.join("access.log").display());
        conf.push_str(&spec.conf_extra);
        let conf_path = dir.join("oxenstored.conf");
        std::fs::write(&conf_path, conf)?;
        // Killed if the thread that starts it goes away, where setpriv(1)
        // is there: a harness that is killed leaves no daemon behind. (The
        // oxenstored launcher does the same.)
        let mut cmd = match (spec.kind, Path::new(SETPRIV).exists()) {
            (Kind::Rx, true) => {
                let mut c = Command::new(SETPRIV);
                c.args(["--pdeathsig", "KILL"]).arg(&spec.exe);
                c
            }
            _ => Command::new(&spec.exe),
        };
        if spec.kind == Kind::Rx {
            // oxenstored's command line and oxenstored.conf, as oxenstored gets.
            cmd.arg("--compat=oxenstored");
        }
        cmd.args(["--no-domain-init", "--no-fork", "--config-file"])
            .arg(&conf_path)
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(dir.join("stdout.txt"))?))
            .stderr(Stdio::from(std::fs::File::create(dir.join("stderr.txt"))?));
        let socket = match spec.kind {
            Kind::Rx => {
                let s = dir.join("socket");
                cmd.arg("--socket").arg(&s);
                s
            }
            Kind::Ox => {
                let run = dir.join("run");
                cmd.env("RXS_OX_RUNDIR", &run);
                run.join("xenstored/socket")
            }
        };
        let child = cmd.spawn()?;
        let mut d = Daemon {
            kind: spec.kind,
            child,
            dir,
            socket,
            keep: std::env::var_os("RXS_DIFF_KEEP").is_some(),
        };
        d.wait_ready()?;
        Ok(d)
    }

    fn wait_ready(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if UnixStream::connect(&self.socket).is_ok() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{} exited at start ({status}): {}",
                    self.kind.name(),
                    self.stderr()
                )));
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} did not open {}", self.kind.name(), self.socket.display()),
                ));
            }
            // sleep-ok: polls for the socket, within the deadline above.
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// What the daemon wrote on stderr so far.
    pub fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.txt")).unwrap_or_default()
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // A daemon whose logs are kept is stopped by SIGTERM, so that it
        // writes out what its logs buffer; KILL if that fails.
        if self.keep
            && Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .is_ok_and(|s| s.success())
        {
            let _ = self.child.wait();
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}
