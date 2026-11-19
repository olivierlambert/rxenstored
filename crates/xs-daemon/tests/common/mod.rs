// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Starts `rxenstored` on a private socket and talks to it.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use xs_wire::{nul_terminated, Message, MsgType, HEADER_LEN};

pub struct Daemon {
    pub child: Child,
    pub dir: PathBuf,
    pub socket: PathBuf,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

impl Daemon {
    pub fn start() -> Daemon {
        Daemon::start_limited(None)
    }

    /// With `Some(n)`, the daemon may not have more than `n` open files.
    pub fn start_limited(max_files: Option<u32>) -> Daemon {
        let dir = std::env::temp_dir().join(format!(
            "rxenstored-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // The daemon creates the socket's directory itself.
        let socket = dir.join("run/socket");
        let bin = env!("CARGO_BIN_EXE_rxenstored");
        let mut command = match max_files {
            None => Command::new(bin),
            Some(n) => {
                // Soft and hard limit, so that the daemon cannot raise it.
                let mut c = Command::new("sh");
                c.args([
                    "-c",
                    "ulimit -n \"$1\" && shift && exec \"$@\"",
                    "sh",
                    &n.to_string(),
                    bin,
                ]);
                c
            }
        };
        // Its own configuration, pid file and daemon log: never the host's.
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("oxenstored.conf");
        std::fs::write(
            &config,
            format!(
                "pid-file = {}\nxenstored-log-file = {}\n",
                dir.join("xenstored.pid").display(),
                dir.join("xenstored.log").display()
            ),
        )
        .unwrap();
        let child = command
            .args(["--compat=oxenstored", "--no-fork", "--no-domain-init", "--config-file"])
            .arg(&config)
            .arg("--socket")
            .arg(&socket)
            .env_remove("NOTIFY_SOCKET")
            .stderr(Stdio::null())
            .spawn()
            .expect("start rxenstored");
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "rxenstored did not start");
            // sleep-ok: polls, within the deadline above.
            std::thread::sleep(Duration::from_millis(10));
        }
        Daemon { child, dir, socket }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn client(&self) -> Client {
        Client::connect(&self.socket)
    }

    /// How many descriptors the daemon has open.
    pub fn fds(&self) -> usize {
        std::fs::read_dir(format!("/proc/{}/fd", self.pid())).unwrap().count()
    }

    /// Its daemon log (at the default level, warn): complete once it stopped.
    pub fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("xenstored.log")).unwrap_or_default()
    }

    /// True if the process is still running.
    pub fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// Sends a signal (by name, as kill(1) takes it) and waits for the
    /// daemon to exit; its exit code, None if it had to be killed.
    pub fn stop(&mut self, signal: &str) -> Option<i32> {
        if let Ok(Some(status)) = self.child.try_wait() {
            return status.code();
        }
        let _ = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.pid().to_string())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)), // sleep-ok: polls, within the deadline.
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return None;
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Asked to stop, not killed: a daemon built for coverage writes its
        // profile on the way out.
        self.stop("TERM");
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A blocking client that keeps watch events apart from replies.
pub struct Client {
    pub stream: UnixStream,
    buf: Vec<u8>,
    pub events: Vec<(String, String)>,
    req: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub ty: u32,
    pub req_id: u32,
    pub tx_id: u32,
    pub payload: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
    pub fn is_error(&self) -> bool {
        self.ty == MsgType::Error as u32
    }
}

impl Client {
    pub fn connect(socket: &std::path::Path) -> Client {
        // The socket's file exists from bind(2) on, a moment before
        // listen(2): a connection is refused meanwhile.
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match UnixStream::connect(socket) {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && Instant::now() < deadline => {
                    // sleep-ok: polls, within the deadline.
                    std::thread::sleep(Duration::from_millis(1))
                }
                r => break r.unwrap(),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Client {
            stream,
            buf: Vec::new(),
            events: Vec::new(),
            req: 0,
        }
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    /// Next message of any kind; replies may exceed PAYLOAD_MAX on sockets.
    pub fn next(&mut self) -> Option<Reply> {
        loop {
            if self.buf.len() >= HEADER_LEN {
                let w = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                let len = w(&self.buf, 12) as usize;
                if self.buf.len() >= HEADER_LEN + len {
                    let r = Reply {
                        ty: w(&self.buf, 0),
                        req_id: w(&self.buf, 4),
                        tx_id: w(&self.buf, 8),
                        payload: self.buf[HEADER_LEN..HEADER_LEN + len].to_vec(),
                    };
                    self.buf.drain(..HEADER_LEN + len);
                    return Some(r);
                }
            }
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                // With a read timeout set, a read is not restarted after a
                // signal handler ran, SA_RESTART or not (signal(7)).
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Next reply, storing watch events seen on the way.
    pub fn reply(&mut self) -> Reply {
        loop {
            let m = self.next().expect("connection closed");
            if m.ty == MsgType::WatchEvent as u32 {
                let f: Vec<String> = m
                    .payload
                    .split(|c| *c == 0)
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                self.events.push((f[0].clone(), f[1].clone()));
            } else {
                return m;
            }
        }
    }

    pub fn call(&mut self, ty: MsgType, tx: u32, payload: &[u8]) -> Reply {
        self.req += 1;
        let mut bytes = Vec::new();
        Message::new(ty, self.req, tx, payload.to_vec())
            .unwrap()
            .encode_into(&mut bytes);
        self.send_raw(&bytes);
        let r = self.reply();
        assert_eq!(r.req_id, self.req);
        r
    }

    pub fn ok(&mut self, ty: MsgType, tx: u32, payload: &[u8]) -> Vec<u8> {
        let r = self.call(ty, tx, payload);
        assert!(
            !r.is_error(),
            "{ty:?} {:?}: {}",
            String::from_utf8_lossy(payload),
            r.text()
        );
        assert_eq!(r.ty, ty as u32);
        r.payload
    }

    pub fn error(&mut self, ty: MsgType, tx: u32, payload: &[u8]) -> String {
        let r = self.call(ty, tx, payload);
        assert!(r.is_error(), "{ty:?} succeeded");
        r.text().trim_end_matches('\0').to_string()
    }

    pub fn write(&mut self, tx: u32, path: &str, value: &str) {
        self.ok(MsgType::Write, tx, &[path.as_bytes(), b"\0", value.as_bytes()].concat());
    }

    pub fn read(&mut self, tx: u32, path: &str) -> Result<String, String> {
        let r = self.call(MsgType::Read, tx, &nul_terminated(&[path.as_bytes()]));
        if r.is_error() {
            Err(r.text().trim_end_matches('\0').into())
        } else {
            Ok(r.text())
        }
    }

    pub fn ls(&mut self, tx: u32, path: &str) -> Vec<String> {
        let p = self.ok(MsgType::Directory, tx, &nul_terminated(&[path.as_bytes()]));
        String::from_utf8(p)
            .unwrap()
            .split_terminator('\0')
            .map(str::to_string)
            .collect()
    }

    pub fn watch(&mut self, path: &str, token: &str) {
        self.ok(MsgType::Watch, 0, &nul_terminated(&[path.as_bytes(), token.as_bytes()]));
    }

    /// Waits until `n` events have been received in total.
    pub fn wait_events(&mut self, n: usize) {
        while self.events.len() < n {
            let m = self.next().expect("connection closed");
            assert_eq!(m.ty, MsgType::WatchEvent as u32, "unexpected {m:?}");
            let f: Vec<String> = m
                .payload
                .split(|c| *c == 0)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            self.events.push((f[0].clone(), f[1].clone()));
        }
    }

    pub fn start(&mut self) -> u32 {
        let p = self.ok(MsgType::TransactionStart, 0, b"\0");
        String::from_utf8(p).unwrap().trim_end_matches('\0').parse().unwrap()
    }

    pub fn end(&mut self, tx: u32, commit: bool) -> Result<(), String> {
        let r = self.call(MsgType::TransactionEnd, tx, if commit { b"T\0" } else { b"F\0" });
        if r.is_error() {
            Err(r.text().trim_end_matches('\0').into())
        } else {
            Ok(())
        }
    }
}
