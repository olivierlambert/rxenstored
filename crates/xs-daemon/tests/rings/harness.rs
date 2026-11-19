// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The event loop in a thread over a `SimXen`; the test plays the
//! toolstack (socket clients, `Handle`) and the guests (`Guest`).

use crate::common::Client;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xs_daemon::log::{self, Dest, Echo, Level, Logger, Output, Settings};
use xs_daemon::reactor::{self, Options};
use xs_sim::{DomainInfo, Guest, Handle, SimXen};
use xs_sys::fd::EventFd;
use xs_sys::ring::Field;
use xs_wire::{nul_terminated, Message, MsgType, HEADER_LEN};

/// The longest any single wait may take.
pub const T: Duration = Duration::from_secs(5);

static NEXT: AtomicU32 = AtomicU32::new(0);

pub struct Daemon {
    pub hv: Handle,
    pub socket: PathBuf,
    dir: PathBuf,
    stop: Arc<EventFd>,
    thread: Option<JoinHandle<io::Result<()>>>,
    /// `/proc/PID/task/TID` of the loop's thread.
    task: PathBuf,
}

/// `run` returned before it called `ready`.
#[derive(Debug)]
pub struct Failed {
    pub error: io::Error,
    pub ready_called: bool,
}

type Open = Box<dyn FnOnce(SimXen) -> io::Result<SimXen> + Send>;

fn fresh_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rxenstored-rings-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Daemon {
    pub fn start() -> Daemon {
        Daemon::start_with(|_, _| {})
    }

    /// `prepare` may change the options and the machine before the start.
    pub fn start_with(prepare: impl FnOnce(&mut Options, &Handle)) -> Daemon {
        Daemon::launch(prepare, Box::new(Ok)).unwrap()
    }

    /// As `start_with`; `open` stands for the opening of the devices.
    pub fn launch(prepare: impl FnOnce(&mut Options, &Handle), open: Open) -> Result<Daemon, Failed> {
        let xen = SimXen::new().unwrap();
        let hv = xen.handle();
        let dir = fresh_dir();
        let mut opts = Options {
            socket: dir.join("run/socket"),
            socket_mode: None,
            disable_socket: false,
            domain_init: true,
            // oxenstored's default.
            ring_scan: Some(Duration::from_secs(20)),
            xsd_kva: "/sim/xsd_kva".into(),
            xsd_port: "/sim/xsd_port".into(),
            config: xs_core::Config::default(),
        };
        prepare(&mut opts, &hv);
        let socket = opts.socket.clone();
        let stop = Arc::new(EventFd::new().unwrap());
        let (tx, rx) = mpsc::channel();
        let (task_tx, task_rx) = mpsc::channel();
        // The loop's daemon log, at warn, read by `stop_with_log`.
        let settings = Settings {
            daemon: Some((
                Output {
                    dest: Dest::File(dir.join("xenstored.log")),
                    nb_files: 1,
                    nb_lines: 1_000_000,
                    nb_chars: 0,
                },
                Level::Warn,
            )),
            access: None,
            ident: "rxenstored".into(),
            syslog_socket: dir.join("dev-log"),
            queue_lines: 1000,
            queue_bytes: 1 << 20,
        };
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let _ = task_tx.send(std::fs::read_link("/proc/thread-self").unwrap());
                let logger = Logger::start_with(&settings, Echo::new(Duration::ZERO, 0, Box::new(io::sink())))?;
                logger.install();
                let r = reactor::run(
                    &opts,
                    || open(xen),
                    Some(&stop),
                    || {
                        let _ = tx.send(());
                        Ok(())
                    },
                );
                log::uninstall();
                logger.stop();
                r
            })
        };
        let task = PathBuf::from("/proc").join(task_rx.recv().unwrap());
        let mut d = Daemon {
            hv,
            socket,
            dir,
            stop,
            thread: Some(thread),
            task,
        };
        match rx.recv_timeout(T) {
            Ok(()) => Ok(d),
            Err(_) => {
                let error = d.join().expect_err("run ended without calling ready");
                Err(Failed {
                    error,
                    ready_called: false,
                })
            }
        }
    }

    /// Stops the loop and returns what `run` returned.
    pub fn stop(mut self) -> io::Result<()> {
        self.stop.signal().unwrap();
        self.join()
    }

    /// Stops the loop and returns its daemon log, complete.
    pub fn stop_with_log(mut self) -> String {
        self.stop.signal().unwrap();
        self.join().unwrap();
        std::fs::read_to_string(self.dir.join("xenstored.log")).unwrap()
    }

    fn join(&mut self) -> io::Result<()> {
        let Some(t) = self.thread.take() else { return Ok(()) };
        let deadline = Instant::now() + T;
        while !t.is_finished() {
            assert!(Instant::now() < deadline, "the event loop did not stop");
            // sleep-ok: polls, within the deadline above.
            std::thread::sleep(Duration::from_millis(1));
        }
        t.join().expect("the event loop panicked")
    }

    /// CPU time the loop's thread has used, in clock ticks.
    pub fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(self.task.join("stat")).unwrap();
        let fields: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
        // utime and stime, fields 14 and 15.
        fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
    }

    /// CPU time the loop's thread has used, in nanoseconds (schedstat).
    #[allow(dead_code)] // tests/wakeups.rs
    pub fn cpu_ns(&self) -> u64 {
        let s = std::fs::read_to_string(self.task.join("schedstat")).unwrap();
        s.split_whitespace().next().unwrap().parse().unwrap()
    }

    /// Waits until the loop's thread sleeps in epoll_wait, and returns the
    /// timeout it sleeps with, in ms (-1: none), as /proc shows the call:
    /// what the loop waits for, read rather than timed.
    pub fn sleeping(&self) -> i32 {
        // The epoll waits whose fourth argument is the timeout in ms.
        #[cfg(target_arch = "x86_64")]
        const WAITS: &[i64] = &[libc::SYS_epoll_wait, libc::SYS_epoll_pwait];
        #[cfg(not(target_arch = "x86_64"))]
        const WAITS: &[i64] = &[libc::SYS_epoll_pwait];
        let deadline = Instant::now() + T;
        loop {
            let call = std::fs::read_to_string(self.task.join("syscall")).unwrap();
            let f: Vec<&str> = call.split_whitespace().collect();
            if f.first()
                .and_then(|n| n.parse::<i64>().ok())
                .is_some_and(|n| WAITS.contains(&n))
            {
                // An int, in a register: its low 32 bits.
                return u64::from_str_radix(f[4].trim_start_matches("0x"), 16).unwrap() as u32 as i32;
            }
            assert!(Instant::now() < deadline, "the event loop did not sleep: {call}");
            std::thread::yield_now();
        }
    }

    /// How many times the loop's thread has gone to sleep: its voluntary
    /// context switches.
    pub fn sleeps(&self) -> u64 {
        let status = std::fs::read_to_string(self.task.join("status")).unwrap();
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))
            .unwrap();
        line.trim().parse().unwrap()
    }

    pub fn client(&self) -> Client {
        let c = Client::connect(&self.socket);
        c.stream.set_read_timeout(Some(T)).unwrap();
        c
    }

    /// A running domain whose guest is not introduced yet.
    pub fn domain(&self, domid: u32) -> (DomainInfo, G) {
        let info = self.hv.create_domain(domid).unwrap();
        (info, G::new(self.hv.guest(domid).unwrap()))
    }

    /// What the toolstack does to start a VM: its home, owned by it, then
    /// INTRODUCE.
    pub fn vm(&self, c: &mut Client, domid: u32) -> G {
        let (info, g) = self.domain(domid);
        let home = format!("/local/domain/{domid}");
        c.ok(MsgType::Mkdir, 0, &nul_terminated(&[home.as_bytes()]));
        c.ok(
            MsgType::SetPerms,
            0,
            &nul_terminated(&[home.as_bytes(), format!("n{domid}").as_bytes()]),
        );
        assert_eq!(introduce(c, &info), Ok(()));
        g
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Also when a test fails: the loop must not outlive it.
        let _ = self.stop.signal();
        if let Some(t) = self.thread.take() {
            let deadline = Instant::now() + T;
            while !t.is_finished() && Instant::now() < deadline {
                // sleep-ok: polls, within the deadline above.
                std::thread::sleep(Duration::from_millis(1));
            }
            if !std::thread::panicking() {
                assert!(t.is_finished(), "the event loop did not stop");
                t.join().expect("the event loop panicked").expect("run failed");
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn introduce_payload(domid: u32, gfn: u64, port: u32) -> Vec<u8> {
    nul_terminated(&[
        domid.to_string().as_bytes(),
        gfn.to_string().as_bytes(),
        port.to_string().as_bytes(),
    ])
}

/// INTRODUCE from a socket client: Ok, or the error.
pub fn introduce(c: &mut Client, d: &DomainInfo) -> Result<(), String> {
    introduce_at(c, d.domid, d.gfn, d.port)
}

pub fn introduce_at(c: &mut Client, domid: u32, gfn: u64, port: u32) -> Result<(), String> {
    let r = c.call(MsgType::Introduce, 0, &introduce_payload(domid, gfn, port));
    if r.is_error() {
        Err(r.text().trim_end_matches('\0').into())
    } else {
        assert_eq!(r.payload, b"OK\0");
        Ok(())
    }
}

pub fn introduced(c: &mut Client, domid: u32) -> bool {
    match &c.ok(
        MsgType::IsDomainIntroduced,
        0,
        &nul_terminated(&[domid.to_string().as_bytes()]),
    )[..]
    {
        b"T\0" => true,
        b"F\0" => false,
        other => panic!("{other:?}"),
    }
}

/// A guest as a xenstore client: keeps watch events apart from replies.
pub struct G {
    pub g: Guest,
    req: u32,
    pub events: Vec<(String, String)>,
}

fn event_of(m: &Message) -> (String, String) {
    let f = m.fields();
    (
        String::from_utf8_lossy(f[0]).into_owned(),
        String::from_utf8_lossy(f[1]).into_owned(),
    )
}

impl G {
    pub fn new(g: Guest) -> G {
        G {
            g,
            req: 1000,
            events: Vec::new(),
        }
    }

    pub fn send(&mut self, ty: MsgType, payload: &[u8]) -> u32 {
        self.req += 1;
        self.g.send_request(ty, self.req, 0, payload, T).unwrap();
        self.req
    }

    /// The next reply, storing the events that come first.
    pub fn reply(&mut self) -> Message {
        loop {
            let m = self.g.recv_message(T).unwrap();
            if m.msg_type() == Some(MsgType::WatchEvent) {
                self.events.push(event_of(&m));
            } else {
                return m;
            }
        }
    }

    pub fn call_tx(&mut self, ty: MsgType, tx: u32, payload: &[u8]) -> Message {
        self.req += 1;
        self.g.send_request(ty, self.req, tx, payload, T).unwrap();
        let m = self.reply();
        assert_eq!(m.req_id, self.req, "replies in order");
        m
    }

    pub fn call(&mut self, ty: MsgType, payload: &[u8]) -> Message {
        self.call_tx(ty, 0, payload)
    }

    pub fn ok(&mut self, ty: MsgType, payload: &[u8]) -> Vec<u8> {
        let m = self.call(ty, payload);
        assert_ne!(
            m.msg_type(),
            Some(MsgType::Error),
            "{ty:?} {:?}: {}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(&m.payload)
        );
        assert_eq!(m.ty, ty as u32);
        m.payload
    }

    pub fn error(&mut self, ty: MsgType, payload: &[u8]) -> String {
        let m = self.call(ty, payload);
        assert_eq!(m.msg_type(), Some(MsgType::Error), "{ty:?} succeeded");
        String::from_utf8_lossy(&m.payload).trim_end_matches('\0').into()
    }

    pub fn read(&mut self, path: &str) -> Result<String, String> {
        let m = self.call(MsgType::Read, &nul_terminated(&[path.as_bytes()]));
        let text = String::from_utf8_lossy(&m.payload).into_owned();
        if m.msg_type() == Some(MsgType::Error) {
            Err(text.trim_end_matches('\0').into())
        } else {
            Ok(text)
        }
    }

    pub fn write(&mut self, path: &str, value: &str) {
        self.ok(MsgType::Write, &[path.as_bytes(), b"\0", value.as_bytes()].concat());
    }

    pub fn watch(&mut self, path: &str, token: &str) {
        self.ok(MsgType::Watch, &nul_terminated(&[path.as_bytes(), token.as_bytes()]));
    }

    /// Waits until `n` events have come in total.
    pub fn wait_events(&mut self, n: usize) {
        while self.events.len() < n {
            let m = self.g.recv_message(T).unwrap();
            assert_eq!(m.msg_type(), Some(MsgType::WatchEvent), "unexpected {m:?}");
            self.events.push(event_of(&m));
        }
    }

    pub fn field(&mut self, f: Field) -> u32 {
        self.g.ring().get(f)
    }
}

/// Encodes one request.
pub fn request(ty: MsgType, req_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    Message::new(ty, req_id, 0, payload.to_vec())
        .unwrap()
        .encode_into(&mut out);
    out
}

/// Polls until `done` or the deadline.
pub fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + T;
    while !done() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(1));
    }
}
