// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The event loop. Work per wake-up is proportional to what is ready:
//! epoll (edge-triggered) reports the sockets that changed state, the
//! event channel device the rings whose port fired; both go to one ready
//! queue, and each turn of a connection reads once and handles at most a
//! budget of requests before the next connection's turn. Output gathered
//! during a pass is written once per connection; then each ring that moved
//! bytes is notified once (`rings.rs`). The only timers, the safety scan of
//! the rings, the retries of a failing event channel device and of a
//! failing accept(2), are the epoll timeout (`rings.rs`).

use crate::rings::{Backoff, RingConn, Scan};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use xs_core::log::Who;
use xs_core::{Config, ConnId, Core, Drops, GaveUp, Status};
use xs_sys::backend::{Port, XenBackend};
use xs_sys::fd::EventFd;
use xs_sys::{Epoll, Event, Interest};

#[derive(Debug)]
pub struct Options {
    pub socket: PathBuf,
    /// The mode the socket is given once bound, before it listens. None:
    /// what the umask leaves, as oxenstored (`ox/utils.ml:81-88`).
    pub socket_mode: Option<u32>,
    /// `--disable-socket`: serve the rings only.
    pub disable_socket: bool,
    /// False with `--no-domain-init`: no Xen at all, the socket only.
    pub domain_init: bool,
    /// `ring-scan-interval`: each ring is examined once per this period
    /// without waiting for a notification. None: never.
    pub ring_scan: Option<Duration>,
    /// `xenstored-kva`: the file dom0's ring page is mapped from, if not
    /// from the xenbus backend device (`XenOptions::with_dom0_files`).
    pub xsd_kva: PathBuf,
    /// `xenstored-port`: the file that holds dom0's event channel port,
    /// likewise.
    pub xsd_port: PathBuf,
    /// The core's configuration; `run` sets `tool_xenstored`.
    pub config: Config,
}

/// Epoll token of the listening socket; connections use their `ConnId`, from 1.
const LISTENER: u64 = 0;
/// Epoll token of the signal descriptor.
const SIGNALS: u64 = u64::MAX;
/// Epoll token of the descriptor that stops the loop (tests).
const STOP: u64 = u64::MAX - 1;
/// Epoll token of the event channel device.
pub(crate) const XEN: u64 = u64::MAX - 2;
/// Requests handled per socket connection per turn.
const BUDGET: usize = 64;
/// Bytes read per connection per turn.
const READ_CHUNK: usize = 64 << 10;
/// Rounds of flushes per pass: a flush can let go of a connection held
/// for a watcher (`Core::consume`), whose own flush, in the next round,
/// queues its turn; and so on along a chain of holds, the rest of which
/// waits for the next pass, which comes at once.
const FLUSH_ROUNDS: usize = 4;
/// accept(2) failed (out of descriptors, or of memory): the listener rests
/// this long, unless a connection closes first.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

pub(crate) struct Client {
    stream: UnixStream,
    /// Data may be waiting in the socket (cleared when a read comes short).
    readable: bool,
}

pub(crate) enum Kind {
    Socket(Client),
    Ring(RingConn),
}

pub(crate) struct Conn {
    /// In the ready queue.
    pub queued: bool,
    /// In the list of connections to flush this pass.
    pub flushing: bool,
    /// Requests are held back until its output drains below the soft limit.
    pub blocked: bool,
    /// The core may hold complete requests (its budget or the soft limit
    /// stopped it): they are processed before more is read, so that what
    /// is buffered for a connection stays bounded.
    pub held: bool,
    pub kind: Kind,
}

impl Conn {
    pub fn new(kind: Kind) -> Conn {
        Conn {
            queued: false,
            flushing: false,
            blocked: false,
            held: false,
            kind,
        }
    }
}

/// Everything but the core, so that it can be the core's `Machine` while
/// the core runs a request.
pub(crate) struct Io<X> {
    pub xen: Option<X>,
    pub conns: HashMap<u64, Conn>,
    /// Local event channel port → its ring connection.
    pub ports: HashMap<Port, ConnId>,
    /// The ring connections, in the order the scan goes through them.
    pub rings: BTreeSet<u64>,
    pub scan: Option<Scan>,
    pub dom_exc: Option<Port>,
    pub ready: VecDeque<ConnId>,
    pub to_flush: Vec<ConnId>,
    /// Rings read or written this pass: to notify, unmask, look at again.
    pub touched: Vec<ConnId>,
    pub buf: Vec<u8>,
    /// VIRQ_DOM_EXC is being handled: a disconnect is a death, not a RELEASE.
    pub dying: bool,
    /// `pending` failed and has not succeeded since: the device is out of
    /// the epoll set until the next try.
    pub backoff: Option<Backoff>,
    /// VIRQ_DOM_EXC could not be unmasked: tried again at each pass.
    pub virq_masked: bool,
    /// accept(2) failed: the listener is out of the epoll set until then,
    /// or until a connection closes. Level-triggered, it would be ready
    /// again at once, the connection still waiting: the loop would spin.
    pub accept_retry: Option<Instant>,
    /// accept(2) has failed since it last worked: logged once per streak.
    pub accept_failing: bool,
}

impl<X> Io<X> {
    pub fn enqueue(&mut self, id: ConnId) {
        match self.conns.get_mut(&id.0) {
            Some(c) if !c.queued => {
                c.queued = true;
                self.ready.push_back(id);
            }
            _ => {}
        }
    }

    pub fn mark_flush(&mut self, id: ConnId) {
        match self.conns.get_mut(&id.0) {
            Some(c) if !c.flushing => {
                c.flushing = true;
                self.to_flush.push(id);
            }
            _ => {}
        }
    }
}

pub(crate) struct Reactor<X> {
    pub epoll: Epoll,
    pub listener: Option<UnixListener>,
    pub core: Core,
    pub io: Io<X>,
    signals: OwnedFd,
    /// Why the daemon is to stop.
    stop: Option<String>,
    /// The origin of the core's clock (`Core::tick`).
    pub epoch: Instant,
}

/// Creates the socket like oxenstored does (`ox/utils.ml:81-88`): missing
/// directories are created with mode 0700, a stale socket is replaced.
/// With `mode`, the socket gets it before it listens, so that no client
/// connects before (C xenstored: 0600, `cx417/xenstored_core.c:2588`).
fn bind(path: &Path, mode: Option<u32>) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(path)?;
    if let Some(mode) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    xs_sys::listen(&listener, 4096)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// A random key for the core's hash tables (`Core::new`), new at each
/// call: std's `RandomState`, whose keys come from the operating system,
/// hashes two values (`xs-core` has no operating system to ask).
pub fn hash_key() -> [u64; 2] {
    let s = std::hash::RandomState::new();
    [s.hash_one(0u8), s.hash_one(1u8)]
}

/// Serves until SIGTERM or SIGINT, or until `stop` is readable, which end
/// it cleanly: socket clients see their connection closed, as when
/// oxenstored is stopped; rings are left as they are (`rings.rs`). SIGHUP
/// reopens the log files (`ox/xenstored.ml:78-80`).
///
/// Unless `opts.domain_init` is false, `open` gives the Xen backend; with
/// it dom0's ring is served and guests can be introduced. Everything that
/// can fail at start is done before `ready`, which is called once, when
/// the daemon is about to serve; an error from it ends `run` with that
/// error.
pub fn run<X: XenBackend>(
    opts: &Options,
    open: impl FnOnce() -> io::Result<X>,
    stop: Option<&EventFd>,
    ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Before anything else: the signals are blocked from here on, and
    // read as events.
    let signals = xs_sys::signal_fd(&[xs_sys::SIGTERM, xs_sys::SIGINT, xs_sys::log::SIGHUP])?;
    // Each client holds a descriptor; the default soft limit is 1024.
    if let Err(e) = xs_sys::raise_fd_limit() {
        crate::echo!(Always, Warn, "xenstored", "cannot raise the open file limit: {e}");
    }
    // `ox/xenstored.ml:356-361`
    let listener = match opts.disable_socket {
        true => None,
        false => {
            let bound = bind(&opts.socket, opts.socket_mode);
            Some(bound.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", opts.socket.display())))?)
        }
    };
    let exe = std::env::current_exe()
        .map(|p| p.into_os_string().into_encoded_bytes())
        .unwrap_or_else(|_| b"rxenstored".to_vec());
    let core = Core::new(
        Config {
            tool_xenstored: exe,
            ..opts.config.clone()
        },
        hash_key(),
    );
    let epoll = Epoll::new()?;
    if let Some(l) = &listener {
        epoll.add(l.as_raw_fd(), LISTENER, Interest::READ)?;
    }
    epoll.add(signals.as_raw_fd(), SIGNALS, Interest::READ)?;
    if let Some(s) = stop {
        epoll.add(s.as_raw_fd(), STOP, Interest::READ)?;
    }
    let io = Io {
        xen: None,
        conns: HashMap::new(),
        ports: HashMap::new(),
        rings: BTreeSet::new(),
        scan: opts.ring_scan.map(Scan::new),
        dom_exc: None,
        ready: VecDeque::new(),
        to_flush: Vec::new(),
        touched: Vec::new(),
        buf: vec![0; READ_CHUNK],
        dying: false,
        backoff: None,
        virq_masked: false,
        accept_retry: None,
        accept_failing: false,
    };
    let mut r = Reactor {
        epoll,
        listener,
        core,
        io,
        signals,
        stop: None,
        epoch: Instant::now(),
    };
    if opts.domain_init {
        let xen = open().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot open the Xen devices (--no-domain-init serves the socket only): {e}"),
            )
        })?;
        r.start_xen(xen)?;
    }
    // After dom0's ring: oxenstored opens its access log after it too.
    crate::log::attach(&mut r.core);
    ready()?;
    match &r.listener {
        Some(_) => crate::echo!(Always, Info, "xenstored", "listening on {}", opts.socket.display()),
        None => crate::echo!(Always, Info, "xenstored", "no socket (--disable-socket)"),
    }
    r.serve()
}

impl<X: XenBackend> Reactor<X> {
    fn serve(&mut self) -> io::Result<()> {
        let mut events = Vec::new();
        let mut dirty = Vec::new();
        let mut flush = Vec::new();
        let mut dead = Vec::new();
        let mut drops = Vec::new();
        loop {
            let idle = self.io.ready.is_empty() && self.io.to_flush.is_empty() && !self.io.virq_masked;
            let timeout = if idle { self.timeout() } else { 0 };
            self.epoll.wait(&mut events, 1024, timeout)?;
            for ev in &events {
                self.event(ev);
            }
            if let Some(why) = self.stop.take() {
                crate::echo!(Always, Info, "xenstored", "stopped by {why}");
                return Ok(());
            }
            self.timers();
            // One turn for each connection that is ready now; those that
            // still have work go to the back of the queue.
            for _ in 0..self.io.ready.len() {
                if let Some(id) = self.io.ready.pop_front() {
                    self.turn(id);
                }
            }
            // What the turns queued, for their own connections and for
            // others (replies, watch events), goes out in this pass, and
            // so does what the flushes let go.
            for _ in 0..FLUSH_ROUNDS {
                self.core.take_dirty(&mut dirty);
                for id in dirty.drain(..) {
                    self.io.mark_flush(id);
                }
                if self.io.to_flush.is_empty() {
                    break;
                }
                std::mem::swap(&mut flush, &mut self.io.to_flush);
                for id in flush.drain(..) {
                    self.flush(id);
                }
            }
            self.settle_rings();
            self.core.take_dead(&mut dead);
            for (id, why) in dead.drain(..) {
                self.bury(id, why);
            }
            self.core.take_drops(&mut drops);
            for d in drops.drain(..) {
                log_drops(d);
            }
            // Closing a watcher lets go of those it held too: flushed at
            // the next pass, with no wait.
            self.core.take_dirty(&mut dirty);
            for id in dirty.drain(..) {
                self.io.mark_flush(id);
            }
            crate::log::kick();
        }
    }

    fn event(&mut self, ev: &Event) {
        match ev.token {
            LISTENER => return self.accept(),
            SIGNALS => {
                let signal = xs_sys::read_signal(&self.signals);
                if let Ok(Some(xs_sys::log::SIGHUP)) = signal {
                    crate::log::reopen();
                    return;
                }
                // A failed read stops the daemon too: it could not be stopped otherwise.
                self.stop = signal.map_or_else(
                    |e| Some(format!("a failure to read the signals: {e}")),
                    |s| s.map(|n| format!("signal {n}")),
                );
                return;
            }
            STOP => {
                self.stop = Some("request".into());
                return;
            }
            XEN => return self.xen_events(),
            _ => {}
        }
        let id = ConnId(ev.token);
        let Some(Conn {
            kind: Kind::Socket(c), ..
        }) = self.io.conns.get_mut(&ev.token)
        else {
            return;
        };
        if ev.readable || ev.closed {
            c.readable = true;
            self.io.enqueue(id);
        }
        if ev.writable {
            self.io.mark_flush(id);
        }
    }

    fn accept(&mut self) {
        let Some(listener) = &self.listener else { return };
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    self.io.accept_failing = false;
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let id = self.core.open();
                    if let Err(e) = self.epoll.add(stream.as_raw_fd(), id.0, Interest::READ_WRITE_EDGE) {
                        crate::error!("xenstored", "epoll: {e}");
                        self.core.close(id);
                        continue;
                    }
                    self.io.conns.insert(
                        id.0,
                        Conn::new(Kind::Socket(Client {
                            stream,
                            readable: false,
                        })),
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if !self.io.accept_failing {
                        crate::error!("xenstored", "accept: {e}");
                    }
                    self.io.accept_failing = true;
                    return self.pause_accept();
                }
            }
        }
    }

    /// The listener leaves the epoll set for `ACCEPT_RETRY`: the connection
    /// that could not be accepted waits in the kernel's queue meanwhile.
    fn pause_accept(&mut self) {
        let Some(listener) = &self.listener else { return };
        if self.epoll.delete(listener.as_raw_fd()).is_ok() {
            self.io.accept_retry = Some(Instant::now() + ACCEPT_RETRY);
        }
    }

    /// The listener is watched again, if it rested: a connection waiting
    /// makes it ready at once.
    pub(crate) fn resume_accept(&mut self) {
        let Some(listener) = &self.listener else { return };
        if self.io.accept_retry.take().is_some() {
            if let Err(e) = self.epoll.add(listener.as_raw_fd(), LISTENER, Interest::READ) {
                crate::error!("xenstored", "epoll: {e}");
                self.io.accept_retry = Some(Instant::now() + ACCEPT_RETRY);
            }
        }
    }

    fn turn(&mut self, id: ConnId) {
        let Some(c) = self.io.conns.get_mut(&id.0) else { return };
        c.queued = false;
        if matches!(c.kind, Kind::Ring(_)) {
            return self.ring_turn(id);
        }
        self.socket_turn(id);
    }

    fn socket_turn(&mut self, id: ConnId) {
        let Io { conns, buf, .. } = &mut self.io;
        let Some(Conn {
            kind: Kind::Socket(c),
            blocked,
            held,
            ..
        }) = conns.get_mut(&id.0)
        else {
            return;
        };
        if !self.core.wants_input(id) {
            *blocked = true;
            return;
        }
        let mut eof = false;
        if c.readable && !*held {
            loop {
                match (&c.stream).read(buf) {
                    Ok(0) => eof = true,
                    // `read` fills at most the buffer: past it would be a
                    // broken stream, closed.
                    Ok(n) => match buf.get(..n) {
                        Some(data) => {
                            self.core.feed(id, data);
                            // A short read emptied the socket; new data raises a new edge.
                            c.readable = n == buf.len();
                        }
                        None => eof = true,
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.readable = false,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => eof = true,
                }
                break;
            }
        }
        let readable = c.readable;
        let status = self.core.process_on(id, BUDGET, &mut self.io);
        if eof {
            // The client is gone: whatever it was owed cannot be delivered.
            return self.close(id);
        }
        let Some(conn) = self.io.conns.get_mut(&id.0) else {
            return;
        };
        conn.held = matches!(status, Status::More | Status::Blocked);
        match status {
            Status::More => self.io.enqueue(id),
            Status::Idle if readable => self.io.enqueue(id),
            Status::Blocked => conn.blocked = true,
            Status::Idle | Status::Closed => {}
        }
    }

    fn flush(&mut self, id: ConnId) {
        let Some(conn) = self.io.conns.get_mut(&id.0) else {
            return;
        };
        conn.flushing = false;
        let Kind::Socket(c) = &mut conn.kind else {
            return self.flush_ring(id);
        };
        loop {
            let out = self.core.output(id);
            if out.is_empty() {
                break;
            }
            match (&c.stream).write(out) {
                Ok(0) => break,
                Ok(n) => self.core.consume(id, n),
                // Full: the next EPOLLOUT edge brings us back.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return self.close(id),
            }
        }
        self.unblock(id);
    }

    /// Lets a connection held back by the soft limit go on once its output
    /// has drained below it.
    pub(crate) fn unblock(&mut self, id: ConnId) {
        let Some(conn) = self.io.conns.get_mut(&id.0) else {
            return;
        };
        if conn.blocked && self.core.wants_input(id) {
            conn.blocked = false;
            self.io.enqueue(id);
        }
    }

    /// A connection the core gave up on.
    fn bury(&mut self, id: ConnId, why: GaveUp) {
        match self.io.conns.get(&id.0).map(|c| &c.kind) {
            Some(Kind::Ring(_)) => self.ring_given_up(id, why),
            // A socket, or what is closed already (closing again does nothing).
            _ => self.close(id),
        }
    }

    fn close(&mut self, id: ConnId) {
        // Dropping the stream closes the descriptor, which leaves the epoll set.
        self.io.conns.remove(&id.0);
        self.core.close(id);
        // A descriptor is free: a connection that could not be accepted may be now.
        self.resume_accept();
    }
}

/// A streak of watch events dropped for a held watcher: one line when it
/// starts, one with the count when it ends; never one per event.
fn log_drops(d: Drops) {
    let name = |w: Who| match w {
        Who::Domain(domid) => format!("domain {domid}"),
        Who::Socket(n) => format!("connection A{n}"),
    };
    match d {
        Drops::Started(w) => crate::warn!(
            "connection",
            "{}: dropping watch events: it has twice quota-maxwatchevents unsent",
            name(w)
        ),
        Drops::Ended(w, n) => crate::warn!("connection", "{}: {n} watch events dropped, no more now", name(w)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn bind_creates_the_directory_and_replaces_a_stale_socket() {
        let dir = std::env::temp_dir().join(format!("rxenstored-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sock = dir.join("sub/socket");
        let l = bind(&sock, None).unwrap();
        let mode = std::fs::metadata(sock.parent().unwrap()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        drop(l);
        let _l = bind(&sock, None).unwrap();
        assert!(UnixStream::connect(&sock).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(bind(Path::new("/proc/rxenstored-cannot/socket"), None).is_err());
    }

    /// The socket's mode: what the umask leaves without one (that of a
    /// socket bound here by hand), the one given otherwise, whatever the
    /// umask; a client connects either way.
    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn bind_gives_the_socket_its_mode_if_asked() {
        let dir = std::env::temp_dir().join(format!("rxenstored-bind-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let by_hand = dir.join("by-hand");
        drop(UnixListener::bind(&by_hand).unwrap());
        let sock = dir.join("socket");
        let _l = bind(&sock, None).unwrap();
        assert_eq!(mode(&sock), mode(&by_hand));
        assert!(UnixStream::connect(&sock).is_ok());
        for m in [0o600, 0o640] {
            let _l = bind(&sock, Some(m)).unwrap();
            assert_eq!(mode(&sock), m);
            assert!(UnixStream::connect(&sock).is_ok());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A directory that exists keeps its mode; a path that cannot be
    /// removed (a directory) fails with that error, not a later one.
    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn bind_leaves_an_existing_directory_alone() {
        let dir = std::env::temp_dir().join(format!("rxenstored-bind-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o751)).unwrap();
        drop(bind(&dir.join("socket"), Some(0o600)).unwrap());
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o751);
        std::fs::create_dir(dir.join("taken")).unwrap();
        let e = bind(&dir.join("taken"), None).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EISDIR), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The key of the core's hash tables is drawn anew each time.
    #[test]
    fn hash_keys_differ() {
        let (a, b) = (hash_key(), hash_key());
        assert_ne!(a, b);
        assert_ne!(a, [0; 2]);
    }

    /// A connection is in the ready queue, and in the flush list, once per
    /// pass however often it is marked: it gets one turn, not one per mark.
    #[test]
    fn a_connection_is_queued_and_flushed_once_per_pass() {
        let mut io: Io<()> = Io {
            xen: None,
            conns: HashMap::new(),
            ports: HashMap::new(),
            rings: BTreeSet::new(),
            scan: None,
            dom_exc: None,
            ready: VecDeque::new(),
            to_flush: Vec::new(),
            touched: Vec::new(),
            buf: Vec::new(),
            dying: false,
            backoff: None,
            virq_masked: false,
            accept_retry: None,
            accept_failing: false,
        };
        let (a, _b) = UnixStream::pair().unwrap();
        let client = Client {
            stream: a,
            readable: false,
        };
        io.conns.insert(1, Conn::new(Kind::Socket(client)));
        for _ in 0..3 {
            io.enqueue(ConnId(1));
            io.mark_flush(ConnId(1));
        }
        // A connection that is gone is neither.
        io.enqueue(ConnId(2));
        io.mark_flush(ConnId(2));
        assert_eq!((io.ready, io.to_flush), (VecDeque::from([ConnId(1)]), vec![ConnId(1)]));
    }
}
