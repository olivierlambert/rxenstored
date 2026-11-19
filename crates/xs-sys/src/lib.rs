// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The only crate of the workspace allowed to contain `unsafe`. Each
//! wrapper is a thin, safe interface over one system call; every unsafe
//! block states the invariant it relies on.

#![deny(unsafe_op_in_unsafe_fn)]
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

pub mod backend;
pub mod fd;
pub mod log;
pub mod map;
pub mod process;
pub mod ring;
#[cfg(test)]
mod testing;
pub mod xen;

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

/// Raises the soft limit on open files to the hard limit and returns it.
pub fn raise_fd_limit() -> io::Result<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of both calls.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) < 0 {
            return Err(io::Error::last_os_error());
        }
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(lim.rlim_cur)
}

/// Calls `listen` again on a bound socket to change its backlog (the
/// standard library picks its own).
pub fn listen(fd: &impl AsRawFd, backlog: i32) -> io::Result<()> {
    // SAFETY: plain syscall on an integer descriptor, no pointers.
    if unsafe { libc::listen(fd.as_raw_fd(), backlog) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub const SIGINT: i32 = libc::SIGINT;
pub const SIGTERM: i32 = libc::SIGTERM;

/// The set of `signals`.
fn sigset(signals: &[i32]) -> io::Result<libc::sigset_t> {
    // SAFETY: `set` is a valid, writable sigset_t for every call; it is
    // initialised by sigemptyset before it is read.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in signals {
            if libc::sigaddset(&mut set, s) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(set)
    }
}

fn block(set: &libc::sigset_t) -> io::Result<()> {
    // SAFETY: `set` is a valid sigset_t; a null old set is allowed.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// Blocks `signals` in the calling thread and in the threads and
/// processes it starts later: one that comes meanwhile stays pending, and
/// a `signal_fd` of them made later reads it. Blocking them again is
/// harmless.
pub fn block_signals(signals: &[i32]) -> io::Result<()> {
    block(&sigset(signals)?)
}

/// Signals as readable events: blocks `signals` in the calling thread
/// (and in the threads it starts later) and returns a non-blocking
/// descriptor that is readable while one of them is pending, including
/// one that came while they were blocked before the call. The daemon
/// calls it once, before it starts any thread.
pub fn signal_fd(signals: &[i32]) -> io::Result<OwnedFd> {
    let set = sigset(signals)?;
    block(&set)?;
    // SAFETY: `set` is a valid sigset_t.
    unsafe {
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // `fd` is a fresh descriptor that nothing else owns.
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Takes one pending signal from a descriptor of `signal_fd`; None if
/// none is pending.
pub fn read_signal(fd: &impl AsRawFd) -> io::Result<Option<i32>> {
    // SAFETY: all-zero bytes are a valid signalfd_siginfo (integers only).
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: `info` is valid and writable for `size` bytes.
    let n = unsafe { libc::read(fd.as_raw_fd(), (&mut info as *mut libc::signalfd_siginfo).cast(), size) };
    if n < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(err)
        };
    }
    if n as usize != size {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a signal descriptor"));
    }
    Ok(Some(info.ssi_signo as i32))
}

/// What to wait for on a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest {
    pub read: bool,
    pub write: bool,
    /// Edge-triggered: an event is reported once per change of state.
    pub edge: bool,
}

impl Interest {
    pub const READ: Interest = Interest {
        read: true,
        write: false,
        edge: false,
    };
    pub const READ_WRITE_EDGE: Interest = Interest {
        read: true,
        write: true,
        edge: true,
    };

    fn bits(self) -> u32 {
        let mut b = 0;
        if self.read {
            b |= libc::EPOLLIN | libc::EPOLLRDHUP;
        }
        if self.write {
            b |= libc::EPOLLOUT;
        }
        if self.edge {
            b |= libc::EPOLLET;
        }
        b as u32
    }
}

/// One readiness report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub token: u64,
    pub readable: bool,
    pub writable: bool,
    /// Hang-up or error: the next read or write tells which.
    pub closed: bool,
}

pub struct Epoll {
    fd: OwnedFd,
    /// What `wait` hands the kernel, kept from one wait to the next (a
    /// lock, so that `wait` takes `&self` as the other calls do).
    buf: Mutex<Vec<libc::epoll_event>>,
}

impl Epoll {
    pub fn new() -> io::Result<Epoll> {
        // SAFETY: plain syscall, no pointers.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor that nothing else owns.
        Ok(Epoll {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            buf: Mutex::new(Vec::new()),
        })
    }

    fn ctl(&self, op: libc::c_int, fd: RawFd, token: u64, interest: Interest) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events: interest.bits(),
            u64: token,
        };
        // SAFETY: `ev` is a valid epoll_event for the duration of the call.
        if unsafe { libc::epoll_ctl(self.fd.as_raw_fd(), op, fd, &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Starts watching `fd`; events carry `token`.
    pub fn add(&self, fd: RawFd, token: u64, interest: Interest) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_ADD, fd, token, interest)
    }

    #[cfg(test)]
    pub fn modify(&self, fd: RawFd, token: u64, interest: Interest) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_MOD, fd, token, interest)
    }

    /// Stops watching `fd` (closing it does the same).
    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_DEL, fd, 0, Interest::READ)
    }

    /// Replaces the content of `out` with at most `max` events, waiting at
    /// most `timeout_ms` (-1: forever). An interrupted wait returns no event.
    pub fn wait(&self, out: &mut Vec<Event>, max: usize, timeout_ms: i32) -> io::Result<()> {
        out.clear();
        let max = max.clamp(1, 4096);
        // A thread that panicked holding it left nothing to undo.
        let mut events = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        events.resize(max, libc::epoll_event { events: 0, u64: 0 });
        // SAFETY: `events` is a valid, writable array of `max` epoll_event.
        let n = unsafe { libc::epoll_wait(self.fd.as_raw_fd(), events.as_mut_ptr(), max as libc::c_int, timeout_ms) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(err);
        }
        let hup = (libc::EPOLLHUP | libc::EPOLLERR | libc::EPOLLRDHUP) as u32;
        // `epoll_wait` fills at most `max` entries: `n <= events.len()`.
        out.extend(events.iter().take(n as usize).map(|e| Event {
            token: e.u64,
            readable: e.events & libc::EPOLLIN as u32 != 0,
            writable: e.events & libc::EPOLLOUT as u32 != 0,
            closed: e.events & hup != 0,
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    #[cfg_attr(miri, ignore = "getrlimit: not emulated by Miri")]
    fn fd_limit_is_raised_to_the_hard_limit() {
        let limit = raise_fd_limit().unwrap();
        assert!(limit >= 1024);
        assert_eq!(raise_fd_limit().unwrap(), limit);
    }

    #[test]
    fn level_triggered_read() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let ep = Epoll::new().unwrap();
        ep.add(a.as_raw_fd(), 7, Interest::READ).unwrap();
        let mut ev = Vec::new();
        ep.wait(&mut ev, 16, 0).unwrap();
        assert!(ev.is_empty());
        b.write_all(b"x").unwrap();
        for _ in 0..2 {
            ep.wait(&mut ev, 16, 1000).unwrap();
            assert_eq!(
                ev,
                [Event {
                    token: 7,
                    readable: true,
                    writable: false,
                    closed: false
                }]
            );
        }
        ep.delete(a.as_raw_fd()).unwrap();
        ep.wait(&mut ev, 16, 0).unwrap();
        assert!(ev.is_empty());
        assert!(ep.delete(a.as_raw_fd()).is_err());
        assert!(ep.add(-1, 0, Interest::READ).is_err());
        assert!(ep.modify(a.as_raw_fd(), 0, Interest::READ).is_err());
    }

    #[test]
    fn edge_triggered_read_write_and_hangup() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let ep = Epoll::new().unwrap();
        ep.add(a.as_raw_fd(), 1, Interest::READ_WRITE_EDGE).unwrap();
        let mut ev = Vec::new();
        ep.wait(&mut ev, 16, 1000).unwrap();
        assert_eq!(
            ev,
            [Event {
                token: 1,
                readable: false,
                writable: true,
                closed: false
            }]
        );
        // Reported once per change only.
        ep.wait(&mut ev, 16, 0).unwrap();
        assert!(ev.is_empty());
        (&b).write_all(b"hello").unwrap();
        ep.wait(&mut ev, 16, 1000).unwrap();
        assert_eq!(ev.len(), 1);
        assert!(ev[0].readable);
        let mut buf = [0u8; 16];
        assert_eq!(a.read(&mut buf).unwrap(), 5);
        drop(b);
        ep.wait(&mut ev, 16, 1000).unwrap();
        assert!(ev[0].closed);
        ep.modify(a.as_raw_fd(), 2, Interest::READ).unwrap();
        ep.wait(&mut ev, 1, 1000).unwrap();
        assert_eq!(ev[0].token, 2);
    }

    /// A hang-up alone (a pipe whose writer closed: no EPOLLRDHUP, which
    /// only sockets report) and an error alone (a pipe whose reader closed,
    /// seen by the writer) are each reported as closed.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's epoll does not report a pipe's hang-up and error as Linux does (it tells of them, or not, from one run to the next)"
    )]
    fn a_pipe_closed_at_the_other_end_is_closed() {
        let ep = Epoll::new().unwrap();
        let mut ev = Vec::new();
        let (r, w) = std::io::pipe().unwrap();
        ep.add(r.as_raw_fd(), 1, Interest::READ).unwrap();
        drop(w);
        ep.wait(&mut ev, 16, 1000).unwrap();
        // Closed (whether it is also readable, Linux says no, Miri yes).
        let closed = |ev: &[Event]| ev.iter().map(|e| (e.token, e.closed)).collect::<Vec<_>>();
        assert_eq!(closed(&ev), [(1, true)]);
        drop(r);
        let (r, w) = std::io::pipe().unwrap();
        let write = Interest {
            read: false,
            write: true,
            edge: false,
        };
        ep.add(w.as_raw_fd(), 2, write).unwrap();
        drop(r);
        ep.wait(&mut ev, 16, 1000).unwrap();
        assert_eq!(closed(&ev), [(2, true)]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "signal handlers: not emulated by Miri")]
    fn wait_reports_errors_and_shrugs_off_interruptions() {
        // Not an epoll descriptor.
        let (a, _b) = UnixStream::pair().unwrap();
        let not_epoll = Epoll {
            fd: a.into(),
            buf: Mutex::new(Vec::new()),
        };
        let mut ev = vec![Event {
            token: 1,
            readable: true,
            writable: true,
            closed: true,
        }];
        assert!(not_epoll.wait(&mut ev, 16, 0).is_err());
        assert!(ev.is_empty());

        // A signal with a handler interrupts the wait: no event, no error.
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: `nothing` is async-signal-safe (it does nothing); the
        // only other user of SIGUSR2 in this process installs the same.
        unsafe {
            libc::signal(
                libc::SIGUSR2,
                nothing as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
        let ep = Epoll::new().unwrap();
        // SAFETY: plain call; the id stays valid while this thread runs,
        // and the sender stops before this function returns.
        let me = unsafe { libc::pthread_self() } as usize;
        let task = testing::this_task();
        let sender = std::thread::spawn(move || {
            // While the wait sleeps.
            testing::wait_asleep(&task, None);
            // SAFETY: `me` names a live thread (see above).
            unsafe { libc::pthread_kill(me as libc::pthread_t, libc::SIGUSR2) };
        });
        let start = std::time::Instant::now();
        ep.wait(&mut ev, 16, 20_000).unwrap();
        sender.join().unwrap();
        assert!(ev.is_empty());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "interrupted, not timed out"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "signal masks and signalfd: not emulated by Miri")]
    fn signals_are_read_from_a_descriptor() {
        // Blocked in this thread only, and sent to this thread only.
        let fd = signal_fd(&[libc::SIGUSR1, SIGTERM]).unwrap();
        assert_eq!(read_signal(&fd).unwrap(), None);
        let ep = Epoll::new().unwrap();
        ep.add(fd.as_raw_fd(), 9, Interest::READ).unwrap();
        let mut ev = Vec::new();
        ep.wait(&mut ev, 4, 0).unwrap();
        assert!(ev.is_empty());
        // SAFETY: plain calls; the signals are blocked, so they stay pending.
        unsafe {
            libc::raise(libc::SIGUSR1);
            libc::raise(SIGTERM);
        }
        ep.wait(&mut ev, 4, 1000).unwrap();
        assert_eq!(
            ev,
            [Event {
                token: 9,
                readable: true,
                writable: false,
                closed: false
            }]
        );
        let mut got = [read_signal(&fd).unwrap().unwrap(), read_signal(&fd).unwrap().unwrap()];
        got.sort();
        assert_eq!(got, [libc::SIGUSR1, SIGTERM]);
        assert_eq!(read_signal(&fd).unwrap(), None);
        // Errors: an invalid signal number, a closed descriptor, and a
        // descriptor of another kind.
        assert!(signal_fd(&[100_000]).is_err());
        assert!(read_signal(&-1).is_err());
        let (a, b) = UnixStream::pair().unwrap();
        (&b).write_all(b"short").unwrap();
        assert_eq!(read_signal(&a).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// A signal that comes after `block_signals` and before `signal_fd`
    /// waits, and the descriptor reads it: a start-up window loses none.
    #[test]
    #[cfg_attr(miri, ignore = "signal masks and signalfd: not emulated by Miri")]
    fn a_signal_blocked_before_the_descriptor_is_read_from_it() {
        block_signals(&[libc::SIGUSR1]).unwrap();
        block_signals(&[libc::SIGUSR1]).unwrap();
        // SAFETY: plain call; the signal is blocked in this thread, so it
        // stays pending.
        unsafe { libc::raise(libc::SIGUSR1) };
        let fd = signal_fd(&[libc::SIGUSR1]).unwrap();
        assert_eq!(read_signal(&fd).unwrap(), Some(libc::SIGUSR1));
        assert_eq!(read_signal(&fd).unwrap(), None);
        assert!(block_signals(&[100_000]).is_err());
    }

    /// Descriptor 0 is a descriptor like any other: a process whose stdin
    /// is closed gets it from the next call that makes one, which must not
    /// take it for an error. In a child (this test run again), so that no
    /// other test's descriptor takes the place.
    #[test]
    #[cfg_attr(miri, ignore = "process spawning: not emulated by Miri")]
    fn a_new_descriptor_may_be_0() {
        const CHILD: &str = "XS_SYS_TEST_FD0_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::a_new_descriptor_may_be_0", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && text.contains("all at 0"), "{text}");
            return;
        }
        let close0 = || {
            // SAFETY: descriptor 0 is the child's stdin, which nothing
            // in it owns or reads.
            unsafe { libc::close(0) };
        };
        close0();
        let m = fd::memfd("zero", 4096).unwrap();
        assert_eq!(m.file().as_raw_fd(), 0);
        drop(m);
        let e = fd::EventFd::new().unwrap();
        assert_eq!(e.as_raw_fd(), 0);
        drop(e);
        let s = signal_fd(&[libc::SIGUSR1]).unwrap();
        assert_eq!(s.as_raw_fd(), 0);
        drop(s);
        let ep = Epoll::new().unwrap();
        assert_eq!(ep.fd.as_raw_fd(), 0);
        println!("all at 0");
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn listen_changes_the_backlog() {
        let dir = std::env::temp_dir().join(format!("xs-sys-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let l = UnixListener::bind(&dir).unwrap();
        listen(&l, 4096).unwrap();
        let _c = UnixStream::connect(&dir).unwrap();
        assert!(l.accept().is_ok());
        std::fs::remove_file(&dir).unwrap();
        let (s, _) = UnixStream::pair().unwrap();
        assert!(listen(&s, 1).is_err());
    }
}
