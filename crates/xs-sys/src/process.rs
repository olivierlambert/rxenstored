// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Becoming a daemon: fork, session, readiness pipe, systemd notification.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;

/// First byte of the report the daemon sends to the process that started it.
const READY: u8 = b'R';
const FAILED: u8 = b'F';

/// What `daemonize` returns, in each of the two processes that see it return.
#[derive(Debug)]
pub enum Daemonized {
    /// The process that called `daemonize`, once the daemon has reported:
    /// it exits with this outcome.
    Parent(Result<(), String>),
    /// The daemon: a new process in a new session, whose parent is gone.
    Daemon(Readiness),
}

/// The daemon's half of the readiness pipe; nothing if it did not fork.
#[derive(Debug)]
pub struct Readiness(Option<PipeWriter>);

impl Readiness {
    /// For a daemon that did not fork: nobody waits for its report.
    pub fn unpiped() -> Readiness {
        Readiness(None)
    }

    /// Reports on `w`, as the daemon `daemonize` returns does; for tests.
    pub fn on_pipe(w: PipeWriter) -> Readiness {
        Readiness(Some(w))
    }

    /// True if a parent waits for the report.
    pub fn is_piped(&self) -> bool {
        self.0.is_some()
    }

    /// Releases the waiting parent, which exits 0.
    pub fn ready(self) -> io::Result<()> {
        self.send(&[READY])
    }

    /// The parent prints `message` and exits non-zero.
    pub fn failed(self, message: &str) -> io::Result<()> {
        self.send(&[&[FAILED], message.as_bytes()].concat())
    }

    fn send(self, report: &[u8]) -> io::Result<()> {
        // Dropping the writer closes the pipe: the parent reads to its end.
        match self.0 {
            Some(mut w) => w.write_all(report),
            None => Ok(()),
        }
    }
}

/// Reads the daemon's report to the end of the pipe, which comes when the
/// daemon has reported or has died.
fn read_report(mut r: impl Read) -> Result<(), String> {
    let mut report = Vec::new();
    r.read_to_end(&mut report).map_err(|e| format!("readiness pipe: {e}"))?;
    match report.split_first() {
        Some((&READY, _)) => Ok(()),
        Some((&FAILED, message)) => Err(String::from_utf8_lossy(message).into_owned()),
        Some(_) => Err("garbled report from the daemon".into()),
        None => Err("the daemon exited before it was ready".into()),
    }
}

/// Puts /dev/null on each of `targets`.
fn null_onto(targets: &[RawFd]) -> io::Result<()> {
    let null = File::options().read(true).write(true).open("/dev/null")?;
    for &fd in targets {
        // SAFETY: dup2 closes `fd` and makes it a copy of `null`; callers
        // pass the standard descriptors, which nothing in the process owns
        // as an OwnedFd, or a descriptor they own and keep using as such.
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Waits for a child, retrying when interrupted.
fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `status` is a valid, writable int for the duration of the call.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
    {}
}

/// The `Threads:` line of a `/proc/PID/status` text.
fn threads_in_status(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
}

/// Ok if this process has a single thread, which `fork` needs for the
/// child to start from a consistent state; else why not (or that it
/// cannot tell: no /proc).
fn single_threaded() -> io::Result<()> {
    one_thread_in(std::fs::read_to_string("/proc/self/status"))
}

/// `single_threaded` on what reading `/proc/self/status` gave.
fn one_thread_in(status: io::Result<String>) -> io::Result<()> {
    let status = status.map_err(|e| io::Error::new(e.kind(), format!("/proc/self/status: {e}")))?;
    match threads_in_status(&status) {
        Some(1) => Ok(()),
        Some(n) => Err(io::Error::other(format!(
            "cannot become a daemon with {n} threads: fork keeps only the calling one"
        ))),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "/proc/self/status: no thread count",
        )),
    }
}

/// Detaches from the caller as oxenstored does (`ox/stdext.ml:118-139`):
/// fork, new session, fork again so that the daemon is not a session
/// leader and cannot acquire a terminal, stdin and stdout on /dev/null.
/// stderr is kept if `keep_stderr` (oxenstored discards it, but it has a
/// log file). Unlike oxenstored, the calling process does not exit at once:
/// `daemonize` returns `Parent` once the daemon has reported through its
/// `Readiness` (or has died), so that whoever started it finds it ready.
///
/// Fails, without forking, if the process has more than one thread: the
/// children would keep only the calling thread, and a lock another thread
/// held at the fork (in stdio, in the environment) would stay locked in
/// them for ever.
pub fn daemonize(keep_stderr: bool) -> io::Result<Daemonized> {
    single_threaded()?;
    fork_twice(keep_stderr)
}

/// `daemonize` once the process is known to have a single thread.
// cov:excl-start daemonize
fn fork_twice(keep_stderr: bool) -> io::Result<Daemonized> {
    let (r, w) = io::pipe()?;
    // SAFETY: the process has a single thread (`daemonize` checked it,
    // and nothing here starts one), so the child starts from a consistent
    // state; both processes own copies of the same descriptors, each
    // dropping the end it does not use.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(r);
            let mut w = w;
            // SAFETY: plain syscall; this child is not a group leader (its
            // pid is new), so setsid cannot fail with EPERM.
            if unsafe { libc::setsid() } < 0 {
                let _ = write!(w, "{}setsid: {}", FAILED as char, io::Error::last_os_error());
                // SAFETY: ends this child without running the parent's
                // exit handlers or destructors twice.
                unsafe { libc::_exit(1) };
            }
            // SAFETY: still a single thread, as above.
            match unsafe { libc::fork() } {
                -1 => {
                    let _ = write!(w, "{}fork: {}", FAILED as char, io::Error::last_os_error());
                    // SAFETY: as above.
                    unsafe { libc::_exit(1) }
                }
                0 => {
                    let mut targets = vec![libc::STDIN_FILENO, libc::STDOUT_FILENO];
                    if !keep_stderr {
                        targets.push(libc::STDERR_FILENO);
                    }
                    if let Err(e) = null_onto(&targets) {
                        let _ = write!(w, "{}/dev/null: {e}", FAILED as char);
                        // SAFETY: as above.
                        unsafe { libc::_exit(1) };
                    }
                    Ok(Daemonized::Daemon(Readiness(Some(w))))
                }
                // SAFETY: the intermediate process has done its part.
                _ => unsafe { libc::_exit(0) },
            }
        }
        pid => {
            drop(w);
            reap(pid);
            Ok(Daemonized::Parent(read_report(r)))
        }
    }
}
// cov:excl-stop daemonize

/// Sends `state` to systemd's notification socket, the value of
/// `$NOTIFY_SOCKET`: a path, or an abstract name written with a leading `@`
/// (as sd_notify(3) takes it).
pub fn notify(socket: &OsStr, state: &str) -> io::Result<()> {
    let sock = UnixDatagram::unbound()?;
    let bytes = socket.as_bytes();
    // A datagram goes whole or not at all.
    match bytes.split_first() {
        Some((b'@', name)) => sock.send_to_addr(state.as_bytes(), &SocketAddr::from_abstract_name(name)?)?,
        Some((b'/', _)) => sock.send_to(state.as_bytes(), Path::new(socket))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported notification socket {}", socket.to_string_lossy()),
            ))
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    fn report(send: impl FnOnce(Readiness) -> io::Result<()>) -> Result<(), String> {
        let (r, w) = io::pipe().map_err(|e| e.to_string())?;
        let readiness = Readiness::on_pipe(w);
        if !readiness.is_piped() {
            return Err("not piped".into());
        }
        send(readiness).map_err(|e| e.to_string())?;
        read_report(r)
    }

    #[test]
    fn readiness_reports_reach_the_parent() {
        assert_eq!(report(Readiness::ready), Ok(()));
        assert_eq!(report(|r| r.failed("cannot bind")), Err("cannot bind".into()));
        assert_eq!(report(|r| r.failed("")), Err("".into()));
        // A daemon that dies without a word, or says something else.
        assert_eq!(
            report(|r| {
                drop(r);
                Ok(())
            }),
            Err("the daemon exited before it was ready".into())
        );
        assert_eq!(report(|r| r.send(b"?")), Err("garbled report from the daemon".into()));
        // Nobody listens.
        let r = Readiness::unpiped();
        assert!(!r.is_piped());
        r.ready().unwrap();
        Readiness::unpiped().failed("x").unwrap();
        // The parent is gone.
        let (r, w) = io::pipe().unwrap();
        drop(r);
        assert!(Readiness(Some(w)).ready().is_err());
        // An unreadable pipe.
        assert!(read_report(File::options().write(true).open("/dev/null").unwrap())
            .unwrap_err()
            .starts_with("readiness pipe: "));
    }

    #[test]
    fn the_thread_count_is_read_from_proc_status() {
        assert_eq!(threads_in_status("Name:\tx\nThreads:\t1\nSigQ:\t0/1\n"), Some(1));
        assert_eq!(threads_in_status("Threads:   12\n"), Some(12));
        assert_eq!(threads_in_status("Name:\tx\n"), None);
        assert_eq!(threads_in_status("Threads:\tmany\n"), None);
        assert!(one_thread_in(Ok("Threads:\t1\n".into())).is_ok());
        let e = one_thread_in(Ok("Threads:\t3\n".into())).unwrap_err();
        assert_eq!(
            e.to_string(),
            "cannot become a daemon with 3 threads: fork keeps only the calling one"
        );
        let e = one_thread_in(Ok("Name:\tx\n".into())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let e = one_thread_in(Err(io::Error::from_raw_os_error(libc::ENOENT))).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().starts_with("/proc/self/status: "), "{e}");
    }

    /// A process with another thread is refused before any fork: the
    /// test harness, with a thread of the test's own to be sure.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "reads /proc/self/status, which counts the host's threads, not Miri's"
    )]
    fn daemonize_refuses_a_process_with_threads() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let r = daemonize(true);
        drop(tx);
        other.join().unwrap();
        match r {
            Err(e) => assert!(
                e.to_string().contains("threads: fork keeps only the calling one"),
                "{e}"
            ),
            // Had it forked, the copy of the harness must not go on.
            Ok(Daemonized::Daemon(_)) => {
                // SAFETY: ends the forked copy at once.
                unsafe { libc::_exit(0) }
            }
            Ok(Daemonized::Parent(p)) => panic!("forked with threads: {p:?}"),
        }
        assert!(single_threaded().is_err());
    }

    #[test]
    fn null_replaces_a_descriptor() {
        let path = std::env::temp_dir().join(format!("xs-sys-null-{}", std::process::id()));
        let mut f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        f.write_all(b"before").unwrap();
        null_onto(&[f.as_raw_fd()]).unwrap();
        f.write_all(b"after").unwrap();
        f.rewind().unwrap();
        let mut back = Vec::new();
        f.read_to_end(&mut back).unwrap();
        assert!(back.is_empty());
        assert!(null_onto(&[-1]).is_err());
        // Descriptor 0, as `daemonize` does (dup2 returns it: 0 is no
        // error). No test reads this process's stdin.
        null_onto(&[libc::STDIN_FILENO]).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "process spawning: not emulated by Miri")]
    #[allow(clippy::zombie_processes)] // reap is the wait
    fn reap_waits_for_a_child() {
        let child = std::process::Command::new("true").spawn().unwrap();
        reap(child.id() as libc::pid_t);
        assert!(!Path::new(&format!("/proc/{}", child.id())).exists());
        // Not a child: returns at once.
        reap(1);
    }

    /// A wait cut short by a signal whose handler does not restart system
    /// calls (EINTR) is made again: the child is reaped all the same.
    #[test]
    #[cfg_attr(miri, ignore = "process spawning: not emulated by Miri")]
    #[allow(clippy::zombie_processes)] // reap is the wait
    fn reap_waits_again_after_an_interruption() {
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: `nothing` is async-signal-safe (it does nothing); no
        // other test uses SIGWINCH; `sa` is valid for the call.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // No SA_RESTART: the signal makes the wait fail with EINTR.
            sa.sa_flags = 0;
            assert_eq!(libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut()), 0);
        }
        // A child that lives until its stdin is closed.
        let mut child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let stdin = child.stdin.take().unwrap();
        // SAFETY: plain call; the id stays valid while this thread runs,
        // and the helper stops before this function returns.
        let me = unsafe { libc::pthread_self() } as usize;
        let task = crate::testing::this_task();
        let helper = std::thread::spawn(move || {
            let waits = [libc::SYS_wait4];
            let sleeps = crate::testing::wait_asleep_in(&task, &waits, None);
            // SAFETY: `me` names a live thread (see above).
            unsafe { libc::pthread_kill(me as libc::pthread_t, libc::SIGWINCH) };
            // Asleep in the wait again, after the interruption.
            crate::testing::wait_asleep_in(&task, &waits, Some(sleeps));
            drop(stdin);
        });
        reap(pid);
        // Reaped, so it had exited: the helper closed its stdin after the
        // interrupted wait was made again.
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        helper.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "AF_UNIX sockets: not emulated by Miri")]
    fn notify_paths_and_abstract_names() {
        let path = std::env::temp_dir().join(format!("xs-sys-notify-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixDatagram::bind(&path).unwrap();
        notify(path.as_os_str(), "READY=1\nMAINPID=7\n").unwrap();
        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nMAINPID=7\n");
        std::fs::remove_file(&path).unwrap();
        assert!(notify(path.as_os_str(), "READY=1").is_err(), "nobody listens");

        let name = format!("xs-sys-notify-{}", std::process::id());
        let listener = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
        notify(OsStr::new(&format!("@{name}")), "READY=1").unwrap();
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");

        for bad in ["", "relative", "vsock:2:1"] {
            assert_eq!(
                notify(OsStr::new(bad), "READY=1").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let long = format!("@{}", "x".repeat(200));
        assert!(notify(OsStr::new(&long), "READY=1").is_err());
    }
}
