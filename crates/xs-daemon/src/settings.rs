// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What the daemon is asked to do, whichever front end read it.
//!
//! Two front ends read a command line and a configuration file: `native`
//! (rxenstored's own, the default) and `compat` (oxenstored's, selected by
//! `--compat=oxenstored`). Each produces the same `Settings`; the rest of
//! the daemon knows which was used only through the behaviour profile,
//! `xs_core::Config::profile`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use xs_daemon::reactor;

/// What the command line and the configuration ask for.
#[derive(Debug)]
pub enum Plan {
    /// Print this usage text and exit 0.
    Usage(&'static str),
    /// Print the version and exit 0.
    Version,
    /// The configuration file at this path is valid: say so and exit 0.
    ConfigValid(PathBuf),
    Start(Box<Settings>),
}

#[derive(Debug)]
pub enum Failure {
    /// A bad command line: the message, then this usage text; exit 2.
    Usage(String, &'static str),
    /// Exit 1 with the message.
    Fatal(String),
}

#[derive(Debug)]
pub struct Settings {
    pub options: reactor::Options,
    pub daemonize: bool,
    /// Written once the daemon serves; a failure to write it is reported
    /// and the daemon goes on.
    pub extra_pid_file: Option<PathBuf>,
    /// Written once the daemon serves; a failure to write it stops the
    /// start.
    pub pid_file: Option<PathBuf>,
    /// `$NOTIFY_SOCKET`: where to send `READY=1`.
    pub notify_socket: Option<OsString>,
    pub log: xs_daemon::log::Settings,
}

/// The program name, as `syslog(3)` takes it when `openlog` was not
/// called (glibc's `__progname`).
pub fn ident() -> String {
    let argv0 = std::env::args_os().next().unwrap_or_default();
    Path::new(&argv0)
        .file_name()
        .map_or_else(|| "rxenstored".into(), |n| n.to_string_lossy().into_owned())
}
