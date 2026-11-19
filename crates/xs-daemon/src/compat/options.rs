// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The command line of oxenstored (`ox/parse_arg.ml:43-58` in Xen 4.17,
//! `--config-test` from later releases), read as OCaml's `Arg.parse` reads
//! it: options in order, a value either in the next argument (whatever it
//! looks like) or after `=` in the same one, other arguments ignored,
//! `--help` ending the parse. Plus rxenstored's own `--socket PATH` and
//! `--foreground` (the same as `--no-fork`). `--compat=oxenstored`, which
//! selects this command line, is taken out before (`main.rs`, `select`).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub const DEFAULT_SOCKET: &str = "/var/run/xenstored/socket";
pub const DEFAULT_CONFIG: &str = "/etc/xen/oxenstored.conf";

pub const USAGE: &str = "\
usage: rxenstored --compat=oxenstored [OPTION]...
  (oxenstored's command line and oxenstored.conf; without --compat,
  rxenstored's own: rxenstored --help)
  --config-file FILE  configuration file (default /etc/xen/oxenstored.conf)
  --config-test       check the configuration file and exit
  --no-fork           stay in the foreground (also --foreground)
  --pid-file FILE     write the daemon's pid to FILE too
  --no-domain-init    do not map dom0's ring nor bind the event channels
  --disable-socket    do not listen on the unix socket (the rings only)
  --socket PATH       unix socket to listen on (default /var/run/xenstored/socket)
  --no-access-log     do not write an access log
  --reraise-top-level accepted for oxenstored compatibility
  -T FILE             trace file (not implemented yet)
  --restart, --live   live update hand-over (not supported: refused)
  --help              print this and exit
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub domain_init: bool,
    pub config_file: Option<PathBuf>,
    pub daemonize: bool,
    pub reraise_top_level: bool,
    pub access_log: bool,
    pub pid_file: Option<PathBuf>,
    pub trace_file: Option<PathBuf>,
    pub restart: bool,
    pub live: bool,
    pub config_test: bool,
    pub disable_socket: bool,
    pub socket: PathBuf,
    /// `--help` was given; what follows it was not read.
    pub help: bool,
    /// Arguments that are not options: oxenstored ignores them.
    pub ignored: Vec<OsString>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            domain_init: true,
            config_file: None,
            daemonize: true,
            reraise_top_level: false,
            access_log: true,
            pid_file: None,
            trace_file: None,
            restart: false,
            live: false,
            config_test: false,
            disable_socket: false,
            socket: DEFAULT_SOCKET.into(),
            help: false,
            ignored: Vec::new(),
        }
    }
}

/// An empty value unsets, as `Arg.Set_string` into "" does in oxenstored.
fn path(v: OsString) -> Option<PathBuf> {
    (!v.is_empty()).then(|| v.into())
}

pub fn parse(argv: &[OsString]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let bytes = arg.as_encoded_bytes();
        if bytes.first() != Some(&b'-') {
            a.ignored.push(arg.clone());
            continue;
        }
        let shown = arg.to_string_lossy();
        // `--key=value`, as Arg.parse takes it, for a key that is not itself known.
        let (name, inline) = match arg.to_str().filter(|s| !is_option(s)).and_then(|s| s.split_once('=')) {
            Some((k, v)) => (k.to_string(), Some(OsString::from(v))),
            None => (shown.to_string(), None),
        };
        if !is_option(&name) {
            return Err(format!("unknown option '{shown}'"));
        }
        let mut value = || -> Result<OsString, String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("option '{name}' needs an argument")),
            }
        };
        match name.as_str() {
            "--config-file" => a.config_file = path(value()?),
            "--pid-file" => a.pid_file = path(value()?),
            "-T" => a.trace_file = path(value()?),
            "--socket" => a.socket = value()?.into(),
            _ if inline.is_some() => {
                return Err(format!(
                    "wrong argument '{}'; option '{name}' expects no argument",
                    inline.as_deref().map(OsStr::to_string_lossy).unwrap_or_default()
                ))
            }
            "--no-domain-init" => a.domain_init = false,
            "--no-fork" | "--foreground" => a.daemonize = false,
            "--reraise-top-level" => a.reraise_top_level = true,
            "--no-access-log" => a.access_log = false,
            "--restart" => a.restart = true,
            "--live" => a.live = true,
            "--config-test" => a.config_test = true,
            "--disable-socket" => a.disable_socket = true,
            _ => {
                // --help, -help, -h
                a.help = true;
                break;
            }
        }
    }
    Ok(a)
}

fn is_option(s: &str) -> bool {
    const KNOWN: &[&str] = &[
        "--no-domain-init",
        "--config-file",
        "--no-fork",
        "--reraise-top-level",
        "--no-access-log",
        "--pid-file",
        "-T",
        "--restart",
        "--live",
        "--config-test",
        "--disable-socket",
        "--help",
        "-help",
        "-h",
        "--socket",
        "--foreground",
    ];
    KNOWN.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(a: &[&str]) -> Result<Args, String> {
        parse(&a.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn defaults() {
        assert_eq!(parse_strs(&[]).unwrap(), Args::default());
        let d = Args::default();
        assert!(d.domain_init && d.daemonize && d.access_log && !d.help);
        assert_eq!(d.socket, PathBuf::from(DEFAULT_SOCKET));
    }

    #[test]
    fn the_host_command_line() {
        let a = parse_strs(&["--pid-file", "/var/run/xen/xenstored.pid"]).unwrap();
        assert_eq!(
            a,
            Args {
                pid_file: Some("/var/run/xen/xenstored.pid".into()),
                ..Args::default()
            }
        );
    }

    #[test]
    fn each_option() {
        let a = parse_strs(&[
            "--no-domain-init",
            "--config-file",
            "/c",
            "--no-fork",
            "--reraise-top-level",
            "--no-access-log",
            "--pid-file",
            "/p",
            "-T",
            "/t",
            "--restart",
            "--live",
            "--config-test",
            "--disable-socket",
            "--socket",
            "/s",
        ])
        .unwrap();
        let expected = Args {
            domain_init: false,
            config_file: Some("/c".into()),
            daemonize: false,
            reraise_top_level: true,
            access_log: false,
            pid_file: Some("/p".into()),
            trace_file: Some("/t".into()),
            restart: true,
            live: true,
            config_test: true,
            disable_socket: true,
            socket: "/s".into(),
            help: false,
            ignored: vec![],
        };
        assert_eq!(a, expected);
        assert!(!parse_strs(&["--foreground"]).unwrap().daemonize);
    }

    #[test]
    fn values_inline_empty_or_option_like() {
        let a = parse_strs(&["--pid-file=/p", "--config-file=", "-T=/t", "--socket=/s=x"]).unwrap();
        assert_eq!(
            (a.pid_file, a.config_file, a.trace_file, a.socket),
            (Some("/p".into()), None, Some("/t".into()), "/s=x".into())
        );
        // The next argument is the value, whatever it looks like.
        let a = parse_strs(&["--pid-file", "--no-fork"]).unwrap();
        assert_eq!(a.pid_file, Some("--no-fork".into()));
        assert!(a.daemonize);
        assert_eq!(parse_strs(&["--pid-file", ""]).unwrap().pid_file, None);
        // The last one wins.
        assert_eq!(
            parse_strs(&["--socket", "/a", "--socket", "/b"]).unwrap().socket,
            PathBuf::from("/b")
        );
    }

    #[test]
    fn help_ends_the_parse() {
        for h in ["--help", "-help", "-h"] {
            assert!(parse_strs(&[h]).unwrap().help);
        }
        let a = parse_strs(&["--live", "--restart", "--pid-file", "/p", "--help", "--bogus"]).unwrap();
        assert!(a.help && a.live && a.restart);
        assert_eq!(a.pid_file, Some("/p".into()));
        assert!(
            parse_strs(&["--bogus", "--help"]).is_err(),
            "what comes before is checked"
        );
    }

    #[test]
    fn other_arguments_are_ignored() {
        let a = parse_strs(&["stray", "--no-fork", ""]).unwrap();
        assert_eq!(a.ignored, [OsString::from("stray"), OsString::from("")]);
        assert!(!a.daemonize);
    }

    #[test]
    fn errors() {
        assert_eq!(parse_strs(&["--bogus"]).unwrap_err(), "unknown option '--bogus'");
        assert_eq!(parse_strs(&["--bogus=1"]).unwrap_err(), "unknown option '--bogus=1'");
        assert_eq!(parse_strs(&["-"]).unwrap_err(), "unknown option '-'");
        assert_eq!(parse_strs(&["--"]).unwrap_err(), "unknown option '--'");
        assert_eq!(
            parse_strs(&["--tracefile", "/t"]).unwrap_err(),
            "unknown option '--tracefile'"
        );
        for opt in ["--config-file", "--pid-file", "-T", "--socket"] {
            assert_eq!(
                parse_strs(&[opt]).unwrap_err(),
                format!("option '{opt}' needs an argument")
            );
        }
        assert_eq!(
            parse_strs(&["--no-fork=yes"]).unwrap_err(),
            "wrong argument 'yes'; option '--no-fork' expects no argument"
        );
        assert!(parse_strs(&["--help=1"]).is_err());
        use std::os::unix::ffi::OsStringExt;
        let not_utf8 = OsString::from_vec(b"--\xff".to_vec());
        assert!(parse(std::slice::from_ref(&not_utf8))
            .unwrap_err()
            .starts_with("unknown option"));
        // Values need not be UTF-8.
        let a = parse(&[OsString::from("--pid-file"), not_utf8.clone()]).unwrap();
        assert_eq!(a.pid_file, Some(PathBuf::from(not_utf8)));
    }
}
