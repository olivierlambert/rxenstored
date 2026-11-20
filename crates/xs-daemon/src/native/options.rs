// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored's own command line, read as `getopt_long` reads one: long
//! options `--name`, with a value as `--name=VALUE` or `--name VALUE`;
//! short ones `-N`, several together (`-ND`), with a value as `-F FILE` or
//! `-FFILE`; `--` ends the options. Every argument is read before anything
//! is acted on, `--help` included, and anything that is not an option is
//! an error, as in C xenstored (`cx/core.c:2786-2787`).
//!
//! The names are those both oxenstored and C xenstored use where they
//! agree (`--pid-file`, `--no-fork`, `--no-domain-init`, `--help`), C
//! xenstored's where only it has the option (`-T`, `-Q NAME=VALUE`, the
//! short letters), and oxenstored's where only it has it
//! (`--config-file`, `--config-test`, `--disable-socket`,
//! `--no-access-log`).

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub const DEFAULT_CONFIG: &str = "/etc/xen/rxenstored.conf";
pub const DEFAULT_SOCKET: &str = "/var/run/xenstored/socket";

pub const USAGE: &str = "\
usage: rxenstored [OPTION]...
  -c, --config-file FILE  configuration file (default /etc/xen/rxenstored.conf)
      --config-test       check the command line and the configuration file, and exit
  -N, --no-fork           stay in the foreground
  -F, --pid-file FILE     write the daemon's pid to FILE once it serves
  -D, --no-domain-init    do not map dom0's ring nor bind the event channels
      --disable-socket    do not listen on the unix socket (the rings only)
      --socket PATH       unix socket to listen on (default /var/run/xenstored/socket)
      --no-access-log     no access log, whatever the configuration file says
  -Q, --quota NAME=VALUE  set a quota, over the configuration file's (0: no limit);
                          NAME: nodes, watches, transactions, outstanding, path-max,
                          value-size, node-permissions, transaction-requests,
                          watch-events, transaction-bytes
  -T, --trace-file FILE   trace file (not implemented: ignored, with a warning)
  -h, -H, --help          print this and exit
      --version           print the version and the commit, and exit
      --compat=oxenstored oxenstored's command line and /etc/xen/oxenstored.conf
                          instead of these (rxenstored --compat=oxenstored --help)
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub config_file: Option<PathBuf>,
    pub config_test: bool,
    pub daemonize: bool,
    pub pid_file: Option<PathBuf>,
    pub domain_init: bool,
    pub disable_socket: bool,
    pub socket: PathBuf,
    /// False with `--no-access-log`.
    pub access_log: bool,
    /// `-Q NAME=VALUE`, in order, as given: the configuration checks them.
    pub quotas: Vec<String>,
    pub trace_file: Option<PathBuf>,
    pub help: bool,
    pub version: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            config_file: None,
            config_test: false,
            daemonize: true,
            pid_file: None,
            domain_init: true,
            disable_socket: false,
            socket: DEFAULT_SOCKET.into(),
            access_log: true,
            quotas: Vec::new(),
            trace_file: None,
            help: false,
            version: false,
        }
    }
}

/// An option: its long name, its short letter if any, whether it takes a value.
struct Opt {
    long: &'static str,
    short: Option<char>,
    value: bool,
}

const OPTS: &[Opt] = &[
    Opt {
        long: "config-file",
        short: Some('c'),
        value: true,
    },
    Opt {
        long: "config-test",
        short: None,
        value: false,
    },
    Opt {
        long: "no-fork",
        short: Some('N'),
        value: false,
    },
    Opt {
        long: "pid-file",
        short: Some('F'),
        value: true,
    },
    Opt {
        long: "no-domain-init",
        short: Some('D'),
        value: false,
    },
    Opt {
        long: "disable-socket",
        short: None,
        value: false,
    },
    Opt {
        long: "socket",
        short: None,
        value: true,
    },
    Opt {
        long: "no-access-log",
        short: None,
        value: false,
    },
    Opt {
        long: "quota",
        short: Some('Q'),
        value: true,
    },
    Opt {
        long: "trace-file",
        short: Some('T'),
        value: true,
    },
    Opt {
        long: "help",
        short: Some('h'),
        value: false,
    },
    Opt {
        long: "help",
        short: Some('H'),
        value: false,
    },
    Opt {
        long: "version",
        short: None,
        value: false,
    },
];

fn by_long(name: &str) -> Option<&'static Opt> {
    OPTS.iter().find(|o| o.long == name)
}

fn by_short(c: char) -> Option<&'static Opt> {
    OPTS.iter().find(|o| o.short == Some(c))
}

/// A path option's value: not empty.
fn path(name: &str, v: OsString) -> Result<PathBuf, String> {
    if v.is_empty() {
        return Err(format!("option '--{name}' needs a non-empty value"));
    }
    Ok(v.into())
}

fn set(a: &mut Args, name: &str, value: Option<OsString>) -> Result<(), String> {
    let v = || value.clone().unwrap_or_default();
    match name {
        "config-file" => a.config_file = Some(path(name, v())?),
        "config-test" => a.config_test = true,
        "no-fork" => a.daemonize = false,
        "pid-file" => a.pid_file = Some(path(name, v())?),
        "no-domain-init" => a.domain_init = false,
        "disable-socket" => a.disable_socket = true,
        "socket" => a.socket = path(name, v())?,
        "no-access-log" => a.access_log = false,
        "quota" => a.quotas.push(
            v().into_string()
                .map_err(|s| format!("option '--quota': '{}' is not NAME=VALUE", s.to_string_lossy()))?,
        ),
        "trace-file" => a.trace_file = Some(path(name, v())?),
        "version" => a.version = true,
        // "help"
        _ => a.help = true,
    }
    Ok(())
}

fn os(bytes: &[u8]) -> OsString {
    OsStr::from_bytes(bytes).to_os_string()
}

pub fn parse(argv: &[OsString]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let bytes = arg.as_bytes();
        let unexpected = |extra: &OsString| format!("unexpected argument '{}'", extra.to_string_lossy());
        if bytes == b"--" {
            if let Some(extra) = it.next() {
                return Err(unexpected(extra));
            }
            break;
        }
        if let Some(long) = bytes.strip_prefix(b"--") {
            let (name, inline) = match long.iter().position(|&b| b == b'=') {
                Some(i) => (
                    long.get(..i).unwrap_or_default(),
                    Some(os(long.get(i + 1..).unwrap_or_default())),
                ),
                None => (long, None),
            };
            let name = String::from_utf8_lossy(name);
            let opt = by_long(&name).ok_or_else(|| format!("unknown option '--{name}'"))?;
            let value = match (opt.value, inline) {
                (true, Some(v)) => Some(v),
                (true, None) => Some(
                    it.next()
                        .cloned()
                        .ok_or_else(|| format!("option '--{name}' needs a value"))?,
                ),
                (false, Some(_)) => return Err(format!("option '--{name}' takes no value")),
                (false, None) => None,
            };
            set(&mut a, opt.long, value)?;
            continue;
        }
        // -N, -ND, -FFILE, -F FILE.
        let Some(shorts) = bytes.strip_prefix(b"-").filter(|s| !s.is_empty()) else {
            return Err(unexpected(arg));
        };
        let mut rest = shorts;
        while let Some((&c, after)) = rest.split_first() {
            let opt = by_short(char::from(c)).ok_or_else(|| format!("unknown option '-{}'", c.escape_ascii()))?;
            let c = char::from(c);
            rest = after;
            if !opt.value {
                set(&mut a, opt.long, None)?;
                continue;
            }
            let value = if rest.is_empty() {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("option '-{c}' needs a value"))?
            } else {
                os(rest)
            };
            set(&mut a, opt.long, Some(value))?;
            break;
        }
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn parse_strs(a: &[&str]) -> Result<Args, String> {
        parse(&a.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn defaults() {
        let a = parse_strs(&[]).unwrap();
        assert_eq!(a, Args::default());
        assert!(a.daemonize && a.domain_init && a.access_log && !a.disable_socket);
        assert!(!a.config_test && !a.help && !a.version);
        assert_eq!((a.config_file, a.pid_file, a.trace_file), (None, None, None));
        assert_eq!(a.socket, PathBuf::from("/var/run/xenstored/socket"));
        assert!(a.quotas.is_empty());
    }

    #[test]
    fn what_launch_xenstore_passes() {
        // `--pid-file`, then XENSTORED_ARGS, then `-T` with XENSTORED_TRACE.
        let a = parse_strs(&[
            "--pid-file",
            "/var/run/xen/xenstored.pid",
            "-T",
            "/var/log/xen/xenstored-trace.log",
        ])
        .unwrap();
        assert_eq!(a.pid_file, Some("/var/run/xen/xenstored.pid".into()));
        assert_eq!(a.trace_file, Some("/var/log/xen/xenstored-trace.log".into()));
    }

    #[test]
    fn every_long_option() {
        let a = parse_strs(&[
            "--config-file",
            "/c",
            "--config-test",
            "--no-fork",
            "--pid-file",
            "/p",
            "--no-domain-init",
            "--disable-socket",
            "--socket",
            "/s",
            "--no-access-log",
            "--quota",
            "nodes=5",
            "--trace-file",
            "/t",
            "--help",
            "--version",
        ])
        .unwrap();
        let expected = Args {
            config_file: Some("/c".into()),
            config_test: true,
            daemonize: false,
            pid_file: Some("/p".into()),
            domain_init: false,
            disable_socket: true,
            socket: "/s".into(),
            access_log: false,
            quotas: vec!["nodes=5".into()],
            trace_file: Some("/t".into()),
            help: true,
            version: true,
        };
        assert_eq!(a, expected);
    }

    #[test]
    fn every_short_option() {
        let a = parse_strs(&["-c", "/c", "-N", "-F", "/p", "-D", "-Q", "nodes=5", "-T", "/t", "-h"]).unwrap();
        let b = parse_strs(&["-c/c", "-NDF/p", "-Qnodes=5", "-T/t", "-H"]).unwrap();
        let expected = Args {
            config_file: Some("/c".into()),
            daemonize: false,
            pid_file: Some("/p".into()),
            domain_init: false,
            quotas: vec!["nodes=5".into()],
            trace_file: Some("/t".into()),
            help: true,
            ..Args::default()
        };
        assert_eq!(a, expected);
        assert_eq!(b, expected);
    }

    #[test]
    fn values_inline_or_next_and_the_last_one_wins() {
        let a = parse_strs(&["--pid-file=/p=q", "--socket", "--no-fork", "--quota=a=1", "-Q", "b=2"]).unwrap();
        assert_eq!(a.pid_file, Some("/p=q".into()));
        // The next argument is the value, whatever it looks like.
        assert_eq!(a.socket, PathBuf::from("--no-fork"));
        assert!(a.daemonize);
        assert_eq!(a.quotas, ["a=1", "b=2"], "kept in order, checked later");
        let a = parse_strs(&["--socket", "/a", "--socket=/b", "-F", "/x", "--pid-file", "/y"]).unwrap();
        assert_eq!((a.socket, a.pid_file), ("/b".into(), Some("/y".into())));
        // Values need not be UTF-8.
        let raw = OsString::from_vec(b"/p\xff".to_vec());
        let a = parse(&[OsString::from("--pid-file"), raw.clone()]).unwrap();
        assert_eq!(a.pid_file, Some(PathBuf::from(&raw)));
        let a = parse(&[OsString::from_vec(b"-F/p\xff".to_vec())]).unwrap();
        assert_eq!(a.pid_file, Some(PathBuf::from(&raw)));
        let a = parse(&[OsString::from_vec(b"--pid-file=/p\xff".to_vec())]).unwrap();
        assert_eq!(a.pid_file, Some(PathBuf::from(&raw)));
    }

    #[test]
    fn a_double_dash_ends_the_options() {
        assert!(!parse_strs(&["--no-fork", "--"]).unwrap().daemonize);
        assert_eq!(parse_strs(&["--", "x"]).unwrap_err(), "unexpected argument 'x'");
    }

    #[test]
    fn errors() {
        for (argv, want) in [
            (&["stray"][..], "unexpected argument 'stray'"),
            (&["-"], "unexpected argument '-'"),
            (&["--bogus"], "unknown option '--bogus'"),
            (&["--bogus=1"], "unknown option '--bogus'"),
            (&["-x"], "unknown option '-x'"),
            (&["-Nx"], "unknown option '-x'"),
            // oxenstored's and C xenstored's options that this command line does not have.
            (&["--live"], "unknown option '--live'"),
            (&["--restart"], "unknown option '--restart'"),
            (&["--reraise-top-level"], "unknown option '--reraise-top-level'"),
            (&["--foreground"], "unknown option '--foreground'"),
            (&["-U"], "unknown option '-U'"),
            (&["--live-update"], "unknown option '--live-update'"),
            (&["-E", "100"], "unknown option '-E'"),
            (&["--entry-nb=100"], "unknown option '--entry-nb'"),
            (&["--compat=oxenstored"], "unknown option '--compat'"),
            (&["--pid-file"], "option '--pid-file' needs a value"),
            (&["-F"], "option '-F' needs a value"),
            (&["-NF"], "option '-F' needs a value"),
            (&["--pid-file", ""], "option '--pid-file' needs a non-empty value"),
            (&["--pid-file="], "option '--pid-file' needs a non-empty value"),
            (&["--socket="], "option '--socket' needs a non-empty value"),
            (&["--config-file="], "option '--config-file' needs a non-empty value"),
            (&["-T", ""], "option '--trace-file' needs a non-empty value"),
            (&["--no-fork=yes"], "option '--no-fork' takes no value"),
            (&["--help=1"], "option '--help' takes no value"),
        ] {
            assert_eq!(parse_strs(argv).unwrap_err(), want, "{argv:?}");
        }
        assert_eq!(
            parse(&[OsString::from_vec(b"-\xff".to_vec())]).unwrap_err(),
            "unknown option '-\\xff'"
        );
        let bad = OsString::from_vec(b"nodes=\xff".to_vec());
        assert_eq!(
            parse(&[OsString::from("-Q"), bad]).unwrap_err(),
            "option '--quota': 'nodes=\u{fffd}' is not NAME=VALUE"
        );
        // Everything is read before --help counts.
        assert!(parse_strs(&["--help", "--bogus"]).is_err());
    }

    #[test]
    fn the_usage_names_every_option() {
        for o in OPTS {
            assert!(USAGE.contains(&format!("--{}", o.long)), "{}", o.long);
            if let Some(c) = o.short {
                assert!(USAGE.contains(&format!("-{c},")), "{c}");
            }
        }
    }
}
