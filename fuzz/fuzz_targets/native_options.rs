// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! xs-daemon's own command line (`src/native/options.rs`, a module of the
//! binary, included here as it is): argv from the input, split on NUL,
//! any bytes (not UTF-8 included); then each `-Q` value as the
//! configuration (`src/native/config.rs`) takes it.
//!
//! Asserts: no panic; deterministic; the result is what an independent
//! reading of the grammar the module documents gives (getopt_long's:
//! `--name`, `--name=VALUE`, `--name VALUE`; `-N`, `-ND`, `-FFILE`,
//! `-F FILE`; `--` ends the options; anything that is not an option or
//! an option's value is an error; a path is not empty; a quota is UTF-8),
//! the same fields set to the same values, the last value of an option
//! winning and every `-Q` kept in order; an error is the one the reading
//! expects, with what it is about quoted.

#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

#[path = "../../crates/xs-daemon/src/native/config.rs"]
mod config;
#[path = "../../crates/xs-daemon/src/native/options.rs"]
mod options;

use options::Args;

/// (long name, short letter, takes a value), from the usage text.
const OPTS: &[(&str, Option<u8>, bool)] = &[
    ("config-file", Some(b'c'), true),
    ("config-test", None, false),
    ("no-fork", Some(b'N'), false),
    ("pid-file", Some(b'F'), true),
    ("no-domain-init", Some(b'D'), false),
    ("disable-socket", None, false),
    ("socket", None, true),
    ("no-access-log", None, false),
    ("quota", Some(b'Q'), true),
    ("trace-file", Some(b'T'), true),
    ("help", Some(b'h'), false),
    ("help", Some(b'H'), false),
    ("version", None, false),
];

/// Why the reference refuses: which kind of error the module must give.
#[derive(Debug)]
enum Refused {
    Unexpected,
    Unknown,
    NeedsValue,
    TakesNoValue,
    Empty,
    Quota,
}

fn apply(a: &mut Args, long: &str, v: Option<&[u8]>) -> Result<(), Refused> {
    let path = || -> Result<PathBuf, Refused> {
        let v = v.unwrap();
        if v.is_empty() {
            Err(Refused::Empty)
        } else {
            Ok(PathBuf::from(OsString::from_vec(v.to_vec())))
        }
    };
    match long {
        "config-file" => a.config_file = Some(path()?),
        "config-test" => a.config_test = true,
        "no-fork" => a.daemonize = false,
        "pid-file" => a.pid_file = Some(path()?),
        "no-domain-init" => a.domain_init = false,
        "disable-socket" => a.disable_socket = true,
        "socket" => a.socket = path()?,
        "no-access-log" => a.access_log = false,
        "quota" => a
            .quotas
            .push(String::from_utf8(v.unwrap().to_vec()).map_err(|_| Refused::Quota)?),
        "trace-file" => a.trace_file = Some(path()?),
        "help" => a.help = true,
        "version" => a.version = true,
        _ => unreachable!(),
    }
    Ok(())
}

fn reference(argv: &[Vec<u8>]) -> Result<Args, Refused> {
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i][..];
        i += 1;
        if arg == b"--" {
            return if i < argv.len() {
                Err(Refused::Unexpected)
            } else {
                Ok(a)
            };
        }
        if let Some(long) = arg.strip_prefix(b"--") {
            let (name, inline) = match long.iter().position(|&b| b == b'=') {
                Some(p) => (&long[..p], Some(&long[p + 1..])),
                None => (long, None),
            };
            let Some(&(l, _, takes)) = OPTS.iter().find(|o| o.0.as_bytes() == name) else {
                return Err(Refused::Unknown);
            };
            let v = match (takes, inline) {
                (true, Some(v)) => Some(v),
                (true, None) => {
                    let v = argv.get(i).ok_or(Refused::NeedsValue)?;
                    i += 1;
                    Some(&v[..])
                }
                (false, Some(_)) => return Err(Refused::TakesNoValue),
                (false, None) => None,
            };
            apply(&mut a, l, v)?;
            continue;
        }
        if arg.len() < 2 || arg[0] != b'-' {
            return Err(Refused::Unexpected);
        }
        let mut j = 1;
        while j < arg.len() {
            let c = arg[j];
            j += 1;
            let Some(&(l, _, takes)) = OPTS.iter().find(|o| o.1 == Some(c)) else {
                return Err(Refused::Unknown);
            };
            if !takes {
                apply(&mut a, l, None)?;
                continue;
            }
            let v = if j < arg.len() {
                &arg[j..]
            } else {
                let v = argv.get(i).ok_or(Refused::NeedsValue)?;
                i += 1;
                &v[..]
            };
            apply(&mut a, l, Some(v))?;
            break;
        }
    }
    Ok(a)
}

fuzz_target!(|data: &[u8]| {
    let raw: Vec<Vec<u8>> = if data.is_empty() {
        Vec::new()
    } else {
        data.split(|c| *c == 0).map(<[u8]>::to_vec).collect()
    };
    let argv: Vec<OsString> = raw.iter().map(|a| OsString::from_vec(a.clone())).collect();
    let r = options::parse(&argv);
    assert_eq!(r, options::parse(&argv), "not deterministic");
    match (&r, reference(&raw)) {
        (Ok(a), Ok(want)) => {
            assert_eq!(a, &want);
            for p in [&a.config_file, &a.pid_file, &a.trace_file].into_iter().flatten() {
                assert!(!p.as_os_str().is_empty());
            }
            assert!(!a.socket.as_os_str().is_empty());
            // The -Q values, as the configuration reads them: any error
            // starts with -Q and names the argument.
            let mut q = config::Quotas::default();
            for arg in &a.quotas {
                if let Err(e) = q.set_arg(arg) {
                    assert!(e.starts_with(&format!("-Q {arg}: ")), "{e}");
                }
            }
        }
        (Err(e), Err(why)) => {
            let prefix = match why {
                Refused::Unexpected => "unexpected argument '",
                Refused::Unknown => "unknown option '-",
                Refused::NeedsValue => "option '-",
                Refused::TakesNoValue => "option '--",
                Refused::Empty => "option '--",
                Refused::Quota => "option '--quota': '",
            };
            let suffix = match why {
                Refused::NeedsValue => "' needs a value",
                Refused::TakesNoValue => "' takes no value",
                Refused::Empty => "' needs a non-empty value",
                Refused::Quota => "' is not NAME=VALUE",
                Refused::Unexpected | Refused::Unknown => "'",
            };
            assert!(e.starts_with(prefix) && e.ends_with(suffix), "{e:?}, expected {why:?}");
        }
        (r, want) => panic!(
            "argv {:?}: {r:?}, expected {want:?}",
            argv.iter()
                .map(|a| a.as_bytes().escape_ascii().to_string())
                .collect::<Vec<_>>()
        ),
    }
});
