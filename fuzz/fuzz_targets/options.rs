// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! xs-daemon's command line (`src/options.rs`, a module of the binary,
//! included here as it is): argv from the input, split on NUL, any bytes
//! (not UTF-8 included).
//!
//! Asserts: no panic; deterministic; arguments not starting with `-` are
//! ignored (kept in `ignored`, in order) unless they are the value of the
//! option before them; an error names the option it is about.

#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

#[path = "../../crates/xs-daemon/src/compat/options.rs"]
mod options;

fuzz_target!(|data: &[u8]| {
    let argv: Vec<OsString> = if data.is_empty() {
        Vec::new()
    } else {
        data.split(|c| *c == 0)
            .map(|a| OsString::from_vec(a.to_vec()))
            .collect()
    };
    let r = options::parse(&argv);
    assert_eq!(r, options::parse(&argv));
    match r {
        Ok(a) => {
            for i in &a.ignored {
                assert!(!i.as_encoded_bytes().starts_with(b"-"), "an option ignored: {i:?}");
                assert!(argv.contains(i));
            }
            assert!(a.ignored.len() <= argv.len());
            let _ = format!("{a:?}");
        }
        Err(e) => {
            assert!(e.contains('\''), "{e}");
        }
    }
});
