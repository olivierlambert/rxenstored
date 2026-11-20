// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>

//! Gives the build the commit it was made from, for `--version`:
//! `RXENSTORED_COMMIT`, twelve hex digits and `-dirty` when tracked files
//! differ from it; not set when the sources are not a git checkout.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=RXENSTORED_COMMIT");
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
    }
    if std::env::var_os("RXENSTORED_COMMIT").is_some() {
        return;
    }
    let Some(commit) = git(&["rev-parse", "--short=12", "HEAD"]).filter(|c| !c.is_empty()) else {
        return;
    };
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    println!(
        "cargo:rustc-env=RXENSTORED_COMMIT={commit}{}",
        if dirty { "-dirty" } else { "" }
    );
}
