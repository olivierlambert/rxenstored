// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! `core_requests` with the core in the native profile (`xs_core::Rules`):
//! the same actions, checks and seeds (`core_requests.rs` documents them).

#![no_main]

#[path = "../../crates/xs-core/tests/oracle/mod.rs"]
#[allow(clippy::all)]
mod oracle;

/// The profile of the core.
const PROFILE: xs_core::Profile = xs_core::Profile::Native;

include!("core_requests_body.rs");
