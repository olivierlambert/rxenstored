// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The core driven as hostile guests and a toolstack would drive it, with
//! its invariants checked after every step.
//!
//! Connections: two sockets (domain 0), domain 0's ring, and three guests
//! (domids 1, 2, 3) introduced at the start with small quotas, domain 3
//! acting for domain 2 (SET_TARGET, a stub domain). The input decodes
//! (`arbitrary`) into actions: well-framed requests of any type built from
//! fields (paths, permissions, numbers, tokens, values, raw bytes), raw
//! bytes fed as they are (the escape hatch for malformed framing),
//! processing, reading some or all of a connection's output or not,
//! INTRODUCE / RELEASE / SET_TARGET, domains dying or shutting down, ring
//! reconnection, a ring given up on, sockets closed and reopened, time.
//!
//! Checked after every step (a panic fails the input):
//! - no panic anywhere, with debug assertions on (`impossible()` included);
//! - `Core::audit()`;
//! - every message queued is complete and well formed: a known error name,
//!   a watch event `<path>\0<token>\0`, a ring's payload within PAYLOAD_MAX
//!   (a socket's too, but for DIRECTORY, CONTROL and watch events, which
//!   have no limit on a socket); one reply per request handled, with its
//!   request id and transaction id;
//! - what a guest holds stays within its quotas: watches, transactions,
//!   unsent replies and events and bytes, nodes per owner (a guest request
//!   never takes an owner past `entity_max`), value sizes;
//! - permissions, by the model's rules (`allowed`): every node a
//!   guest request created, changed or removed was writable by it (at the
//!   commit of a transaction whose store nothing replaced, by it as it was
//!   when one of the transaction's requests ran: such a commit publishes
//!   the transaction as it ran, SET_TARGET or a RELEASE since), every
//!   READ / DIRECTORY / GET_PERMS outside a transaction it got an answer to
//!   was readable by it, and every watch event it got is for a node it
//!   could read (or its parent) in the store before or after, or at the
//!   start of a transaction then ending;
//! - every watch event matches a watch its connection has (the harness
//!   keeps the list from the replies), and the core's count of watches is
//!   the sum of those lists; the core's count of transactions per
//!   connection is the harness's;
//! - the machine (map/bind/unbind) sees exactly the domains the core knows;
//! - the access log's lines, as the daemon formats them, are one line each.
//!
//! The core runs in oxenstored's profile here, in the native one in
//! `core_requests_native` (the same body, `core_requests_body.rs`, and
//! the same inputs and seeds); the checks follow the profile's rules
//! where they differ (`xs_core::Rules`).

#![no_main]

#[path = "../../crates/xs-core/tests/oracle/mod.rs"]
#[allow(clippy::all)]
mod oracle;

/// The profile of the core.
const PROFILE: xs_core::Profile = xs_core::Profile::Oxenstored;

include!("core_requests_body.rs");
