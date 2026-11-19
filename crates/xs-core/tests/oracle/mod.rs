// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The naive model of oxenstored that `model.rs` compares the core with,
//! its request generator and the comparison loop (moved here from
//! `model.rs`). Shared with the fuzz target `core_vs_model` (fuzz/),
//! which drives the same generator with the fuzzer's bytes instead of a
//! seeded random generator: every choice is a `Source::below`.
//!
//! With the native profile (`Profile::Native`) the model follows its six
//! rules (`xs_core::Rules`) and is oxenstored's otherwise: quotas refuse
//! with ENOSPC; a quota of N allows N watches and N transactions; CONTROL
//! from a guest is EACCES; a guest owns, and is counted for, the nodes it
//! creates; a WRITE or MKDIR that fails leaves the store as it was; a
//! missing node is EACCES to a caller that may not access its nearest
//! existing ancestor as the request asks.

// Each of the two users of this module uses part of it.
#![allow(dead_code)]

use std::collections::BTreeMap;
use xs_core::{Config, ConnId, Core, Profile, Status};
use xs_wire::{write_header, MsgType};

pub type P = Vec<Vec<u8>>;

#[derive(Clone, PartialEq, Debug)]
pub struct MNode {
    pub value: Vec<u8>,
    pub perms: Vec<u8>,
}

pub type Store = BTreeMap<P, MNode>;

/// A connection's domain and SET_TARGET domain.
pub type Who = (u32, Option<u32>);

pub fn is_dom0(who: Who) -> bool {
    who.0 == 0 || who.1 == Some(0)
}

/// `Perms.has`: may `who` read (`b'r'`) or write (`b'w'`) a node with
/// these permissions (`n0\0r5\0...`: owner and others, then the ACL)?
pub fn allowed(perms: &[u8], who: Who, want: u8) -> bool {
    let entries: Vec<(u8, u32)> = perms
        .split(|c| *c == 0)
        .filter(|e| !e.is_empty())
        .map(|e| (e[0], std::str::from_utf8(&e[1..]).unwrap().parse().unwrap()))
        .collect();
    let ids: Vec<u32> = [Some(who.0), who.1].into_iter().flatten().collect();
    if is_dom0(who) || ids.contains(&entries[0].1) {
        return true;
    }
    ids.iter().any(|d| {
        let letter = entries[1..].iter().find(|e| e.1 == *d).map_or(entries[0].0, |e| e.0);
        letter == b'b' || letter == want
    })
}

pub fn owner(perms: &[u8]) -> u32 {
    std::str::from_utf8(&perms[1..perms.iter().position(|c| *c == 0).unwrap()])
        .unwrap()
        .parse()
        .unwrap()
}

/// The permissions of a node `who` creates below one with `parent`'s: the
/// parent's, or in the native profile, for a guest, the parent's with the
/// guest as owner.
pub fn created(parent: &[u8], who: Who, native: bool) -> Vec<u8> {
    if !native || is_dom0(who) {
        return parent.to_vec();
    }
    let end = parent.iter().position(|c| *c == 0).unwrap();
    [&parent[..1], who.0.to_string().as_bytes(), &parent[end..]].concat()
}

pub struct MWatch {
    path: Vec<u8>,
    token: Vec<u8>,
    apath: Vec<u8>,
    /// None for a special path.
    key: Option<P>,
    relative: bool,
}

pub struct MTxn {
    store: Store,
    /// The store when it started.
    snapshot: Store,
    /// The store's `Model::version` when it started.
    version: u64,
    /// Requests made in it.
    requests: usize,
    /// (type, payload, reply bytes, who made it) of every request.
    log: Vec<(u32, Vec<u8>, Vec<u8>, Who)>,
    /// The changes its requests made as they ran in it: what its commit
    /// fires (`ox/process.ml:60-72`, the paths it recorded).
    changes: Vec<Change>,
}

pub struct MConn {
    watches: Vec<MWatch>,
    txns: BTreeMap<u32, MTxn>,
    next_tid: u32,
    domid: u32,
    /// A domain's connection, not a socket: SET_TARGET finds it.
    ring: bool,
    target: Option<u32>,
}

impl MConn {
    fn new(domid: u32, ring: bool) -> MConn {
        MConn {
            watches: Vec::new(),
            txns: BTreeMap::new(),
            next_tid: 1,
            domid,
            ring,
            target: None,
        }
    }

    fn who(&self) -> Who {
        (self.domid, self.target)
    }

    fn home(&self) -> Vec<u8> {
        format!("/local/domain/{}/", self.domid).into_bytes()
    }
}

/// A message as (type, req_id, tx_id, payload).
pub type Msg = (u32, u32, u32, Vec<u8>);

pub struct Model {
    store: Store,
    /// How many times the store's root was replaced: oxenstored's commit
    /// compares roots by identity (`==`), not by content
    /// (`ox/transaction.ml:239`), so a change that leaves the content as it
    /// was still counts.
    version: u64,
    conns: Vec<MConn>,
    q: Quotas,
    /// The native profile's rules.
    native: bool,
}

/// The error of a quota.
pub fn quota_error(native: bool) -> &'static str {
    if native {
        "ENOSPC"
    } else {
        "EQUOTA"
    }
}

/// Is a count of `n` at a quota of `max` (watches, transactions)? A quota
/// of N allows N + 1, or N in the native profile.
pub fn full(n: usize, max: usize, native: bool) -> bool {
    if native {
        n >= max
    } else {
        n > max
    }
}

/// The nearest node of `store` above `p`, which does not exist: a node
/// that does not exist is ENOENT, or in the native profile EACCES to a
/// caller that may not `want` (`b'r'`, `b'w'`) that node.
pub fn missing(store: &Store, p: &[Vec<u8>], who: Who, want: u8, native: bool) -> &'static str {
    let above = (0..p.len())
        .rev()
        .map(|k| &p[..k])
        .find(|a| store.contains_key(*a))
        .unwrap();
    if native && !allowed(&store[above].perms, who, want) {
        "EACCES"
    } else {
        "ENOENT"
    }
}

/// Whether a request replaced the store's root: any WRITE, SET_PERMS or RM
/// that succeeded, even with the value or permissions the node had
/// (`ox/store.ml:272-317` build a new path to the root), and anything that changed the content,
/// such as a MKDIR or the missing parents created before a request fails.
/// A MKDIR of the root returns the root as it is (`ox/store.ml:267-268`).
fn replaces(ty: u32, before: &Store, after: &Store, changes: &[Change]) -> bool {
    before != after || (!changes.is_empty() && ty != MsgType::Mkdir as u32)
}

/// The quotas of the run (`Config`'s), and which a request is held to.
#[derive(Clone, Copy)]
pub struct Quotas {
    pub entity_max: usize,
    pub watch_max: usize,
    pub transaction_max: usize,
    pub request_max: usize,
    pub acl_max: usize,
}

/// The node quota a store operation runs under: the limit if the caller
/// is held, and for a transaction the store and the transaction's start,
/// whose difference with its own store it adds to the store's counts;
/// and the profile.
#[derive(Clone, Copy)]
pub struct Ent<'a> {
    max: Option<usize>,
    txn: Option<(&'a Store, &'a Store)>,
    native: bool,
}

/// Nodes of `owner` in a store, the root aside.
pub fn count(store: &Store, owner: u32) -> isize {
    store
        .iter()
        .filter(|(k, n)| !k.is_empty() && self::owner(&n.perms) == owner)
        .count() as isize
}

/// How many more nodes `owner` may get (`ox/quota.ml:51-66`): any but
/// domain 0 is held (`id > 0`; the root's lost owner, -1, is not modelled).
pub fn room(store: &Store, e: Ent, owner: u32) -> usize {
    let Some(max) = e.max else { return usize::MAX };
    if owner == 0 {
        return usize::MAX;
    }
    let n = count(store, owner) + e.txn.map_or(0, |(g, snap)| count(g, owner) - count(snap, owner));
    match n.max(0) as usize {
        0 => max.max(1),
        n => max.saturating_sub(n),
    }
}

pub enum Change {
    Normal(P, Vec<Store>),
    /// Removal: the path and the store before.
    Rm(P, Store),
}

pub fn parse_path(raw: &[u8], home: &[u8]) -> Option<P> {
    if raw.is_empty() {
        return None;
    }
    let abs: Vec<u8> = if raw[0] == b'/' || raw[0] == b'@' {
        raw.to_vec()
    } else {
        [home, raw].concat()
    };
    if abs[0] == b'@' {
        return Some(vec![abs]);
    }
    if abs == b"/" {
        return Some(vec![]);
    }
    let mut out = Vec::new();
    for c in abs[1..].split(|b| *b == b'/') {
        if c.is_empty() || !c.iter().all(|b| b.is_ascii_alphanumeric() || b"_-@".contains(b)) {
            return None;
        }
        out.push(c.to_vec());
    }
    Some(out)
}

pub fn show(p: &[Vec<u8>]) -> Vec<u8> {
    if p.is_empty() {
        return b"/".to_vec();
    }
    p.iter().flat_map(|c| [&b"/"[..], c].concat()).collect()
}

pub fn parent(p: &[Vec<u8>]) -> &[Vec<u8>] {
    &p[..p.len() - 1]
}

pub fn ok() -> Vec<u8> {
    b"OK\0".to_vec()
}

/// Reply type and payload: Ok(payload) or Err(error name).
pub type R = Result<Vec<u8>, &'static str>;

pub fn enc(r: &R) -> Vec<u8> {
    match r {
        Ok(p) => [b"+".to_vec(), p.clone()].concat(),
        Err(e) => [b"-".to_vec(), e.as_bytes().to_vec()].concat(),
    }
}

pub fn split(data: &[u8], limit: usize) -> Vec<&[u8]> {
    data.splitn(limit, |c| *c == 0).collect()
}

pub fn parse_perms(s: &[u8]) -> Option<Vec<u8>> {
    let mut pieces: Vec<&[u8]> = s.split(|c| *c == 0).collect();
    pieces.pop();
    if pieces.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for p in pieces {
        if p.len() < 2 || !b"nrwb".contains(&p[0]) || !p[1..].iter().all(u8::is_ascii_digit) || p.len() > 6 {
            return None;
        }
        out.push(p[0]);
        out.extend_from_slice(format!("{}", std::str::from_utf8(&p[1..]).unwrap().parse::<u32>().unwrap()).as_bytes());
        out.push(0);
    }
    Some(out)
}

/// The missing nodes of `p` (`create_implicit_path`, and a MKDIR's own
/// node), as the core's `Missing` makes them (`store.rs`): the room in
/// their owner's quota is taken once, at the first, which needs room and
/// write access to its parent; all get its permissions (`created`); as many
/// are made as the room allows, and the request fails if that is not all.
/// Per node, the room would be larger in one case: in a transaction whose
/// changes uncount more of an owner's nodes than the store now counts
/// (removed in it and by others since it started), the count is held at 0
/// (`quota::txn_count`) while the first nodes made bring it back up.
/// Returns the room left, or None if nothing was missing.
pub fn create_missing(store: &mut Store, p: &[Vec<u8>], who: Who, e: Ent) -> Result<Option<usize>, &'static str> {
    let Some(first) = (1..=p.len()).find(|i| !store.contains_key(&p[..*i])) else {
        return Ok(None);
    };
    let parent = &store[&p[..first - 1]].perms;
    let perms = created(parent, who, e.native);
    let room = room(store, e, owner(&perms));
    if room == 0 {
        return Err(quota_error(e.native));
    }
    if !allowed(parent, who, b'w') {
        return Err("EACCES");
    }
    for (made, i) in (first..=p.len()).enumerate() {
        if made == room {
            return Err(quota_error(e.native));
        }
        store.insert(
            p[..i].to_vec(),
            MNode {
                value: vec![],
                perms: perms.clone(),
            },
        );
    }
    Ok(Some(room - (p.len() + 1 - first)))
}

pub fn check(store: &Store, p: &[Vec<u8>], who: Who, want: u8) -> Result<(), &'static str> {
    if allowed(&store[p].perms, who, want) {
        Ok(())
    } else {
        Err("EACCES")
    }
}

pub fn op_write(store: &mut Store, p: P, v: &[u8], who: Who, e: Ent, changes: &mut Vec<Change>) -> R {
    let left = create_missing(store, &p[..p.len().saturating_sub(1)], who, e)?;
    if v.len() > 2048 {
        return Err("E2BIG");
    }
    if store.contains_key(&p) {
        check(store, &p, who, b'w')?;
        store.get_mut(&p).unwrap().value = v.to_vec();
    } else {
        let perms = created(&store[parent(&p)].perms, who, e.native);
        // After missing parents, the node needs the room left by them in
        // the native profile (every check before the first node is made),
        // the room counted again otherwise (`store.rs`, `Op::Write`).
        let room = match left {
            Some(left) if e.native => left,
            _ => room(store, e, owner(&perms)),
        };
        if room == 0 {
            return Err(quota_error(e.native));
        }
        check(store, parent(&p), who, b'w')?;
        store.insert(
            p.clone(),
            MNode {
                value: v.to_vec(),
                perms,
            },
        );
    }
    changes.push(Change::Normal(p, vec![store.clone()]));
    Ok(ok())
}

pub fn op_mkdir(store: &mut Store, p: P, who: Who, e: Ent, changes: &mut Vec<Change>) -> R {
    if p.is_empty() {
        changes.push(Change::Normal(p, vec![store.clone()]));
        return Ok(ok());
    }
    if store.contains_key(&p) {
        check(store, &p, who, b'w')?;
        return Ok(ok());
    }
    create_missing(store, &p, who, e)?;
    changes.push(Change::Normal(p, vec![store.clone()]));
    Ok(ok())
}

pub fn op_rm(store: &mut Store, p: P, who: Who, native: bool, changes: &mut Vec<Change>) -> R {
    if p.is_empty() {
        check(store, &p, who, b'w')?;
        let before = store.clone();
        store.retain(|k, _| k.is_empty());
        changes.push(Change::Rm(p, before));
        return Ok(ok());
    }
    if !store.contains_key(parent(&p)) {
        return Err(missing(store, parent(&p), who, b'w', native));
    }
    if store.contains_key(&p) {
        check(store, &p, who, b'w')?;
        let before = store.clone();
        store.retain(|k, _| !k.starts_with(&p));
        changes.push(Change::Rm(p, before));
    } else if native {
        check(store, parent(&p), who, b'w')?;
    }
    Ok(ok())
}

pub fn op_setperms(store: &mut Store, p: P, perms: Vec<u8>, who: Who, native: bool, changes: &mut Vec<Change>) -> R {
    let Some(node) = store.get(&p) else {
        return Err(missing(store, &p, who, b'w', native));
    };
    if owner(&node.perms) != owner(&perms) && !is_dom0(who) {
        return Err("EACCES");
    }
    if !p.is_empty() && !is_dom0(who) && who.0 != owner(&node.perms) && who.1 != Some(owner(&node.perms)) {
        return Err("EACCES");
    }
    check(store, &p, who, b'w')?;
    let before = store.clone();
    store.get_mut(&p).unwrap().perms = perms;
    changes.push(Change::Normal(p, vec![before, store.clone()]));
    Ok(ok())
}

/// One store request on `store`, by `who`, whose relative paths start at
/// `home`; the changes it makes.
pub fn store_op(
    store: &mut Store,
    ty: u32,
    payload: &[u8],
    who: Who,
    home: &[u8],
    e: Ent,
    acl_max: usize,
) -> (R, Vec<Change>) {
    let one = || match split(payload, 2)[..] {
        [p, b""] => parse_path(p, home),
        _ => None,
    };
    let t = MsgType::from_u32(ty).unwrap();
    let mut changes = Vec::new();
    // A WRITE or MKDIR that fails leaves the store as it was, in the
    // native profile.
    let undo = (e.native && matches!(t, MsgType::Write | MsgType::Mkdir)).then(|| store.clone());
    let r = match t {
        MsgType::Read | MsgType::GetPerms | MsgType::Directory => match one() {
            None => Err("EINVAL"),
            Some(p) => match store.get(&p) {
                None => Err(missing(store, &p, who, b'r', e.native)),
                Some(n) if !allowed(&n.perms, who, b'r') => Err("EACCES"),
                Some(n) => Ok(match t {
                    MsgType::Read => n.value.clone(),
                    MsgType::GetPerms => n.perms.clone(),
                    _ => {
                        let mut out = Vec::new();
                        for k in store.keys().filter(|k| k.len() == p.len() + 1 && k.starts_with(&p)) {
                            out.extend_from_slice(k.last().unwrap());
                            out.push(0);
                        }
                        out
                    }
                }),
            },
        },
        MsgType::Write => match split(payload, 2)[..] {
            [p, v] => match parse_path(p, home) {
                None => Err("EINVAL"),
                Some(p) => op_write(store, p, v, who, e, &mut changes),
            },
            _ => Err("EINVAL"),
        },
        MsgType::Mkdir => match one() {
            None => Err("EINVAL"),
            Some(p) => op_mkdir(store, p, who, e, &mut changes),
        },
        MsgType::Rm => match one() {
            None => Err("EINVAL"),
            Some(p) => op_rm(store, p, who, e.native, &mut changes),
        },
        MsgType::SetPerms => match split(payload, 2)[..] {
            [p, perms] => match (parse_path(p, home), parse_perms(perms)) {
                (Some(_), Some(perms)) if !is_dom0(who) && perms.iter().filter(|c| **c == 0).count() - 1 > acl_max => {
                    Err(quota_error(e.native))
                }
                (Some(p), Some(perms)) => op_setperms(store, p, perms, who, e.native, &mut changes),
                _ => Err("EINVAL"),
            },
            _ => Err("EINVAL"),
        },
        _ => unreachable!(),
    };
    if let (Some(before), Err(_)) = (undo, &r) {
        *store = before;
    }
    (r, changes)
}

impl Model {
    fn new(q: Quotas, native: bool) -> Model {
        let mut store = Store::new();
        let n = |v: &[u8]| MNode {
            value: v.to_vec(),
            perms: b"n0\0".to_vec(),
        };
        store.insert(vec![], n(b""));
        for p in [&b"@introduceDomain"[..], b"@releaseDomain", b"local", b"tool"] {
            store.insert(vec![p.to_vec()], n(b""));
        }
        store.insert(vec![b"tool".to_vec(), b"xenstored".to_vec()], n(b"rxenstored"));
        Model {
            store,
            version: 0,
            conns: Vec::new(),
            q,
            native,
        }
    }

    /// The events of a change, each connection's in oxenstored's order
    /// (`ox/connections.ml:152-167`): the watches on the path and on its
    /// ancestors, the root first, each path's newest first; then, for an
    /// RM, those below it by path (each component in byte order, a node
    /// before what is below it), each path's newest first.
    fn fire(&self, change: &Change, out: &mut Vec<(usize, Msg)>) {
        let ev = |path: &[u8], token: &[u8]| (15u32, 0u32, 0u32, [path, b"\0", token, b"\0"].concat());
        let (p, roots): (&P, Vec<&Store>) = match change {
            Change::Normal(p, roots) => (p, roots.iter().collect()),
            Change::Rm(p, before) => (p, vec![before]),
        };
        // `lookup_watch_perms`: the permissions of the parent and of the
        // node, in each store where the parent exists; the watcher must be
        // able to read one of them.
        let readable = |stores: &[&Store], path: &P, who: Who| {
            !path.is_empty()
                && stores.iter().any(|r| {
                    let node = r.get(path).into_iter();
                    r.get(parent(path))
                        .into_iter()
                        .chain(node)
                        .any(|n| allowed(&n.perms, who, b'r'))
                })
        };
        for (ci, c) in self.conns.iter().enumerate() {
            let newest_first = || c.watches.iter().rev().filter_map(|w| w.key.as_ref().map(|k| (k, w)));
            for depth in 0..=p.len() {
                for (_, w) in newest_first().filter(|(k, _)| k[..] == p[..depth]) {
                    if readable(&roots, p, c.who()) {
                        let full = show(p);
                        let shown = if w.relative {
                            full[c.home().len()..].to_vec()
                        } else {
                            full
                        };
                        out.push((ci, ev(&shown, &w.token)));
                    }
                }
            }
            if let Change::Rm(_, before) = change {
                let mut below: Vec<_> = newest_first()
                    .filter(|(k, _)| k.len() > p.len() && k.starts_with(p))
                    .collect();
                // Stable: a path's watches stay newest first.
                below.sort_by(|x, y| x.0.cmp(y.0));
                for (k, w) in below {
                    if readable(&[before], k, c.who()) {
                        out.push((ci, ev(&w.path, &w.token)));
                    }
                }
            }
        }
    }

    fn request(&mut self, ci: usize, ty: u32, req: u32, tx: u32, payload: &[u8]) -> Vec<(usize, Msg)> {
        let mut out = Vec::new();
        let mt = MsgType::from_u32(ty);
        let tid = if matches!(mt, Some(MsgType::Watch | MsgType::Unwatch)) {
            0
        } else {
            tx
        };
        let reply = |r: R| -> Msg {
            match r {
                Ok(p) => (ty, req, tid, p),
                Err(e) => (16, req, tid, [e.as_bytes(), b"\0"].concat()),
            }
        };
        if tid != 0 && !self.conns[ci].txns.contains_key(&tid) {
            out.push((ci, reply(Err("EIO"))));
            return out;
        }
        let (who, home) = (self.conns[ci].who(), self.conns[ci].home());
        // Requests per transaction, before anything else.
        let q = self.q;
        let held = !is_dom0(who);
        let native = self.native;
        let requests = self.conns[ci].txns.get(&tid).map_or(0, |t| t.requests);
        if held && requests >= q.request_max {
            out.push((ci, reply(Err(quota_error(native)))));
            return out;
        }
        if let Some(t) = self.conns[ci].txns.get_mut(&tid) {
            t.requests += 1;
        }
        let max = held.then_some(q.entity_max);
        match mt {
            Some(
                MsgType::Read
                | MsgType::GetPerms
                | MsgType::Directory
                | MsgType::Write
                | MsgType::Mkdir
                | MsgType::Rm
                | MsgType::SetPerms,
            ) => {
                if tid == 0 {
                    let before = self.store.clone();
                    let (r, changes) = store_op(
                        &mut self.store,
                        ty,
                        payload,
                        who,
                        &home,
                        Ent { max, txn: None, native },
                        q.acl_max,
                    );
                    self.version += replaces(ty, &before, &self.store, &changes) as u64;
                    out.push((ci, reply(r)));
                    for c in &changes {
                        self.fire(c, &mut out);
                    }
                } else {
                    let t = self.conns[ci].txns.get_mut(&tid).unwrap();
                    let (global, snap) = (&self.store, &t.snapshot);
                    let (r, changes) = store_op(
                        &mut t.store,
                        ty,
                        payload,
                        who,
                        &home,
                        Ent {
                            max,
                            txn: Some((global, snap)),
                            native,
                        },
                        q.acl_max,
                    );
                    t.changes.extend(changes);
                    t.log.push((ty, payload.to_vec(), enc(&r), who));
                    out.push((ci, reply(r)));
                }
            }
            Some(MsgType::Watch | MsgType::Unwatch) => {
                let f = split(payload, 8);
                let r = if f.len() != 3 || !f[2].is_empty() || f[0].is_empty() {
                    Err("EINVAL")
                } else {
                    let (node, token) = (f[0], f[1]);
                    let apath = if node[0] == b'/' || node[0] == b'@' {
                        node.to_vec()
                    } else {
                        [&home[..], node].concat()
                    };
                    let c = &mut self.conns[ci];
                    let pos = c.watches.iter().position(|w| w.apath == apath && w.token == token);
                    let full = held && full(c.watches.len(), q.watch_max, native);
                    if mt == Some(MsgType::Unwatch) {
                        match pos {
                            Some(i) => {
                                c.watches.remove(i);
                                Ok(ok())
                            }
                            None => Err("ENOENT"),
                        }
                    } else {
                        let key = if node[0] == b'@' {
                            Some(None)
                        } else {
                            parse_path(&apath, &home).map(Some)
                        };
                        match key {
                            None => Err("EINVAL"),
                            Some(_) if full => Err(quota_error(native)),
                            Some(_) if pos.is_some() => Err("EEXIST"),
                            Some(key) => {
                                let relative = node[0] != b'/' && node[0] != b'@';
                                c.watches.push(MWatch {
                                    path: node.to_vec(),
                                    token: token.to_vec(),
                                    apath,
                                    key,
                                    relative,
                                });
                                out.push((ci, reply(Ok(ok()))));
                                out.push((ci, (15, 0, 0, [node, b"\0", token, b"\0"].concat())));
                                return out;
                            }
                        }
                    }
                };
                out.push((ci, reply(r)));
            }
            Some(MsgType::TransactionStart) => {
                if tid != 0 {
                    out.push((ci, reply(Err("EBUSY"))));
                } else if held && full(self.conns[ci].txns.len(), q.transaction_max, native) {
                    out.push((ci, reply(Err(quota_error(native)))));
                } else {
                    let c = &mut self.conns[ci];
                    let mut t = c.next_tid.max(1);
                    while c.txns.contains_key(&t) {
                        t += 1;
                    }
                    c.next_tid = t + 1;
                    c.txns.insert(
                        t,
                        MTxn {
                            store: self.store.clone(),
                            snapshot: self.store.clone(),
                            version: self.version,
                            requests: 0,
                            log: Vec::new(),
                            changes: Vec::new(),
                        },
                    );
                    out.push((ci, reply(Ok(format!("{t}\0").into_bytes()))));
                }
            }
            Some(MsgType::TransactionEnd) => {
                let commit = match split(payload, 8)[0] {
                    b"T" => Some(true),
                    b"F" => Some(false),
                    _ => None,
                };
                let r = match commit {
                    None => Err("EINVAL"),
                    Some(commit) => match self.conns[ci].txns.remove(&tid) {
                        None => Err("ENOENT"),
                        Some(t) if commit && !t.changes.is_empty() => {
                            let mut store = self.store.clone();
                            let mut same = true;
                            let mut replaced = false;
                            // Root not replaced since it started: oxenstored
                            // publishes the transaction's store as it is
                            // (`ox/connection.ml:402`,
                            // `ox/transaction.ml:238-246`). The
                            // requests run again here as they ran, by whom
                            // the connection was then, which gives that
                            // store. Otherwise they run again as the
                            // connection is now (`ox/process.ml:463-487`).
                            let unchanged = self.version == t.version;
                            for (ty, payload, recorded, then) in &t.log {
                                let who = if unchanged { *then } else { who };
                                let max = (!is_dom0(who)).then_some(q.entity_max);
                                let before = store.clone();
                                let e = Ent { max, txn: None, native };
                                let (r, c) = store_op(&mut store, *ty, payload, who, &home, e, q.acl_max);
                                replaced |= replaces(*ty, &before, &store, &c);
                                if enc(&r) != *recorded {
                                    same = false;
                                    break;
                                }
                            }
                            if same {
                                self.store = store;
                                self.version += replaced as u64;
                                // The changes its requests made as they ran
                                // in it, whatever running them again changed,
                                // checked against the store before the
                                // transaction and the one committed.
                                for c in t.changes {
                                    let c = match c {
                                        Change::Normal(p, roots) if roots.len() == 2 => {
                                            Change::Normal(p, vec![t.snapshot.clone(), self.store.clone()])
                                        }
                                        Change::Normal(p, _) => Change::Normal(p, vec![self.store.clone()]),
                                        Change::Rm(p, _) => Change::Rm(p, t.snapshot.clone()),
                                    };
                                    self.fire(&c, &mut out);
                                }
                                Ok(ok())
                            } else {
                                Err("EAGAIN")
                            }
                        }
                        Some(_) => Ok(ok()),
                    },
                };
                out.push((ci, reply(r)));
            }
            Some(MsgType::ResetWatches) => {
                self.conns[ci].watches.clear();
                self.conns[ci].txns.clear();
                out.push((ci, reply(Ok(ok()))));
            }
            Some(MsgType::GetDomainPath) => {
                let r = match split(payload, 8)[..] {
                    [d, b""] if d.iter().all(u8::is_ascii_digit) => Ok(format!(
                        "/local/domain/{}\0",
                        std::str::from_utf8(d).unwrap().parse::<u64>().unwrap_or(0)
                    )
                    .into_bytes()),
                    _ => Err("EINVAL"),
                };
                out.push((ci, reply(r)));
            }
            Some(MsgType::SetTarget) => {
                let f: Vec<&[u8]> = payload.split(|c| *c == 0).collect();
                let num = |d: &[u8]| std::str::from_utf8(d).unwrap().parse::<u32>().unwrap();
                let r = if !is_dom0(who) {
                    Err("EACCES")
                } else if f.len() != 3 || !f[2].is_empty() {
                    Err("EINVAL")
                } else {
                    match self.conns.iter_mut().find(|c| c.ring && c.domid == num(f[0])) {
                        None => Err("ENOENT"),
                        Some(c) => {
                            c.target = Some(num(f[1]));
                            Ok(ok())
                        }
                    }
                };
                out.push((ci, reply(r)));
            }
            // `print` only logs: OK for domain 0, and for a guest OK, or
            // EACCES in the native profile.
            Some(MsgType::Control) => {
                let r = if held && native { Err("EACCES") } else { Ok(ok()) };
                out.push((ci, reply(r)));
            }
            _ => out.push((ci, reply(Err("ENOSYS")))),
        }
        out
    }
}

/// Where the generator's choices come from: a seeded generator in
/// `model.rs`, the fuzzer's bytes in the fuzz target.
pub trait Source {
    /// A number below `n` (`n > 0`).
    fn below(&mut self, n: usize) -> usize;
    /// No more choices: the run ends before its next step.
    fn done(&self) -> bool {
        false
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

/// xorshift64*.
pub struct Rng(pub u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

impl Source for Rng {
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A source that writes down its choices, one byte each (every `n` asked
/// for is at most 60): the input of the fuzz target that replays them.
pub struct Recorder<S> {
    pub inner: S,
    pub choices: Vec<u8>,
}

impl<S: Source> Source for Recorder<S> {
    fn below(&mut self, n: usize) -> usize {
        let v = self.inner.below(n);
        self.choices.push(v as u8);
        v
    }

    fn done(&self) -> bool {
        self.inner.done()
    }
}

pub fn gen_path(rng: &mut impl Source) -> Vec<u8> {
    match rng.below(24) {
        0 => b"/".to_vec(),
        1 => b"a//b".to_vec(),
        2 => b"@introduceDomain".to_vec(),
        3 => b"".to_vec(),
        // The homes of the guests, where their relative paths go.
        4 => b"/local/domain/5".to_vec(),
        5 => b"/local/domain/3/a".to_vec(),
        _ => {
            let depth = 1 + rng.below(3);
            let mut s = Vec::new();
            let relative = rng.below(4) == 0;
            for i in 0..depth {
                if i > 0 || !relative {
                    s.push(b'/');
                }
                s.extend_from_slice(rng.pick(&[&b"a"[..], b"b", b"c"]));
            }
            s
        }
    }
}

/// A request on a connection with transactions `open`. In the native
/// profile a CONTROL `print` comes among the requests of the last branch;
/// the choices of the other profile are as they were.
pub fn gen_request(rng: &mut impl Source, open: &[u32], native: bool) -> (u32, u32, Vec<u8>) {
    let tx = match rng.below(10) {
        0..=4 => 0,
        5 => 99,
        _ => open.get(rng.below(open.len().max(1))).copied().unwrap_or(0),
    };
    let path = gen_path(rng);
    let z = |parts: &[&[u8]]| parts.iter().flat_map(|p| [*p, b"\0"].concat()).collect::<Vec<u8>>();
    let (ty, payload) = match rng.below(24) {
        0..=3 => {
            let v: &[u8] = match rng.below(6) {
                0 => b"",
                1 => b"yy",
                2 => &[b'x'; 2049],
                _ => b"x",
            };
            (MsgType::Write, [&path[..], b"\0", v].concat())
        }
        4 => (MsgType::Write, path.clone()),
        5..=6 => (MsgType::Mkdir, z(&[&path])),
        7..=8 => (MsgType::Rm, z(&[&path])),
        9 => (
            MsgType::SetPerms,
            z(&[
                &path,
                rng.pick(&[&b"n0"[..], b"r5", b"b0", b"n5", b"w0", b"n3"]),
                rng.pick(&[&b"w3"[..], b"r3", b"b5", b"n5"]),
            ]),
        ),
        22 => (MsgType::SetPerms, z(&[&path, rng.pick(&[&b"n5"[..], b"b3", b"r0"])])),
        // Domain 9 has no connection; acting for domain 0 is rare.
        23 => match rng.below(8) {
            0 => (MsgType::SetTarget, z(&[b"5"])),
            1 => (MsgType::SetTarget, z(&[rng.pick(&[&b"5"[..], b"3"]), b"0"])),
            _ => (
                MsgType::SetTarget,
                z(&[rng.pick(&[&b"5"[..], b"3", b"9"]), rng.pick(&[&b"5"[..], b"3", b"7"])]),
            ),
        },
        10 => (MsgType::SetPerms, z(&[&path, b"q1"])),
        11..=12 => (MsgType::Read, z(&[&path])),
        13 => (MsgType::Directory, z(&[&path])),
        14 => (MsgType::GetPerms, z(&[&path])),
        15..=16 => (MsgType::Watch, z(&[&path, rng.pick(&[&b"t1"[..], b"t2"])])),
        17 => (MsgType::Unwatch, z(&[&path, rng.pick(&[&b"t1"[..], b"t2"])])),
        18 => (MsgType::TransactionStart, b"\0".to_vec()),
        19..=20 => (
            MsgType::TransactionEnd,
            rng.pick(&[&b"T\0"[..], b"T\0", b"F\0", b"X\0"]).to_vec(),
        ),
        _ => match rng.below(if native { 3 } else { 2 }) {
            0 => (MsgType::ResetWatches, b"5\0".to_vec()),
            1 => (MsgType::GetDomainPath, b"5\0".to_vec()),
            _ => (MsgType::Control, b"print\0model\0".to_vec()),
        },
    };
    (ty as u32, tx, payload)
}

/// Per connection, messages in order, watch events included.
pub fn normalise(msgs: Vec<(usize, Msg)>, conns: usize) -> Vec<Vec<Msg>> {
    let mut per: Vec<Vec<Msg>> = vec![Vec::new(); conns];
    for (c, m) in msgs {
        per[c].push(m);
    }
    per
}

pub fn core_store(core: &Core) -> Store {
    fn walk(n: &xs_core::store::Node, p: &mut P, out: &mut Store) {
        out.insert(
            p.clone(),
            MNode {
                value: n.value.to_vec(),
                perms: n.perms.encode(),
            },
        );
        for (k, c) in n.children.iter() {
            p.push(k.to_vec());
            walk(c, p, out);
            p.pop();
        }
    }
    let mut out = Store::new();
    walk(core.root(), &mut Vec::new(), &mut out);
    out
}

/// What a run exercised.
#[derive(Default)]
pub struct Seen {
    pub commits: usize,
    pub conflicts: usize,
    /// Requests refused with EACCES.
    pub denied: usize,
    /// Changes of the store by a guest.
    pub guest_writes: usize,
    /// Watch events delivered to a guest.
    pub guest_events: usize,
    /// Requests refused by a quota (EQUOTA, or ENOSPC in the native
    /// profile).
    pub quota: usize,
}

/// The connections: two sockets, then the guests.
pub const DOMIDS: [Option<u32>; 4] = [None, None, Some(5), Some(3)];

/// The core and the model side by side, with the connections of `DOMIDS`.
pub struct Pair {
    core: Core,
    model: Model,
    ids: Vec<ConnId>,
    /// ORACLE_TRACE set: every step and what the model expects, on stderr.
    trace: bool,
}

impl Pair {
    /// The watch index keyed by `key`, the core and the model in profile
    /// `profile`.
    pub fn new(q: Quotas, profile: Profile, key: [u64; 2]) -> Pair {
        let cfg = Config {
            profile,
            entity_max: q.entity_max,
            watch_max: Some(q.watch_max),
            transaction_max: Some(q.transaction_max),
            request_max: Some(q.request_max),
            acl_max: q.acl_max,
            // The model has no conflict credit (tests.rs has its tests).
            conflict_burst_limit: f64::INFINITY,
            ..Config::default()
        };
        let mut pair = Pair {
            core: Core::new(cfg, key),
            model: Model::new(q, profile == Profile::Native),
            ids: Vec::new(),
            trace: std::env::var_os("ORACLE_TRACE").is_some(),
        };
        for i in 0..DOMIDS.len() {
            let (id, conn) = pair.connect(i);
            pair.ids.push(id);
            pair.model.conns.push(conn);
        }
        pair
    }

    fn connect(&mut self, i: usize) -> (ConnId, MConn) {
        match DOMIDS[i] {
            None => (self.core.open(), MConn::new(0, false)),
            Some(d) => (self.core.open_domain(d), MConn::new(d, true)),
        }
    }

    /// The client of connection `ci` goes away and a new one connects in
    /// its place.
    pub fn reopen(&mut self, ci: usize, step: usize) {
        if self.trace {
            eprintln!("step {step}: conn {ci} closed and opened again");
        }
        self.core.close(self.ids[ci]);
        (self.ids[ci], self.model.conns[ci]) = self.connect(ci);
    }

    /// The transactions open on connection `ci`.
    pub fn open_txns(&self, ci: usize) -> Vec<u32> {
        self.model.conns[ci].txns.keys().copied().collect()
    }

    /// Panics if the two stores differ.
    pub fn check_store(&self, what: &str) {
        assert_eq!(core_store(&self.core), self.model.store, "{what}");
    }

    /// One request on connection `ci`, made to both: panics if the replies
    /// or watch events differ, or the core's audit fails; else what
    /// connection `ci` got. `name` names the run in messages.
    #[allow(clippy::too_many_arguments)]
    pub fn step(
        &mut self,
        name: &str,
        step: usize,
        ci: usize,
        ty: u32,
        tx: u32,
        payload: &[u8],
        seen: &mut Seen,
    ) -> Vec<Msg> {
        const N: usize = DOMIDS.len();
        let (core, ids) = (&mut self.core, &self.ids);
        let req = step as u32;
        let expect = normalise(self.model.request(ci, ty, req, tx, payload), N);
        if self.trace {
            eprintln!(
                "step {step}: conn {ci} type {ty} tx {tx} {:?} -> {:?}",
                String::from_utf8_lossy(payload),
                expect
                    .iter()
                    .map(|c| c
                        .iter()
                        .map(|m| (m.0, m.2, String::from_utf8_lossy(&m.3).into_owned()))
                        .collect())
                    .collect::<Vec<Vec<_>>>()
            );
        }
        let mut bytes = Vec::new();
        write_header(&mut bytes, ty, req, tx, payload.len() as u32);
        bytes.extend_from_slice(payload);
        core.feed(ids[ci], &bytes);
        assert_eq!(core.process(ids[ci], 10), Status::Idle);
        let mut got = Vec::new();
        let mut dirty = Vec::new();
        core.take_dirty(&mut dirty);
        for id in dirty {
            let c = ids.iter().position(|x| *x == id).unwrap();
            let out = core.output(id).to_vec();
            core.consume(id, out.len());
            let mut rest = &out[..];
            while !rest.is_empty() {
                let w = |i: usize| u32::from_le_bytes(rest[i..i + 4].try_into().unwrap());
                let len = w(12) as usize;
                got.push((c, (w(0), w(4), w(8), rest[16..16 + len].to_vec())));
                rest = &rest[16 + len..];
            }
        }
        let got = normalise(got, N);
        if ty == MsgType::TransactionEnd as u32 && payload.starts_with(b"T") {
            for m in &expect[ci] {
                if m.0 == 16 && m.3 == b"EAGAIN\0" {
                    seen.conflicts += 1;
                } else if m.0 == ty {
                    seen.commits += 1;
                }
            }
        }
        let is_write = [MsgType::Write, MsgType::Mkdir, MsgType::Rm, MsgType::SetPerms]
            .iter()
            .any(|t| *t as u32 == ty);
        for (c, msgs) in expect.iter().enumerate() {
            for m in msgs {
                seen.denied += (m.0 == 16 && m.3 == b"EACCES\0") as usize;
                seen.quota += (m.0 == 16 && (m.3 == b"EQUOTA\0" || m.3 == b"ENOSPC\0")) as usize;
                seen.guest_writes += (DOMIDS[c].is_some() && is_write && tx == 0 && m.0 == ty) as usize;
                seen.guest_events += (DOMIDS[c].is_some() && m.0 == 15) as usize;
            }
        }
        let show = |v: &Vec<Vec<Msg>>| {
            format!(
                "{:?}",
                v.iter()
                    .map(|c| c
                        .iter()
                        .map(|m| (m.0, m.2, String::from_utf8_lossy(&m.3).into_owned()))
                        .collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            )
        };
        assert_eq!(
            got,
            expect,
            "{name} step {step}: conn {ci} type {ty} tx {tx} payload {:?}\n got {}\nwant {}",
            String::from_utf8_lossy(payload),
            show(&got),
            show(&expect)
        );
        if step.is_multiple_of(50) {
            self.check_store(&format!("{name} step {step}"));
        }
        self.core.audit().unwrap_or_else(|e| panic!("{name} step {step}: {e}"));
        got[ci].clone()
    }
}

/// Up to `steps` steps of choices from `rng` (fewer if it is `done`), with
/// the watch index keyed by `key`, in profile `profile`. `seed` only names
/// the run in messages.
pub fn run(
    rng: &mut impl Source,
    seed: u64,
    key: [u64; 2],
    steps: usize,
    q: Quotas,
    profile: Profile,
    seen: &mut Seen,
) {
    let name = format!("seed {seed} ({profile:?})");
    let mut pair = Pair::new(q, profile, key);
    for step in 0..steps {
        if rng.done() {
            break;
        }
        let ci = rng.below(DOMIDS.len());
        if rng.below(60) == 0 {
            pair.reopen(ci, step);
            continue;
        }
        let (ty, tx, payload) = gen_request(rng, &pair.open_txns(ci), profile == Profile::Native);
        let _ = pair.step(&name, step, ci, ty, tx, &payload, seen);
    }
    pair.check_store(&format!("{name} at the end"));
}
