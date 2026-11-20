// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The store: a persistent tree of nodes. A version of the whole store is
//! an `Arc<Node>` (its root); taking a snapshot is cloning that pointer.
//! A node lives in its parent's map of children, next to its name, and a
//! map shares its pages between versions: an update copies the pages on
//! the path from the root that are shared with another version, and
//! modifies unshared ones in place.
//!
//! Each operation exists once and runs against any version: the global
//! store, a transaction's private copy, or a commit being re-applied.

use crate::bytes::Bytes;
use crate::path::{Name, Path};
use crate::perms::{Access, Caller, Perms};
use crate::pmap::PMap;
use crate::prelude::*;
use crate::quota::Acct;
use crate::{Profile, Rules};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use xs_wire::Errno;

/// Default limit on a node's value (`quota-maxsize`); applies to domain 0 too.
pub const VALUE_MAX: usize = 2048;

#[derive(Clone, Debug)]
pub struct Node {
    pub value: Bytes,
    pub perms: Arc<Perms>,
    pub children: PMap<Name, Node>,
    /// Generation of the last change of value or permissions.
    pub vgen: u64,
    /// Generation of the last change of the set of children.
    pub cgen: u64,
}

impl Node {
    pub fn new(perms: Arc<Perms>, value: Bytes, gen: u64) -> Node {
        Node {
            value,
            perms,
            children: PMap::new(),
            vgen: gen,
            cgen: gen,
        }
    }

    pub fn child(&self, name: &[u8]) -> Option<&Node> {
        self.children.get(name)
    }
}

/// Source of generation numbers: every change gets a new one, so equal
/// generations mean equal content.
#[derive(Debug, Default)]
pub struct Gen(u64);

impl Gen {
    pub fn bump(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

pub fn lookup<'a>(root: &'a Node, path: &[Name]) -> Option<&'a Node> {
    path.iter().try_fold(root, |n, name| n.child(name))
}

/// Number of leading components of `path` that exist, and the deepest
/// node that does (`root` if none).
fn deepest<'a>(root: &'a Node, path: &[Name]) -> (usize, &'a Node) {
    let mut n = root;
    for (i, name) in path.iter().enumerate() {
        match n.child(name) {
            Some(c) => n = c,
            None => return (i, n),
        }
    }
    (path.len(), n)
}

/// Walks to `path`, creating missing nodes with permissions `perms`
/// (`Missing`), and calls `f` on the node. A missing node is made, and
/// what goes below it, before it is inserted.
fn walk_create<R>(
    n: &mut Node,
    path: &[Name],
    gen: &mut Gen,
    perms: &Arc<Perms>,
    f: impl FnOnce(&mut Node, &mut Gen) -> R,
) -> R {
    let Some((name, rest)) = path.split_first() else {
        return f(n, gen);
    };
    match n.children.get_mut(&**name) {
        Some(child) => walk_create(child, rest, gen, perms, f),
        None => {
            let g = gen.bump();
            let mut child = Node::new(perms.clone(), Bytes::EMPTY, g);
            let r = walk_create(&mut child, rest, gen, perms, f);
            n.children.insert(name.clone(), child);
            n.cgen = g;
            r
        }
    }
}

/// Walks to an existing node and calls `f` on it; the caller has checked
/// that it exists (were it missing, nothing would be called or changed).
fn walk_existing<R>(n: &mut Node, path: &[Name], f: impl FnOnce(&mut Node) -> R) -> Option<R> {
    match path.split_first() {
        None => Some(f(n)),
        Some((name, rest)) => n.children.get_mut(&**name).and_then(move |c| walk_existing(c, rest, f)),
    }
}

/// A change that may fire watches, with the versions of the store its
/// permission checks look at (`ox/process.ml:59-73`).
#[derive(Clone, Debug)]
pub struct Change {
    pub path: Path,
    pub kind: ChangeKind,
    pub before: Option<Arc<Node>>,
    pub after: Option<Arc<Node>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Write,
    Mkdir,
    Rm,
    SetPerms,
}

impl Change {
    /// The versions whose permissions decide whether a watch fires: the
    /// new store for write and mkdir, the old one for rm, both for setperms.
    pub fn roots(&self) -> impl Iterator<Item = &Node> {
        let (a, b) = match self.kind {
            ChangeKind::Write | ChangeKind::Mkdir => (self.after.as_deref(), None),
            ChangeKind::Rm => (self.before.as_deref(), None),
            ChangeKind::SetPerms => (self.before.as_deref(), self.after.as_deref()),
        };
        a.into_iter().chain(b)
    }
}

/// A store request, parsed.
#[derive(Clone, Debug)]
pub enum Op {
    Read(Path),
    GetPerms(Path),
    Directory(Path),
    Write(Path, Bytes),
    Mkdir(Path),
    Rm(Path),
    SetPerms(Path, Arc<Perms>),
}

impl Op {
    /// The path the request is on.
    pub fn path(&self) -> &Path {
        match self {
            Op::Read(p) | Op::GetPerms(p) | Op::Directory(p) | Op::Mkdir(p) | Op::Rm(p) => p,
            Op::Write(p, _) | Op::SetPerms(p, _) => p,
        }
    }

    pub fn is_write(&self) -> bool {
        !matches!(self, Op::Read(_) | Op::GetPerms(_) | Op::Directory(_))
    }
}

/// The result of an operation, as needed to reply. A transaction keeps
/// what tells whether a re-executed operation gives the same reply
/// (`txlog::Entry`).
#[derive(Clone, Debug)]
pub enum Outcome {
    Done,
    Value { vgen: u64, value: Bytes },
    Perms { vgen: u64, perms: Arc<Perms> },
    Children { cgen: u64, children: PMap<Name, Node> },
    Failed(Errno),
}

/// Who runs an operation, and under which limits.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub caller: Caller,
    /// The profile's rules.
    pub rules: Rules,
    /// `perms-activate`: without it, only a change of owner is refused.
    pub perms_active: bool,
    pub value_max: usize,
    /// Nodes a domain other than 0 may own, if the caller is held to it.
    pub entity_max: Option<usize>,
}

impl Ctx {
    /// Domain 0 with checks on and no limit on values.
    pub const DOM0: Ctx = Ctx {
        caller: Caller::DOM0,
        rules: Profile::Oxenstored.rules(),
        perms_active: true,
        value_max: usize::MAX,
        entity_max: None,
    };

    fn can(&self, node: &Node, want: Access) -> Result<(), Errno> {
        node.perms.check(self.perms_active, &self.caller, want)
    }

    /// The permissions of a node created below one with `parent`: those,
    /// or with `Rules::creator_owns` and a caller other than domain 0,
    /// those with the caller as owner. The record is shared when it does
    /// not change.
    fn created(&self, parent: &Arc<Perms>) -> Arc<Perms> {
        let owner = i64::from(self.caller.domid);
        if self.rules.creator_owns && !self.caller.is_dom0() && parent.owner != owner {
            Arc::new(Perms {
                owner,
                ..(**parent).clone()
            })
        } else {
            parent.clone()
        }
    }

    /// The error for `path`, which does not exist, asked for `want`:
    /// ENOENT, or with `Rules::hide_missing` EACCES to a caller that may
    /// not `want` its nearest existing ancestor.
    fn missing(&self, root: &Node, path: &[Name], want: Access) -> Errno {
        if self.rules.hide_missing && self.can(deepest(root, path).1, want).is_err() {
            Errno::EACCES
        } else {
            Errno::ENOENT
        }
    }
}

/// Executes `op` on the store version `root`, whose node counts `acct`
/// has. Changes that may fire watches are appended to `changes`, and tell
/// whether oxenstored would count the operation as a write of its
/// transaction (its `add_wop`).
///
/// Access is checked as oxenstored does (`ox/store.ml:257-356`): on the
/// node itself, never on the way to it, so a missing node is ENOENT to
/// everybody (but with `Rules::hide_missing`); a node that does not exist
/// yet needs write access to its parent, and missing parents to the
/// deepest existing one, whose permissions they get (`ox/process.ml:74-87`;
/// with `Rules::creator_owns`, `Ctx::created`).
///
/// A node that does not exist yet must also fit in its owner's quota,
/// checked before the access (`ox/store.ml:415-436`); missing parents are
/// created one by one, so those that fit stay when the quota runs out
/// (none with `Rules::all_or_nothing`: a request that fails makes
/// nothing).
pub fn execute(
    root: &mut Arc<Node>,
    gen: &mut Gen,
    op: &Op,
    ctx: &Ctx,
    acct: &mut Acct,
    changes: &mut Vec<Change>,
) -> Outcome {
    match run(root, gen, op, ctx, acct, true) {
        Ok((outcome, fired)) => {
            if let Some((kind, before)) = fired {
                changes.push(Change {
                    path: op.path().clone(),
                    kind,
                    before,
                    after: (kind != ChangeKind::Rm).then(|| root.clone()),
                });
            }
            outcome
        }
        Err(e) => Outcome::Failed(e),
    }
}

/// As `execute`, in a transaction's version or in a commit being
/// re-applied: no version of the store is kept, since the commit checks
/// watches against the store before and after the whole transaction
/// (`ox/process.ml:59-73`). A version kept per change would make the next
/// request copy every page on its path, and keep the copy. Returns the
/// kind of change that may fire watches, if any.
pub fn execute_in(
    root: &mut Arc<Node>,
    gen: &mut Gen,
    op: &Op,
    ctx: &Ctx,
    acct: &mut Acct,
) -> (Outcome, Option<ChangeKind>) {
    match run(root, gen, op, ctx, acct, false) {
        Ok((outcome, fired)) => (outcome, fired.map(|(kind, _)| kind)),
        Err(e) => (Outcome::Failed(e), None),
    }
}

/// The node of a READ, DIRECTORY or GET_PERMS.
fn readable<'a>(root: &'a Node, p: &Path, ctx: &Ctx) -> Result<&'a Node, Errno> {
    let n = lookup(root, p).ok_or_else(|| ctx.missing(root, p, Access::Read))?;
    ctx.can(n, Access::Read).map(|()| n)
}

/// What is missing of a path, to be created: each node a MKDIR
/// (`ox/process.ml:74-87`, `ox/store.ml:429-436`), its owner's quota then
/// access to its parent. They all get the same permissions, those
/// `Ctx::created` gives below the deepest node that exists, so the same
/// owner and the same answer.
struct Missing {
    /// Components of the path that exist.
    depth: usize,
    /// The permissions of the nodes to create.
    perms: Arc<Perms>,
    /// Nodes their owner's quota has room for.
    room: usize,
}

impl Missing {
    /// Checks the first node to create below the deepest that exists of
    /// `path`: its owner's quota, then write access to that node.
    fn of(root: &Node, path: &[Name], ctx: &Ctx, acct: &Acct) -> Result<Missing, Errno> {
        let (depth, deepest) = deepest(root, path);
        let perms = ctx.created(&deepest.perms);
        let room = acct.room(perms.owner, ctx.entity_max);
        if room == 0 {
            return Err(ctx.rules.quota_error);
        }
        ctx.can(deepest, Access::Write)?;
        Ok(Missing { depth, perms, room })
    }

    /// Creates the missing nodes of `path` (whose `Missing` this is) that
    /// the quota has room for, and fails if that is not all of them; with
    /// `Rules::all_or_nothing`, creates none then.
    fn create(
        &self,
        root: &mut Arc<Node>,
        gen: &mut Gen,
        path: &[Name],
        ctx: &Ctx,
        acct: &mut Acct,
    ) -> Result<(), Errno> {
        let missing = path.len() - self.depth;
        if self.room < missing && ctx.rules.all_or_nothing {
            return Err(ctx.rules.quota_error);
        }
        let n = self.room.min(missing);
        // `depth + n` is at most `path.len()`.
        walk_create(
            Arc::make_mut(root),
            path.get(..self.depth + n).unwrap_or(path),
            gen,
            &self.perms,
            |_, _| (),
        );
        acct.add(self.perms.owner, n as isize);
        if n < missing {
            return Err(ctx.rules.quota_error);
        }
        Ok(())
    }
}

/// A change that may fire watches: its kind, and the store before it if
/// it was asked for (`keep`) and the kind needs it (RM, SET_PERMS).
type Fired = Option<(ChangeKind, Option<Arc<Node>>)>;

fn run(
    root: &mut Arc<Node>,
    gen: &mut Gen,
    op: &Op,
    ctx: &Ctx,
    acct: &mut Acct,
    keep: bool,
) -> Result<(Outcome, Fired), Errno> {
    let value_max = ctx.value_max;
    let before = |root: &Arc<Node>| keep.then(|| root.clone());
    Ok(match op {
        Op::Read(p) => {
            let n = readable(root, p, ctx)?;
            let value = n.value.clone();
            (Outcome::Value { vgen: n.vgen, value }, None)
        }
        Op::GetPerms(p) => {
            let n = readable(root, p, ctx)?;
            let perms = n.perms.clone();
            (Outcome::Perms { vgen: n.vgen, perms }, None)
        }
        Op::Directory(p) => {
            let n = readable(root, p, ctx)?;
            let children = n.children.clone();
            (Outcome::Children { cgen: n.cgen, children }, None)
        }
        Op::Write(p, value) => {
            let Some((name, parent)) = p.split_last() else {
                // The root: no parent to create (`ox/store.ml:286-289`).
                // The size is checked before the access (`ox/store.ml:414-427`).
                if value.len() > value_max {
                    return Err(Errno::E2BIG);
                }
                ctx.can(root, Access::Write)?;
                let n = Arc::make_mut(root);
                if n.value != *value {
                    n.value = value.clone();
                    n.vgen = gen.bump();
                }
                return Ok((Outcome::Done, Some((ChangeKind::Write, None))));
            };
            let (depth, parent_node) = deepest(root, parent);
            let quota = ctx.rules.quota_error;
            // The permissions of the node if it is new: those of the
            // parents created for it, if any.
            let perms = if depth < parent.len() {
                // New parents have the permissions `Missing` gives them,
                // and no child yet.
                let missing = Missing::of(root, parent, ctx, acct)?;
                let parents = parent.len() - depth;
                if ctx.rules.all_or_nothing {
                    // Nothing is made before every check has passed, which
                    // give the answer of the order below.
                    if missing.room < parents {
                        return Err(quota);
                    }
                    if value.len() > value_max {
                        return Err(Errno::E2BIG);
                    }
                    if missing.room == parents {
                        return Err(quota);
                    }
                }
                missing.create(root, gen, parent, ctx, acct)?;
                if value.len() > value_max {
                    // Missing parents are created before the size is checked
                    // (`ox/process.ml:305-310`, `ox/store.ml:415-423`).
                    return Err(Errno::E2BIG);
                }
                if acct.room(missing.perms.owner, ctx.entity_max) == 0 {
                    return Err(quota);
                }
                missing.perms
            } else {
                if value.len() > value_max {
                    return Err(Errno::E2BIG);
                }
                match parent_node.child(name) {
                    Some(node) => {
                        ctx.can(node, Access::Write)?;
                        // Not used: nothing is created.
                        node.perms.clone()
                    }
                    None => {
                        let perms = ctx.created(&parent_node.perms);
                        if acct.room(perms.owner, ctx.entity_max) == 0 {
                            return Err(quota);
                        }
                        ctx.can(parent_node, Access::Write)?;
                        perms
                    }
                }
            };
            let created = walk_create(Arc::make_mut(root), parent, gen, &perms, |n, gen| {
                match n.children.get_mut(&**name) {
                    Some(child) => {
                        if child.value != *value {
                            child.value = value.clone();
                            child.vgen = gen.bump();
                        }
                        false
                    }
                    None => {
                        let g = gen.bump();
                        n.children
                            .insert(name.clone(), Node::new(perms.clone(), value.clone(), g));
                        n.cgen = g;
                        true
                    }
                }
            });
            if created {
                acct.add(perms.owner, 1);
            }
            (Outcome::Done, Some((ChangeKind::Write, None)))
        }
        Op::Mkdir(p) => {
            if p.is_empty() {
                // Nothing is checked on the root (`ox/store.ml:267-268`).
                return Ok((Outcome::Done, Some((ChangeKind::Mkdir, None))));
            }
            let (depth, node) = deepest(root, p);
            if depth == p.len() {
                // EEXIST, after the access check, is swallowed and fires
                // nothing (`ox/store.ml:258-266`, `ox/process.ml:312-318`).
                ctx.can(node, Access::Write)?;
                return Ok((Outcome::Done, None));
            }
            Missing::of(root, p, ctx, acct)?.create(root, gen, p, ctx, acct)?;
            (Outcome::Done, Some((ChangeKind::Mkdir, None)))
        }
        Op::Rm(p) => {
            let Some((name, parent)) = p.split_last() else {
                // Removing the root removes its children (`ox/store.ml:302-305`),
                // or with `Rules::root_stays` is refused
                // (`cx417/xenstored_core.c:1725-1726`).
                ctx.can(root, Access::Write)?;
                if ctx.rules.root_stays {
                    return Err(Errno::EINVAL);
                }
                for (_, c) in root.children.iter() {
                    acct.remove_tree(c);
                }
                let before = before(root);
                let n = Arc::make_mut(root);
                n.children = PMap::new();
                n.cgen = gen.bump();
                return Ok((Outcome::Done, Some((ChangeKind::Rm, before))));
            };
            // A missing ancestor is an error; a missing node is not
            // (`ox/store.ml:189-203`, `ox/process.ml:320-325`), but with
            // `Rules::hide_missing` to who may not write its parent
            // (`cx417/xenstored_core.c:1701-1716`).
            let parent_node = lookup(root, parent).ok_or_else(|| ctx.missing(root, parent, Access::Write))?;
            let Some(node) = parent_node.child(name) else {
                if ctx.rules.hide_missing {
                    ctx.can(parent_node, Access::Write)?;
                }
                return Ok((Outcome::Done, None));
            };
            // Only the node is checked: neither its parent nor what is below.
            ctx.can(node, Access::Write)?;
            acct.remove_tree(node);
            let before = before(root);
            walk_existing(Arc::make_mut(root), parent, |n| {
                n.children.remove(&**name);
                n.cgen = gen.bump();
            });
            (Outcome::Done, Some((ChangeKind::Rm, before)))
        }
        Op::SetPerms(p, perms) => {
            let node = lookup(root, p).ok_or_else(|| ctx.missing(root, p, Access::Write))?;
            // Only domain 0 changes the owner, whatever `perms-activate`
            // says (`ox/store.ml:447-449`).
            if node.perms.owner != perms.owner && !ctx.caller.is_dom0() {
                return Err(Errno::EACCES);
            }
            // The root has no owner check (`ox/store.ml:309-321`).
            if !p.is_empty() {
                node.perms.check_owner(ctx.perms_active, &ctx.caller)?;
            }
            ctx.can(node, Access::Write)?;
            // The node goes to its new owner, whatever its quota
            // (`ox/store.ml:446-457`); the root never counts.
            if !p.is_empty() && node.perms.owner != perms.owner {
                acct.add(node.perms.owner, -1);
                acct.add(perms.owner, 1);
            }
            let before = before(root);
            walk_existing(Arc::make_mut(root), p, |n| {
                if *n.perms != **perms {
                    n.perms = perms.clone();
                    n.vgen = gen.bump();
                }
            });
            (Outcome::Done, Some((ChangeKind::SetPerms, before)))
        }
    })
}

/// The owner of the root once its owner's domain is gone: oxenstored marks
/// it invalid (-1) since the root cannot be removed (`ox/store.ml:96-109`).
/// The nodes created below it since have it too, and count for it. No
/// domid is -1: it prints as 9223372036854775807 (`Perms::encode_sep`).
pub const NO_OWNER: i64 = -1;

/// What oxenstored does to the store when domains go (`Store.reset_permissions`,
/// `ox/store.ml:459-469`, `ox/perms.ml:65-67`): every node one of them owns
/// is removed with everything below it, firing no watch; elsewhere their
/// ACL entries are dropped. The root loses its owner instead, and keeps
/// its ACL. A walk of the whole store, as in oxenstored; what does not
/// change is not copied, and nodes that shared a permission record still
/// share one. What goes is uncounted, whoever owned it.
pub fn forget_domains(root: &mut Arc<Node>, gen: &mut Gen, dead: &[u32], acct: &mut Acct) {
    if dead.is_empty() {
        return;
    }
    if let Some(n) = forget_in(root, gen, dead, acct, &mut BTreeMap::new()) {
        *root = Arc::new(n);
    }
}

/// The node without the domains, None if that is the node as it is.
/// `memo` maps a permission record (by address) to its replacement.
fn forget_in(
    n: &Node,
    gen: &mut Gen,
    dead: &[u32],
    acct: &mut Acct,
    memo: &mut BTreeMap<usize, Option<Arc<Perms>>>,
) -> Option<Node> {
    let gone = |owner: i64| dead.iter().any(|d| i64::from(*d) == owner);
    let mut copy: Option<Node> = None;
    for (name, child) in n.children.iter() {
        if gone(child.perms.owner) {
            acct.remove_tree(child);
            let c = copy.get_or_insert_with(|| n.clone());
            c.children.remove(&**name);
            c.cgen = gen.bump();
        } else if let Some(new) = forget_in(child, gen, dead, acct, memo) {
            copy.get_or_insert_with(|| n.clone()).children.insert(name.clone(), new);
        }
    }
    let perms = memo.entry(Arc::as_ptr(&n.perms) as usize).or_insert_with(|| {
        let p = &n.perms;
        if gone(p.owner) {
            // Only the root gets here: other nodes went with their parent.
            Some(Arc::new(Perms {
                owner: NO_OWNER,
                ..(**p).clone()
            }))
        } else {
            let acl: Vec<_> = p.acl.iter().copied().filter(|(d, _)| !dead.contains(d)).collect();
            (acl.len() != p.acl.len()).then(|| Arc::new(Perms { acl, ..(**p).clone() }))
        }
    });
    if let Some(p) = perms {
        let c = copy.get_or_insert_with(|| n.clone());
        c.perms = p.clone();
        c.vgen = gen.bump();
    }
    copy
}

/// The store oxenstored starts with (`ox/xenstored.ml:418-459`): the
/// special nodes, `/local`, and `/tool/xenstored`, counted in `acct`.
pub fn initial(gen: &mut Gen, tool_xenstored: &[u8], acct: &mut Acct) -> Arc<Node> {
    let mut root = Arc::new(Node::new(Arc::new(Perms::default0()), Bytes::EMPTY, gen.bump()));
    let name = |s: &[u8]| Name::from(s);
    let mut sink = Vec::new();
    for op in [
        Op::Write(vec![name(b"@introduceDomain")], Bytes::EMPTY),
        Op::Write(vec![name(b"@releaseDomain")], Bytes::EMPTY),
        Op::Mkdir(vec![name(b"local")]),
        Op::Write(vec![name(b"tool"), name(b"xenstored")], Bytes::from(tool_xenstored)),
    ] {
        execute(&mut root, gen, &op, &Ctx::DOM0, acct, &mut sink);
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::Entries;

    fn path(s: &str) -> Path {
        crate::path::parse(s.as_bytes(), b"/local/domain/0/", 1024).unwrap()
    }

    struct T {
        root: Arc<Node>,
        gen: Gen,
        changes: Vec<Change>,
        ctx: Ctx,
        entries: Entries,
    }

    impl T {
        fn new() -> T {
            let mut gen = Gen::default();
            let mut entries = Entries::default();
            let root = initial(&mut gen, b"/usr/sbin/rxenstored", &mut Acct::Store(&mut entries));
            T {
                root,
                gen,
                changes: Vec::new(),
                ctx: Ctx {
                    value_max: VALUE_MAX,
                    ..Ctx::DOM0
                },
                entries,
            }
        }
        /// Runs an operation, and checks the node counts after it.
        fn run(&mut self, op: Op) -> Outcome {
            let r = execute(
                &mut self.root,
                &mut self.gen,
                &op,
                &self.ctx,
                &mut Acct::Store(&mut self.entries),
                &mut self.changes,
            );
            assert_eq!(self.entries, Entries::recount(&self.root), "{op:?}");
            r
        }
        /// The next operations are run by this domain.
        fn by(&mut self, domid: u32, target: Option<u32>) -> &mut T {
            self.ctx.caller = Caller { domid, target };
            self
        }
        /// The error of an operation, None if it succeeded.
        fn err(&mut self, op: Op) -> Option<Errno> {
            match self.run(op) {
                Outcome::Failed(e) => Some(e),
                _ => None,
            }
        }
        fn w(&mut self, p: &str, v: &str) -> Option<Errno> {
            self.err(Op::Write(path(p), Bytes::from(v.as_bytes())))
        }
        fn set(&mut self, p: &str, perms: &[u8]) -> Option<Errno> {
            self.err(Op::SetPerms(path(p), Arc::new(Perms::parse(perms).unwrap())))
        }
        fn perms(&self, p: &str) -> Vec<u8> {
            lookup(&self.root, &path(p)).unwrap().perms.encode()
        }
        fn exists(&self, p: &str) -> bool {
            lookup(&self.root, &path(p)).is_some()
        }
        fn write(&mut self, p: &str, v: &str) -> Outcome {
            self.run(Op::Write(path(p), Bytes::from(v.as_bytes())))
        }
        fn read(&mut self, p: &str) -> Result<Vec<u8>, Errno> {
            match self.run(Op::Read(path(p))) {
                Outcome::Value { value, .. } => Ok(value.to_vec()),
                Outcome::Failed(e) => Err(e),
                o => panic!("{o:?}"),
            }
        }
        fn ls(&mut self, p: &str) -> Result<Vec<String>, Errno> {
            match self.run(Op::Directory(path(p))) {
                Outcome::Children { children, .. } => Ok(children
                    .keys()
                    .map(|k| String::from_utf8(k.to_vec()).unwrap())
                    .collect()),
                Outcome::Failed(e) => Err(e),
                o => panic!("{o:?}"),
            }
        }
        fn kinds(&mut self) -> Vec<(String, ChangeKind)> {
            self.changes
                .drain(..)
                .map(|c| (String::from_utf8(crate::path::to_string(&c.path)).unwrap(), c.kind))
                .collect()
        }
    }

    /// `/p` readable by domain 5, with one child of each kind.
    fn guarded() -> T {
        let mut t = T::new();
        for p in ["/p/own", "/p/w", "/p/rw", "/p/none/below"] {
            assert_eq!(t.w(p, "v"), None);
        }
        assert_eq!(t.set("/p", b"n0\0r5\0"), None);
        assert_eq!(t.set("/p/own", b"n5\0"), None);
        assert_eq!(t.set("/p/w", b"n0\0w5\0"), None);
        assert_eq!(t.set("/p/rw", b"n0\0b5\0"), None);
        t.kinds();
        t.by(5, None);
        t
    }

    const EACCES: Option<Errno> = Some(Errno::EACCES);
    const ENOENT: Option<Errno> = Some(Errno::ENOENT);
    const E2BIG: Option<Errno> = Some(Errno::E2BIG);

    #[test]
    fn reading_needs_read_access_to_the_node_only() {
        let mut t = guarded();
        let ops = |p: &str| [Op::Read(path(p)), Op::Directory(path(p)), Op::GetPerms(path(p))];
        for (p, want) in [
            ("/p", None),
            ("/p/own", None),
            ("/p/rw", None),
            ("/p/w", EACCES),
            ("/p/none", EACCES),
            ("/", EACCES),
            // Existence is not hidden, and the way to a node is not checked.
            ("/p/missing", ENOENT),
            ("/p/none/missing", ENOENT),
            ("/p/none/missing/deeper", ENOENT),
        ] {
            for op in ops(p) {
                assert_eq!(t.err(op.clone()), want, "{op:?}");
            }
        }
        // `/p/none/below` got the permissions of `/p` as it was then.
        assert_eq!(t.perms("/p/none/below"), b"n0\0");
        assert_eq!(t.read("/p/none/below"), Err(Errno::EACCES));
        // Domain 0, a domain acting for domain 0, and anybody without checks.
        for (domid, target, active) in [(0, None, true), (7, Some(0), true), (7, None, false)] {
            t.by(domid, target).ctx.perms_active = active;
            for op in ops("/p/none") {
                assert_eq!(t.err(op), None, "{domid} {target:?} {active}");
            }
        }
        // Through the target domain.
        t.by(9, Some(5)).ctx.perms_active = true;
        assert_eq!(t.read("/p/rw"), Ok(b"v".to_vec()));
        assert_eq!(t.by(9, None).read("/p/rw"), Err(Errno::EACCES));
    }

    #[test]
    fn write_needs_write_access_to_the_node_or_to_its_deepest_existing_parent() {
        let mut t = guarded();
        assert_eq!(t.w("/p/w", "1"), None);
        assert_eq!(t.w("/p/rw", "1"), None);
        assert_eq!(t.w("/p/own", "1"), None);
        assert_eq!(t.w("/p/none", "1"), EACCES);
        assert_eq!(t.w("/p", "1"), EACCES, "read only");
        assert_eq!(t.w("/", "1"), EACCES);
        assert_eq!(t.w("/p/new", "1"), EACCES, "a new node needs its parent");
        assert_eq!(t.w("/p/w/new", "1"), None);
        assert_eq!(t.perms("/p/w/new"), b"n0\0w5\0", "inherited");
        assert_eq!(t.w("/p/w/x/y/z", "1"), None);
        assert_eq!(t.perms("/p/w/x/y"), b"n0\0w5\0");
        assert_eq!(t.w("/p/none/x/y", "1"), EACCES);
        assert!(!t.exists("/p/none/x"), "nothing is created");
        assert_eq!(t.w("/q/r", "1"), EACCES, "the root is the deepest existing parent");
        assert_eq!(t.kinds().len(), 5, "only what succeeded may fire");
        assert_eq!(t.by(0, None).read("/p/none"), Ok(b"".to_vec()));
        assert_eq!(t.read("/p"), Ok(b"".to_vec()));
    }

    #[test]
    fn write_checks_the_size_between_the_parents_and_the_node() {
        let mut t = guarded();
        let big = "x".repeat(VALUE_MAX + 1);
        // Missing parents: access to the deepest existing one comes first.
        assert_eq!(t.w("/p/none/a/b", &big), EACCES);
        assert_eq!(t.w("/p/w/a/b", &big), E2BIG);
        assert!(t.exists("/p/w/a") && !t.exists("/p/w/a/b"), "and they are created");
        // No missing parent: the size comes first.
        assert_eq!(t.w("/p/none", &big), E2BIG);
        assert_eq!(t.w("/p/new", &big), E2BIG);
        assert_eq!(t.w("/", &big), E2BIG);
        assert_eq!(t.w("/p/w", &big), E2BIG);
        assert_eq!(t.kinds(), []);
    }

    #[test]
    fn mkdir_needs_write_access_even_to_an_existing_node() {
        let mut t = guarded();
        let mut mk = |p: &str| t.err(Op::Mkdir(path(p)));
        assert_eq!(mk("/p/none"), EACCES);
        assert_eq!(mk("/p"), EACCES);
        assert_eq!(mk("/p/w"), None);
        assert_eq!(mk("/p/new"), EACCES);
        assert_eq!(mk("/p/none/m/n"), EACCES);
        assert_eq!(mk("/p/w/m/n"), None);
        assert_eq!(mk("/"), None, "nothing is checked on the root");
        assert_eq!(t.perms("/p/w/m/n"), b"n0\0w5\0");
        assert!(!t.exists("/p/new") && !t.exists("/p/none/m"));
        assert_eq!(
            t.kinds(),
            [("/p/w/m/n".into(), ChangeKind::Mkdir), ("/".into(), ChangeKind::Mkdir)]
        );
    }

    #[test]
    fn rm_needs_write_access_to_the_node_alone() {
        let mut t = guarded();
        let rm = |t: &mut T, p: &str| t.err(Op::Rm(path(p)));
        assert_eq!(rm(&mut t, "/p/none"), EACCES);
        assert_eq!(rm(&mut t, "/p/none/below"), EACCES);
        assert_eq!(rm(&mut t, "/"), EACCES);
        assert_eq!(rm(&mut t, "/p/missing"), None);
        assert_eq!(rm(&mut t, "/missing/x"), ENOENT);
        assert_eq!(t.kinds(), []);
        // Not its parent (read only), and not what is below it.
        assert_eq!(t.by(0, None).w("/p/w/sub", "1"), None);
        assert_eq!(t.set("/p/w/sub", b"n0\0"), None);
        t.kinds();
        assert_eq!(rm(t.by(5, None), "/p/w"), None);
        assert!(!t.exists("/p/w"));
        assert_eq!(t.kinds(), [("/p/w".into(), ChangeKind::Rm)]);
        // The root, for who may write it.
        assert_eq!(t.by(0, None).set("/", b"n0\0w5\0"), None);
        assert_eq!(rm(t.by(5, None), "/"), None);
        assert!(!t.exists("/p"));
    }

    #[test]
    fn set_perms_is_for_the_owner_and_only_domain_0_changes_the_owner() {
        let mut t = guarded();
        assert_eq!(t.set("/p/own", b"r5\0w6\0"), None);
        assert_eq!(t.perms("/p/own"), b"r5\0w6\0");
        assert_eq!(t.set("/p/own", b"n0\0"), EACCES, "giving it away");
        assert_eq!(t.set("/p/rw", b"n0\0b5\0"), EACCES, "write access is not ownership");
        assert_eq!(t.set("/p/rw", b"n5\0"), EACCES);
        assert_eq!(t.set("/p/missing", b"n5\0"), ENOENT);
        assert_eq!(t.set("/missing/x", b"n5\0"), ENOENT);
        assert_eq!(t.kinds(), [("/p/own".into(), ChangeKind::SetPerms)]);
        // Domain 6 may write the node but does not own it.
        assert_eq!(t.by(6, None).w("/p/own", "1"), None);
        assert_eq!(t.set("/p/own", b"r5\0b6\0"), EACCES);
        // A domain acting for the owner does.
        assert_eq!(t.by(9, Some(5)).set("/p/own", b"b5\0"), None);
        // Domain 0 changes owners.
        assert_eq!(t.by(0, None).set("/p/rw", b"n5\0"), None);
        assert_eq!(t.by(3, Some(0)).set("/p/rw", b"n7\0"), None);
        // The root has no owner check: write access is enough, but the
        // owner stays.
        assert_eq!(t.by(5, None).set("/", b"b0\0"), EACCES);
        assert_eq!(t.by(0, None).set("/", b"n0\0w5\0"), None);
        assert_eq!(t.by(5, None).set("/", b"b0\0"), None);
        assert_eq!(t.perms("/"), b"b0\0");
        assert_eq!(t.set("/", b"b5\0"), EACCES);
    }

    #[test]
    fn without_perms_activate_only_the_owner_change_is_refused() {
        let mut t = guarded();
        t.ctx.perms_active = false;
        assert_eq!(t.w("/p/none", "1"), None);
        assert_eq!(t.w("/p/new/deep", "1"), None);
        assert_eq!(t.err(Op::Mkdir(path("/p/none/m"))), None);
        assert_eq!(t.err(Op::Rm(path("/p/none/below"))), None);
        assert_eq!(t.set("/p/none", b"r0\0"), None, "not the owner");
        assert_eq!(t.set("/p/none", b"r5\0"), EACCES);
        assert_eq!(t.err(Op::Rm(path("/"))), None);
    }

    #[test]
    fn forgetting_domains_removes_what_they_own_and_their_acl_entries() {
        let mut t = T::new();
        for p in ["/a/mine/x", "/a/theirs/y", "/b/c", "/b/d"] {
            assert_eq!(t.w(p, "v"), None);
        }
        assert_eq!(t.set("/a/mine", b"b5\0"), None);
        assert_eq!(t.set("/a/mine/x", b"n7\0"), None);
        assert_eq!(t.set("/a/theirs", b"n7\0r5\0w9\0r6\0"), None);
        // /b/c and /b/d were created below /b: they share its record.
        assert_eq!(t.set("/b", b"n0\0r6\0"), None);
        assert_eq!(t.w("/b/e", ""), None);
        assert_eq!(t.w("/b/f", ""), None);
        let before = t.root.clone();
        let version = |t: &T, p: &str| {
            let n = lookup(&t.root, &path(p)).unwrap();
            (n.vgen, n.cgen)
        };
        let (tool, a) = (version(&t, "/tool"), version(&t, "/a"));
        t.kinds();
        forget_domains(&mut t.root, &mut t.gen, &[], &mut Acct::Store(&mut t.entries));
        forget_domains(&mut t.root, &mut t.gen, &[8], &mut Acct::Store(&mut t.entries));
        assert!(Arc::ptr_eq(&before, &t.root), "nothing to forget: not even copied");
        forget_domains(&mut t.root, &mut t.gen, &[5, 6], &mut Acct::Store(&mut t.entries));
        // What 5 owns goes, with what is below whoever owns it.
        assert!(!t.exists("/a/mine"));
        assert_eq!(t.perms("/a/theirs"), b"n7\0w9\0");
        assert_eq!(t.perms("/a/theirs/y"), b"n0\0", "never had an entry");
        assert_eq!(t.perms("/b"), b"n0\0");
        let (b, e, f) = (
            lookup(&t.root, &path("/b")).unwrap(),
            lookup(&t.root, &path("/b/e")).unwrap(),
            lookup(&t.root, &path("/b/f")).unwrap(),
        );
        assert!(
            Arc::ptr_eq(&b.perms, &e.perms) && Arc::ptr_eq(&e.perms, &f.perms),
            "still shared"
        );
        assert_eq!(t.perms("/b/c"), b"n0\0");
        // The generations move where something changed, and only there.
        let (a2, tool2) = (version(&t, "/a"), version(&t, "/tool"));
        assert_eq!((a2.0, tool2), (a.0, tool));
        assert!(a2.1 > a.1, "a child of /a went");
        assert!(lookup(&t.root, &path("/a/theirs")).unwrap().vgen > lookup(&before, &path("/a/theirs")).unwrap().vgen);
        assert_eq!(t.kinds(), [], "nothing fires");
        assert!(lookup(&before, &path("/a/mine")).is_some(), "the old version is intact");
        // The root cannot go: it loses its owner and keeps its ACL.
        assert_eq!(t.set("/", b"r9\0w9\0b3\0"), None);
        assert_eq!(t.w("/new/x", ""), None);
        forget_domains(&mut t.root, &mut t.gen, &[9], &mut Acct::Store(&mut t.entries));
        // -1, printed as `%u` prints an OCaml int.
        assert_eq!(lookup(&t.root, &path("/")).unwrap().perms.owner, NO_OWNER);
        assert_eq!(t.perms("/"), b"r9223372036854775807\0w9\0b3\0");
        assert!(!t.exists("/new"), "what inherited the root's record goes");
        assert_eq!(t.perms("/a/theirs"), b"n7\0", "an ACL entry elsewhere does not");
        // What is created below it since is the lost owner's, which no
        // domid names, the largest included.
        assert_eq!(t.w("/new/x", ""), None);
        assert_eq!(t.perms("/new/x"), b"r9223372036854775807\0w9\0b3\0");
        assert_eq!(t.entries.get(NO_OWNER), 2);
        forget_domains(&mut t.root, &mut t.gen, &[u32::MAX], &mut Acct::Store(&mut t.entries));
        assert!(t.exists("/new/x"));
        assert_eq!(t.set("/new", b"n4294967295\0"), None);
        assert_eq!(t.perms("/new"), b"n4294967295\0", "another owner");
        assert_eq!((t.entries.get(NO_OWNER), t.entries.get(u32::MAX.into())), (1, 1));
        forget_domains(&mut t.root, &mut t.gen, &[u32::MAX], &mut Acct::Store(&mut t.entries));
        assert!(!t.exists("/new"));
        assert_eq!(t.perms("/"), b"r9223372036854775807\0w9\0b3\0");
    }

    #[test]
    fn a_node_is_56_bytes() {
        // With its name, 80 bytes in its parent's map: the store of a
        // host is hundreds of nodes per VM.
        assert_eq!(core::mem::size_of::<Node>(), 56);
        assert_eq!(core::mem::size_of::<(Name, Node)>(), 80);
    }

    #[test]
    fn initial_store() {
        let mut t = T::new();
        assert_eq!(
            t.ls("/").unwrap(),
            ["@introduceDomain", "@releaseDomain", "local", "tool"]
        );
        assert_eq!(t.read("/tool/xenstored").unwrap(), b"/usr/sbin/rxenstored");
        assert_eq!(t.read("@introduceDomain").unwrap(), b"");
        assert!(t.ls("/local").unwrap().is_empty());
    }

    #[test]
    fn write_creates_parents_with_inherited_perms() {
        let mut t = T::new();
        assert!(matches!(
            t.run(Op::SetPerms(
                path("/local"),
                Arc::new(Perms::parse(b"n0\0r5\0").unwrap())
            )),
            Outcome::Done
        ));
        t.kinds();
        assert!(matches!(t.write("/local/a/b/c", "v"), Outcome::Done));
        assert_eq!(t.read("/local/a/b/c").unwrap(), b"v");
        assert_eq!(t.read("/local/a").unwrap(), b"");
        for p in ["/local/a", "/local/a/b", "/local/a/b/c"] {
            assert_eq!(lookup(&t.root, &path(p)).unwrap().perms.encode(), b"n0\0r5\0");
        }
        // Only the written path is reported, not the implicit parents.
        assert_eq!(t.kinds(), [("/local/a/b/c".into(), ChangeKind::Write)]);
        // Overwrite keeps the node's own permissions.
        t.write("/local/a/b/c", "w");
        assert_eq!(t.read("/local/a/b/c").unwrap(), b"w");
    }

    #[test]
    fn same_value_keeps_the_generation_but_still_fires() {
        let mut t = T::new();
        t.write("/a", "1");
        let g = lookup(&t.root, &path("/a")).unwrap().vgen;
        t.kinds();
        t.write("/a", "1");
        assert_eq!(lookup(&t.root, &path("/a")).unwrap().vgen, g);
        assert_eq!(t.kinds().len(), 1);
    }

    #[test]
    fn value_limit_after_implicit_parents() {
        let mut t = T::new();
        let big = "x".repeat(VALUE_MAX + 1);
        assert!(matches!(t.write("/a/b/c", &big), Outcome::Failed(Errno::E2BIG)));
        assert_eq!(t.ls("/a").unwrap(), ["b"], "parents were created");
        assert_eq!(t.read("/a/b/c"), Err(Errno::ENOENT));
        assert!(t.kinds().is_empty());
        // Nothing to create: the store is not touched, not even copied.
        let version = t.root.clone();
        assert!(matches!(t.write("/a/b", &big), Outcome::Failed(Errno::E2BIG)));
        assert!(matches!(t.write("/", &big), Outcome::Failed(Errno::E2BIG)));
        assert!(Arc::ptr_eq(&version, &t.root));
        assert!(matches!(t.write("/a/b/c", &"x".repeat(VALUE_MAX)), Outcome::Done));
        assert!(matches!(t.write("/", &"x".repeat(VALUE_MAX)), Outcome::Done));
    }

    #[test]
    fn root_value() {
        let mut t = T::new();
        t.write("/", "r");
        assert_eq!(t.read("/").unwrap(), b"r");
        t.write("/", "r");
        assert_eq!(t.kinds().len(), 2);
    }

    #[test]
    fn mkdir() {
        let mut t = T::new();
        assert!(matches!(t.run(Op::Mkdir(path("/a/b"))), Outcome::Done));
        assert_eq!(t.read("/a/b").unwrap(), b"");
        assert_eq!(t.kinds(), [("/a/b".into(), ChangeKind::Mkdir)]);
        t.write("/a/b", "keep");
        t.kinds();
        assert!(matches!(t.run(Op::Mkdir(path("/a/b"))), Outcome::Done));
        assert_eq!(t.read("/a/b").unwrap(), b"keep");
        assert!(t.kinds().is_empty(), "existing node: no change");
        assert!(matches!(t.run(Op::Mkdir(path("/"))), Outcome::Done));
        assert_eq!(t.kinds(), [("/".into(), ChangeKind::Mkdir)]);
    }

    #[test]
    fn rm() {
        let mut t = T::new();
        t.write("/a/b/c", "1");
        t.kinds();
        assert!(
            matches!(t.run(Op::Rm(path("/a/x"))), Outcome::Done),
            "missing node, parent exists"
        );
        assert!(
            matches!(t.run(Op::Rm(path("/a/x/y"))), Outcome::Failed(Errno::ENOENT)),
            "missing parent"
        );
        assert!(t.kinds().is_empty());
        assert!(matches!(t.run(Op::Rm(path("/a/b"))), Outcome::Done));
        assert_eq!(t.ls("/a").unwrap(), Vec::<String>::new());
        let c = t.changes.pop().unwrap();
        assert_eq!(c.kind, ChangeKind::Rm);
        assert!(
            lookup(c.before.as_ref().unwrap(), &path("/a/b/c")).is_some(),
            "old version kept"
        );
        assert!(c.after.is_none());
        t.run(Op::Rm(path("/")));
        assert!(t.ls("/").unwrap().is_empty());
        assert_eq!(t.kinds(), [("/".into(), ChangeKind::Rm)]);
    }

    #[test]
    fn setperms_and_getperms() {
        let mut t = T::new();
        let p = Arc::new(Perms::parse(b"b3\0").unwrap());
        assert!(matches!(
            t.run(Op::SetPerms(path("/nope"), p.clone())),
            Outcome::Failed(Errno::ENOENT)
        ));
        assert!(matches!(
            t.run(Op::GetPerms(path("/nope"))),
            Outcome::Failed(Errno::ENOENT)
        ));
        t.write("/a", "");
        t.kinds();
        t.run(Op::SetPerms(path("/a"), p.clone()));
        match t.run(Op::GetPerms(path("/a"))) {
            Outcome::Perms { perms, .. } => assert_eq!(perms, p),
            o => panic!("{o:?}"),
        }
        let c = t.changes.pop().unwrap();
        assert_eq!(c.kind, ChangeKind::SetPerms);
        assert_eq!(c.roots().count(), 2);
        let g = lookup(&t.root, &path("/a")).unwrap().vgen;
        t.run(Op::SetPerms(path("/a"), Arc::new(Perms::parse(b"b3\0").unwrap())));
        assert_eq!(
            lookup(&t.root, &path("/a")).unwrap().vgen,
            g,
            "equal permissions keep the generation"
        );
        t.run(Op::SetPerms(path("/"), p.clone()));
        assert_eq!(t.root.perms, p);
    }

    #[test]
    fn missing_reads() {
        let mut t = T::new();
        assert_eq!(t.read("/x/y"), Err(Errno::ENOENT));
        assert_eq!(t.ls("/x"), Err(Errno::ENOENT));
    }

    #[test]
    fn versions_are_independent() {
        let mut t = T::new();
        t.write("/a/b", "1");
        let snap = t.root.clone();
        t.write("/a/b", "2");
        t.run(Op::Rm(path("/a")));
        assert_eq!(&*lookup(&snap, &path("/a/b")).unwrap().value, b"1");
        assert!(lookup(&t.root, &path("/a")).is_none());
    }

    #[test]
    fn generations_track_value_and_children() {
        let mut t = T::new();
        t.write("/a", "1");
        let a = lookup(&t.root, &path("/a")).unwrap().clone();
        t.write("/a/b", "1");
        let a2 = lookup(&t.root, &path("/a")).unwrap().clone();
        assert_eq!(a.vgen, a2.vgen);
        assert!(a2.cgen > a.cgen);
        t.write("/a", "2");
        let a3 = lookup(&t.root, &path("/a")).unwrap().clone();
        assert!(a3.vgen > a2.vgen);
        assert_eq!(a3.cgen, a2.cgen);
    }

    #[test]
    fn requests_that_write() {
        assert!(Op::Write(vec![], Bytes::EMPTY).is_write());
        assert!(!Op::Read(vec![]).is_write());
    }

    #[test]
    fn every_request_has_its_path() {
        let perms = Arc::new(Perms::default0());
        for op in [
            Op::Read(path("/a")),
            Op::GetPerms(path("/a")),
            Op::Directory(path("/a")),
            Op::Write(path("/a"), Bytes::EMPTY),
            Op::Mkdir(path("/a")),
            Op::Rm(path("/a")),
            Op::SetPerms(path("/a"), perms),
        ] {
            assert_eq!(op.path(), &path("/a"), "{op:?}");
        }
    }

    #[test]
    fn in_a_transaction_no_version_is_kept() {
        let mut t = T::new();
        t.write("/a/b", "1");
        let mut tree = t.root.clone();
        let mut entries = t.entries.clone();
        let mut run = |tree: &mut Arc<Node>, t: &mut T, op: Op| {
            execute_in(tree, &mut t.gen, &op, &t.ctx, &mut Acct::Store(&mut entries))
        };
        for (op, kind) in [
            (Op::Write(path("/a/b"), Bytes::from(&b"2"[..])), Some(ChangeKind::Write)),
            (Op::Mkdir(path("/a/c")), Some(ChangeKind::Mkdir)),
            (Op::Mkdir(path("/a/c")), None),
            (
                Op::SetPerms(path("/a/c"), Arc::new(Perms::parse(b"n0\0").unwrap())),
                Some(ChangeKind::SetPerms),
            ),
            (Op::Rm(path("/a/c")), Some(ChangeKind::Rm)),
            (Op::Rm(path("/a/c")), None),
            (Op::Read(path("/a/b")), None),
            (Op::Rm(path("/")), Some(ChangeKind::Rm)),
        ] {
            let first = Arc::ptr_eq(&tree, &t.root);
            let at = Arc::as_ptr(&tree);
            let (outcome, fired) = run(&mut tree, &mut t, op.clone());
            assert!(matches!(outcome, Outcome::Done | Outcome::Value { .. }), "{op:?}");
            assert_eq!(fired, kind, "{op:?}");
            // Nothing else holds the transaction's version: once it is
            // its own, each request changes it in place.
            assert_eq!(Arc::strong_count(&tree), 1, "{op:?}");
            assert!(first || Arc::as_ptr(&tree) == at, "{op:?} copied the version");
        }
        assert!(matches!(
            run(&mut tree, &mut t, Op::Read(path("/a/b"))),
            (Outcome::Failed(Errno::ENOENT), None)
        ));
        // Outside a transaction, an RM keeps the store before it.
        t.run(Op::Rm(path("/a")));
        let c = t.changes.pop().unwrap();
        assert!(c.before.is_some() && c.after.is_none());
        assert_eq!(c.path, path("/a"));
    }
}
