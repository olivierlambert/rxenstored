// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The kernel and hypervisor ABIs the real backend speaks, transcribed
//! from their headers, and the pure functions that build every argument
//! and read every reply. Nothing here makes a system call.
//!
//! Sources: the Linux uapi headers `xen/evtchn.h`, `xen/privcmd.h`,
//! `xen/gntdev.h` (identical in Linux 4.19 and in /usr/include for what is
//! used here) and the Xen 4.17 public headers (`RELEASE-4.17.0`, unchanged
//! for these items in `RELEASE-4.17.6`), as seen by an x86_64 dom0: the
//! layouts assume 64-bit pointers and `unsigned long` (`xen_pfn_t`).

use crate::backend::{DomainState, Port};
use std::io;
use std::mem::size_of;

const _: () = assert!(
    size_of::<usize>() == 8 && size_of::<libc::c_ulong>() == 8,
    "layouts transcribed for a 64-bit dom0"
);

/// An ioctl argument, which names its request: the number and the
/// structure cannot be paired wrongly.
pub(super) trait Request {
    const NR: u32;
}

// asm-generic/ioctl.h:44-73: _IOC(dir, type, nr, size) is dir << 30 |
// size << 16 | type << 8 | nr, and _IOC_NONE (line 58) is 0.
const fn ioc_none(ty: u8, nr: u8, size: usize) -> u32 {
    ((size as u32) << 16) | ((ty as u32) << 8) | nr as u32
}

// ---- /dev/xen/evtchn (xen/evtchn.h) ----

/// struct ioctl_evtchn_bind_virq (evtchn.h:43).
#[repr(C)]
pub(super) struct BindVirq {
    pub virq: u32,
}

/// struct ioctl_evtchn_bind_interdomain (evtchn.h:53).
#[repr(C)]
pub(super) struct BindInterdomain {
    pub remote_domain: u32,
    pub remote_port: u32,
}

/// struct ioctl_evtchn_bind_unbound_port (evtchn.h:63).
#[repr(C)]
pub(super) struct BindUnboundPort {
    pub remote_domain: u32,
}

/// struct ioctl_evtchn_unbind (evtchn.h:72).
#[repr(C)]
pub(super) struct Unbind {
    pub port: u32,
}

/// struct ioctl_evtchn_notify (evtchn.h:81).
#[repr(C)]
pub(super) struct Notify {
    pub port: u32,
}

/// evtchn.h:41.
pub(super) const IOCTL_EVTCHN_BIND_VIRQ: u32 = ioc_none(b'E', 0, size_of::<BindVirq>());
/// evtchn.h:51.
pub(super) const IOCTL_EVTCHN_BIND_INTERDOMAIN: u32 = ioc_none(b'E', 1, size_of::<BindInterdomain>());
/// evtchn.h:61.
pub(super) const IOCTL_EVTCHN_BIND_UNBOUND_PORT: u32 = ioc_none(b'E', 2, size_of::<BindUnboundPort>());
/// evtchn.h:70.
pub(super) const IOCTL_EVTCHN_UNBIND: u32 = ioc_none(b'E', 3, size_of::<Unbind>());
/// IOCTL_EVTCHN_RESET takes no argument (evtchn.h:85-87, size 0).
#[repr(C)]
pub(super) struct Reset {}

/// evtchn.h:79.
pub(super) const IOCTL_EVTCHN_NOTIFY: u32 = ioc_none(b'E', 4, size_of::<Notify>());
/// evtchn.h:86.
pub(super) const IOCTL_EVTCHN_RESET: u32 = ioc_none(b'E', 5, size_of::<Reset>());

impl Request for BindVirq {
    const NR: u32 = IOCTL_EVTCHN_BIND_VIRQ;
}
impl Request for BindInterdomain {
    const NR: u32 = IOCTL_EVTCHN_BIND_INTERDOMAIN;
}
impl Request for BindUnboundPort {
    const NR: u32 = IOCTL_EVTCHN_BIND_UNBOUND_PORT;
}
impl Request for Unbind {
    const NR: u32 = IOCTL_EVTCHN_UNBIND;
}
impl Request for Notify {
    const NR: u32 = IOCTL_EVTCHN_NOTIFY;
}
impl Request for Reset {
    const NR: u32 = IOCTL_EVTCHN_RESET;
}

/// Ports as the evtchn device reads and writes them: native `evtchn_port_t`
/// (uint32_t), and only whole ones (Linux drivers/xen/evtchn.c, "Whole
/// number of ports").
pub(super) fn decode_ports(bytes: &[u8], out: &mut Vec<Port>) {
    out.extend(bytes.as_chunks::<4>().0.iter().map(|c| u32::from_ne_bytes(*c)));
}

// ---- /dev/xen/privcmd (xen/privcmd.h) ----

/// struct privcmd_hypercall (privcmd.h:41).
#[repr(C)]
pub(super) struct PrivcmdHypercall {
    pub op: u64,
    pub arg: [u64; 5],
}

/// struct privcmd_mmapbatch_v2 (privcmd.h:73). `arr` is `const xen_pfn_t *`,
/// and xen_pfn_t is `unsigned long` (Xen arch-x86/xen.h:59). The C
/// structure has two bytes of padding after `dom`; here they are a field,
/// so that what the kernel copies in is all written (zero).
#[repr(C)]
pub(super) struct MmapBatchV2 {
    pub num: u32,
    pub dom: u16,
    pub pad: u16,
    pub addr: u64,
    pub arr: *const u64,
    pub err: *mut i32,
}

/// privcmd.h:147.
pub(super) const IOCTL_PRIVCMD_HYPERCALL: u32 = ioc_none(b'P', 0, size_of::<PrivcmdHypercall>());
/// privcmd.h:153.
pub(super) const IOCTL_PRIVCMD_MMAPBATCH_V2: u32 = ioc_none(b'P', 4, size_of::<MmapBatchV2>());

impl Request for PrivcmdHypercall {
    const NR: u32 = IOCTL_PRIVCMD_HYPERCALL;
}
impl Request for MmapBatchV2 {
    const NR: u32 = IOCTL_PRIVCMD_MMAPBATCH_V2;
}

/// The outcome of a one-page IOCTL_PRIVCMD_MMAPBATCH_V2. privcmd.h:139-145:
/// the ioctl fails for an error other than a failed frame, or with ENOENT
/// for a paged-out frame; otherwise the frame's own error is in `err[0]`,
/// as a negative errno.
pub(super) fn mmapbatch_outcome(ioctl: io::Result<()>, err0: i32) -> io::Result<()> {
    ioctl?;
    if err0 != 0 {
        return Err(io::Error::from_raw_os_error(err0.wrapping_neg()));
    }
    Ok(())
}

// ---- /dev/xen/gntdev (xen/gntdev.h) ----

#[cfg(feature = "gnttab")]
pub(super) use gntdev::*;

/// Built with the `gnttab` feature only (see `super`).
#[cfg(feature = "gnttab")]
mod gntdev {
    use super::{ioc_none, Request};
    use std::mem::size_of;

    /// struct ioctl_gntdev_grant_ref (gntdev.h:40).
    #[repr(C)]
    pub(in crate::xen) struct GrantRef {
        pub domid: u32,
        pub ref_: u32,
    }

    /// struct ioctl_gntdev_map_grant_ref (gntdev.h:60), with room for one ref.
    #[repr(C)]
    pub(in crate::xen) struct MapGrantRef {
        pub count: u32,
        pub pad: u32,
        pub index: u64,
        pub refs: [GrantRef; 1],
    }

    /// struct ioctl_gntdev_unmap_grant_ref (gntdev.h:80).
    #[repr(C)]
    pub(in crate::xen) struct UnmapGrantRef {
        pub index: u64,
        pub count: u32,
        pub pad: u32,
    }

    /// gntdev.h:58.
    pub(in crate::xen) const IOCTL_GNTDEV_MAP_GRANT_REF: u32 = ioc_none(b'G', 0, size_of::<MapGrantRef>());
    /// gntdev.h:78.
    pub(in crate::xen) const IOCTL_GNTDEV_UNMAP_GRANT_REF: u32 = ioc_none(b'G', 1, size_of::<UnmapGrantRef>());

    impl Request for MapGrantRef {
        const NR: u32 = IOCTL_GNTDEV_MAP_GRANT_REF;
    }
    impl Request for UnmapGrantRef {
        const NR: u32 = IOCTL_GNTDEV_UNMAP_GRANT_REF;
    }

    /// The grant every toolstack sets up for the xenstore ring (Xen
    /// public/grant_table.h:135).
    pub(in crate::xen) const GNTTAB_RESERVED_XENSTORE: u32 = 1;

    pub(in crate::xen) fn map_grant_arg(domid: u16) -> MapGrantRef {
        MapGrantRef {
            count: 1,
            pad: 0,
            index: 0,
            refs: [GrantRef {
                domid: domid.into(),
                ref_: GNTTAB_RESERVED_XENSTORE,
            }],
        }
    }

    pub(in crate::xen) fn unmap_grant_arg(index: u64) -> UnmapGrantRef {
        UnmapGrantRef {
            index,
            count: 1,
            pad: 0,
        }
    }
}

// ---- Xen public headers, 4.17 ----

/// public/xen.h:167.
pub(super) const VIRQ_DOM_EXC: u32 = 3;
/// public/xen.h:110.
pub(super) const HYPERVISOR_DOMCTL: u64 = 36;
/// public/xen.h:562: ids from here up are not ordinary domains; the
/// daemon never asks Xen about them.
pub(super) const DOMID_FIRST_RESERVED: u32 = 0x7FF0;

/// public/domctl.h:24. Xen refuses any other value with EACCES
/// (xen/common/domctl.c: `op->interface_version !=
/// XEN_DOMCTL_INTERFACE_VERSION`).
pub const XEN_DOMCTL_INTERFACE_VERSION: u32 = 0x15;
/// public/domctl.h:1200.
pub(super) const XEN_DOMCTL_GETDOMAININFO: u32 = 5;
/// public/domctl.h:104-105.
pub(super) const XEN_DOMINF_DYING: u32 = 1 << 0;
/// public/domctl.h:110-111.
pub(super) const XEN_DOMINF_SHUTDOWN: u32 = 1 << 2;
/// public/domctl.h:131-132.
const XEN_DOMINF_SHUTDOWNMASK: u32 = 255;
const XEN_DOMINF_SHUTDOWNSHIFT: u32 = 16;

/// struct xen_domctl (public/domctl.h:1194): cmd at 0 (line 1195),
/// interface_version at 4 (1285), domain (domid_t) at 8 (1286), _pad[3]
/// to 16 (1287), then the union u (1288), whose largest member is
/// pad[128] (1343) and whose alignment is 8 (uint64_aligned_t members).
pub(super) const DOMCTL_SIZE: usize = 16 + 128;
const DOMCTL_CMD: usize = 0;
const DOMCTL_VERSION: usize = 4;
const DOMCTL_DOMAIN: usize = 8;
/// u.getdomaininfo (domctl.h:99): domain (domid_t) at 0 (line 101), pad1
/// (102), flags (uint32_t) at 4 (133).
const DOMCTL_U: usize = 16;
const GETDOMAININFO_DOMAIN: usize = DOMCTL_U;
const GETDOMAININFO_FLAGS: usize = DOMCTL_U + 4;

/// What getdomaininfo says of one domain, the parts rxenstored uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainInfo {
    pub domid: u32,
    /// `XEN_DOMINF_*`.
    pub flags: u32,
}

impl DomainInfo {
    pub fn dying(&self) -> bool {
        self.flags & XEN_DOMINF_DYING != 0
    }

    pub fn shutdown(&self) -> bool {
        self.flags & XEN_DOMINF_SHUTDOWN != 0
    }

    /// The guest-supplied reason (`SHUTDOWN_*`), meaningful when `shutdown`.
    pub fn shutdown_code(&self) -> u32 {
        (self.flags >> XEN_DOMINF_SHUTDOWNSHIFT) & XEN_DOMINF_SHUTDOWNMASK
    }
}

/// Dying wins over shut down: a domain being destroyed may be both.
pub fn domain_state_of(info: Option<DomainInfo>) -> DomainState {
    match info {
        None => DomainState::Dead,
        Some(i) if i.dying() => DomainState::Dead,
        Some(i) if i.shutdown() => DomainState::Shutdown,
        Some(_) => DomainState::Running,
    }
}

/// The domctl argument of XEN_DOMCTL_getdomaininfo for `domid`.
pub(super) fn getdomaininfo_request(domid: u16) -> [u8; DOMCTL_SIZE] {
    let mut b = [0u8; DOMCTL_SIZE];
    b[DOMCTL_CMD..DOMCTL_CMD + 4].copy_from_slice(&XEN_DOMCTL_GETDOMAININFO.to_ne_bytes());
    b[DOMCTL_VERSION..DOMCTL_VERSION + 4].copy_from_slice(&XEN_DOMCTL_INTERFACE_VERSION.to_ne_bytes());
    b[DOMCTL_DOMAIN..DOMCTL_DOMAIN + 2].copy_from_slice(&domid.to_ne_bytes());
    b
}

/// Reads the domctl after a successful call, for the domain asked. Xen
/// 4.17.6 looks the id up exactly and fails with ESRCH when there is no
/// such domain (xen/common/domctl.c, `rcu_lock_domain_by_id`, since
/// "domctl: Modify XEN_DOMCTL_getdomaininfo to fail if domid is not
/// found"); Xen 4.17.0 answered instead for the first domain whose id is
/// at least the one asked (`d->domain_id >= dom`). Another id in the reply
/// therefore also means there is no such domain.
pub(super) fn getdomaininfo_reply(asked: u16, b: &[u8; DOMCTL_SIZE]) -> Option<DomainInfo> {
    let domid = u16::from_ne_bytes([b[GETDOMAININFO_DOMAIN], b[GETDOMAININFO_DOMAIN + 1]]);
    const F: usize = GETDOMAININFO_FLAGS;
    let flags = u32::from_ne_bytes([b[F], b[F + 1], b[F + 2], b[F + 3]]);
    (domid == asked).then_some(DomainInfo {
        domid: domid.into(),
        flags,
    })
}

/// Turns a failed getdomaininfo into its meaning: ESRCH is no such domain
/// (in 4.17.0: none at or above the id asked); EACCES is first of all a hypervisor that does
/// not speak this interface version, which must not pass for a dead
/// domain.
pub(super) fn getdomaininfo_error(e: io::Error) -> io::Result<Option<DomainInfo>> {
    match e.raw_os_error() {
        Some(libc::ESRCH) => Ok(None),
        Some(libc::EACCES) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Xen refused XEN_DOMCTL_getdomaininfo: {e}; rxenstored speaks domctl interface version \
                 {XEN_DOMCTL_INTERFACE_VERSION:#x} (Xen 4.17) and this hypervisor expects another one, \
                 or an XSM policy denies the call"
            ),
        )),
        _ => Err(io::Error::new(
            e.kind(),
            format!("XEN_DOMCTL_getdomaininfo hypercall: {e}"),
        )),
    }
}

/// The domid_t of a domain the daemon may ask about, or None for an id
/// that cannot be an ordinary domain.
pub(super) fn guest_domid(domid: u32) -> Option<u16> {
    if domid < DOMID_FIRST_RESERVED {
        Some(domid as u16)
    } else {
        None
    }
}

// ---- dom0's ring ----

/// /proc/xen/xsd_port holds the port as `%d`, without a newline (Linux
/// drivers/xen/xenfs/xenstored.c, xsd_port_open). Port 0 is never a
/// usable event channel in Xen, so it means the kernel has none.
pub fn parse_xsd_port(text: &str) -> io::Result<Port> {
    let t = text.trim();
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected an event channel port number, found {text:?}"),
        )
    };
    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    match t.parse::<u32>() {
        Ok(0) | Err(_) => Err(bad()),
        Ok(p) => Ok(p),
    }
}

// ---- /dev/xen/xenbus_backend (xen/xenbus_dev.h) ----
//
// The header is internal to Linux 4.19 (include/xen/xenbus_dev.h); Xen
// carries the same definitions in tools/include/xen-sys/Linux/xenbus_dev.h.

/// IOCTL_XENBUS_BACKEND_EVTCHN takes no argument (xenbus_dev.h:38-39,
/// size 0); its result is the port.
#[repr(C)]
pub(super) struct XenbusBackendEvtchn {}

/// xenbus_dev.h:38. Number 1 is IOCTL_XENBUS_BACKEND_SETUP, which hands
/// the store to another domain: never used here.
pub(super) const IOCTL_XENBUS_BACKEND_EVTCHN: u32 = ioc_none(b'B', 0, size_of::<XenbusBackendEvtchn>());

impl Request for XenbusBackendEvtchn {
    const NR: u32 = IOCTL_XENBUS_BACKEND_EVTCHN;
}

/// The port IOCTL_XENBUS_BACKEND_EVTCHN returned. The driver fails with
/// ENODEV rather than return a port that is not positive (Linux 4.19
/// drivers/xen/xenbus/xenbus_dev_backend.c:81-84); 0 is refused anyway,
/// as for `xsd_port`.
pub(super) fn backend_port(rc: libc::c_int) -> io::Result<Port> {
    match Port::try_from(rc) {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected an event channel port number, got {rc}"),
        )),
    }
}

// ---- the ring page (Xen public/io/xs_wire.h) ----

/// struct xenstore_domain_interface (xs_wire.h:105): req[1024] and
/// rsp[1024] (XENSTORE_RING_SIZE, line 102), then uint32_t req_cons,
/// req_prod (108), rsp_cons, rsp_prod (109), server_features (110),
/// connection (111), error (112).
pub(super) const RING_REQ_CONS: usize = 2048;
pub(super) const RING_REQ_PROD: usize = 2052;
pub(super) const RING_RSP_CONS: usize = 2056;
pub(super) const RING_RSP_PROD: usize = 2060;
pub(super) const RING_SERVER_FEATURES: usize = 2064;
pub(super) const RING_CONNECTION: usize = 2068;
pub(super) const RING_ERROR: usize = 2072;
/// sizeof(struct xenstore_domain_interface) in 4.17.
pub(super) const RING_FIELDS_END: usize = 2076;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of};

    // Expected values printed by a C program built against /usr/include/xen
    // (and, identically, Linux 4.19.19 include/uapi/xen) and the Xen
    // RELEASE-4.17.0 public headers with __XEN_TOOLS__.

    #[test]
    fn ioctl_numbers_are_encoded_as_ioc_none() {
        // asm-generic/ioctl.h:69-73 with _IOC_NONE: size, type, nr.
        assert_eq!(ioc_none(b'P', 0, 48), 48 << 16 | 0x50 << 8);
    }

    #[test]
    fn evtchn_ioctls_match_the_uapi_header() {
        // evtchn.h:41, 51, 61, 70, 79, 86.
        assert_eq!(IOCTL_EVTCHN_BIND_VIRQ, 0x44500);
        assert_eq!(IOCTL_EVTCHN_BIND_INTERDOMAIN, 0x84501);
        assert_eq!(IOCTL_EVTCHN_BIND_UNBOUND_PORT, 0x44502);
        assert_eq!(IOCTL_EVTCHN_UNBIND, 0x44503);
        assert_eq!(IOCTL_EVTCHN_NOTIFY, 0x44504);
        assert_eq!(IOCTL_EVTCHN_RESET, 0x4505);
        assert_eq!(size_of::<Reset>(), 0);
        // evtchn.h:43, 53, 63, 72, 81: unsigned int fields.
        assert_eq!(size_of::<BindVirq>(), 4);
        assert_eq!(size_of::<BindInterdomain>(), 8);
        assert_eq!(offset_of!(BindInterdomain, remote_port), 4);
        assert_eq!(size_of::<BindUnboundPort>(), 4);
        assert_eq!(size_of::<Unbind>(), 4);
        assert_eq!(size_of::<Notify>(), 4);
    }

    #[test]
    fn privcmd_ioctls_match_the_uapi_header() {
        // privcmd.h:147, 153.
        assert_eq!(IOCTL_PRIVCMD_HYPERCALL, 0x305000);
        assert_eq!(IOCTL_PRIVCMD_MMAPBATCH_V2, 0x205004);
        // privcmd.h:41: __u64 op; __u64 arg[5].
        assert_eq!(size_of::<PrivcmdHypercall>(), 48);
        assert_eq!(offset_of!(PrivcmdHypercall, arg), 8);
        // privcmd.h:73: unsigned int num; domid_t dom; __u64 addr; pointers.
        assert_eq!(size_of::<MmapBatchV2>(), 32);
        assert_eq!(offset_of!(MmapBatchV2, dom), 4);
        // The C padding, a field here: every byte is written.
        assert_eq!(offset_of!(MmapBatchV2, pad), 6);
        assert_eq!(offset_of!(MmapBatchV2, addr), 8);
        assert_eq!(offset_of!(MmapBatchV2, arr), 16);
        assert_eq!(offset_of!(MmapBatchV2, err), 24);
        // No padding left: the fields fill the size.
        assert_eq!(4 + 2 + 2 + 8 + 8 + 8, size_of::<MmapBatchV2>());
    }

    #[test]
    #[cfg(feature = "gnttab")]
    fn gntdev_ioctls_match_the_uapi_header() {
        // gntdev.h:58, 78.
        assert_eq!(IOCTL_GNTDEV_MAP_GRANT_REF, 0x184700);
        assert_eq!(IOCTL_GNTDEV_UNMAP_GRANT_REF, 0x104701);
        // gntdev.h:40, 60, 80.
        assert_eq!(size_of::<GrantRef>(), 8);
        assert_eq!(size_of::<MapGrantRef>(), 24);
        assert_eq!(offset_of!(MapGrantRef, index), 8);
        assert_eq!(offset_of!(MapGrantRef, refs), 16);
        assert_eq!(size_of::<UnmapGrantRef>(), 16);
        assert_eq!(offset_of!(UnmapGrantRef, count), 8);
    }

    #[test]
    #[cfg(feature = "gnttab")]
    fn grant_arguments_name_the_xenstore_grant() {
        assert_eq!(GNTTAB_RESERVED_XENSTORE, 1); // grant_table.h:135
        let m = map_grant_arg(7);
        assert_eq!(
            (m.count, m.pad, m.index, m.refs[0].domid, m.refs[0].ref_),
            (1, 0, 0, 7, 1)
        );
        let u = unmap_grant_arg(0x1234_5000);
        assert_eq!((u.index, u.count, u.pad), (0x1234_5000, 1, 0));
    }

    #[test]
    fn xen_constants_match_the_4_17_headers() {
        assert_eq!(XEN_DOMCTL_INTERFACE_VERSION, 0x15); // domctl.h:24
        assert_eq!(XEN_DOMCTL_GETDOMAININFO, 5); // domctl.h:1200
        assert_eq!(HYPERVISOR_DOMCTL, 36); // xen.h:110
        assert_eq!(VIRQ_DOM_EXC, 3); // xen.h:167
        assert_eq!(DOMID_FIRST_RESERVED, 0x7FF0); // xen.h:562
        assert_eq!((XEN_DOMINF_DYING, XEN_DOMINF_SHUTDOWN), (1, 4)); // domctl.h:104-111

        // sizeof(struct xen_domctl) is 144; u is at 16; u.getdomaininfo
        // .domain at 16 and .flags at 20.
        assert_eq!(DOMCTL_SIZE, 144);
        assert_eq!((GETDOMAININFO_DOMAIN, GETDOMAININFO_FLAGS), (16, 20));
        // The reply is read from a page-aligned buffer: every field is
        // naturally aligned at these offsets.
        assert_eq!(GETDOMAININFO_FLAGS % align_of::<u32>(), 0);
    }

    #[test]
    fn the_getdomaininfo_request_layout() {
        let b = getdomaininfo_request(0x1234);
        let mut want = [0u8; 144];
        // domctl.h:1195 cmd = XEN_DOMCTL_getdomaininfo (5), little-endian.
        want[0] = 5;
        // domctl.h:1285 interface_version = 0x15.
        want[4] = 0x15;
        // domctl.h:1286 domain (domid_t).
        want[8] = 0x34;
        want[9] = 0x12;
        assert_eq!(b, want);
    }

    fn reply(domain: u16, flags: u32) -> [u8; DOMCTL_SIZE] {
        let mut b = getdomaininfo_request(0);
        b[8..10].copy_from_slice(&domain.to_le_bytes());
        // domctl.h:101 u.getdomaininfo.domain, 133 u.getdomaininfo.flags.
        b[16..18].copy_from_slice(&domain.to_le_bytes());
        b[20..24].copy_from_slice(&flags.to_le_bytes());
        // Fields a decoder must not read as the flags: tot_pages (line 134).
        b[24..32].fill(0xff);
        b
    }

    #[test]
    fn the_getdomaininfo_reply_is_read_at_the_header_offsets() {
        let i = getdomaininfo_reply(0x0102, &reply(0x0102, 0x0003_0024)).unwrap();
        assert_eq!(
            i,
            DomainInfo {
                domid: 0x0102,
                flags: 0x0003_0024
            }
        );
        assert!(i.shutdown() && !i.dying());
        assert_eq!(i.shutdown_code(), 3);
        // Each of the four bytes of the flags from its place.
        assert_eq!(
            getdomaininfo_reply(1, &reply(1, 0xa1b2_c3d4)).unwrap().flags,
            0xa1b2_c3d4
        );
        // The next domain up answered: the one asked does not exist.
        assert_eq!(getdomaininfo_reply(5, &reply(6, 0)), None);
    }

    #[test]
    fn flags_map_to_states() {
        let s = |flags| domain_state_of(Some(DomainInfo { domid: 1, flags }));
        assert_eq!(domain_state_of(None), DomainState::Dead);
        assert_eq!(s(0), DomainState::Running);
        // running (1 << 5), blocked (1 << 4), paused (1 << 3), hvm (1 << 1)
        // are all still running for xenstore.
        assert_eq!(s(1 << 5 | 1 << 4 | 1 << 3 | 1 << 1), DomainState::Running);
        assert_eq!(s(XEN_DOMINF_SHUTDOWN | 2 << 16), DomainState::Shutdown);
        assert_eq!(s(XEN_DOMINF_DYING), DomainState::Dead);
        assert_eq!(s(XEN_DOMINF_DYING | XEN_DOMINF_SHUTDOWN), DomainState::Dead);
    }

    #[test]
    fn getdomaininfo_errors() {
        let e = |n| getdomaininfo_error(io::Error::from_raw_os_error(n));
        assert_eq!(e(libc::ESRCH).unwrap(), None);
        let acc = e(libc::EACCES).unwrap_err();
        assert_eq!(acc.kind(), io::ErrorKind::PermissionDenied);
        let msg = acc.to_string();
        assert!(
            msg.contains("interface version 0x15") && msg.contains("os error 13"),
            "{msg}"
        );
        let other = e(libc::ENOTTY).unwrap_err();
        assert!(
            other.to_string().starts_with("XEN_DOMCTL_getdomaininfo hypercall: "),
            "{other}"
        );
        assert!(other.to_string().contains("os error 25"), "{other}");
    }

    #[test]
    fn guest_domids() {
        assert_eq!(guest_domid(0), Some(0));
        assert_eq!(guest_domid(0x7FEF), Some(0x7FEF));
        assert_eq!(guest_domid(0x7FF0), None); // DOMID_SELF
        assert_eq!(guest_domid(0x1_0005), None);
    }

    #[test]
    fn mmapbatch_outcomes() {
        assert!(mmapbatch_outcome(Ok(()), 0).is_ok());
        let e = mmapbatch_outcome(Ok(()), -libc::EINVAL).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        let e = mmapbatch_outcome(Err(io::Error::from_raw_os_error(libc::ENOENT)), 0).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn ports_are_native_u32() {
        let mut out = vec![9];
        let mut bytes = Vec::new();
        for p in [1u32, 0x0102_0304, 4095] {
            bytes.extend_from_slice(&p.to_ne_bytes());
        }
        decode_ports(&bytes, &mut out);
        assert_eq!(out, [9, 1, 0x0102_0304, 4095]);
    }

    #[test]
    fn xsd_port_contents() {
        assert_eq!(parse_xsd_port("7").unwrap(), 7);
        assert_eq!(parse_xsd_port(" 4294967295\n").unwrap(), u32::MAX);
        for bad in ["", "\n", "0", "-1", "+3", "0x10", "12a", "4294967296", "1 2"] {
            let e = parse_xsd_port(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad:?}");
            assert!(e.to_string().contains(&format!("{bad:?}")), "{e}");
        }
    }

    #[test]
    fn the_xenbus_backend_ioctl_matches_the_header() {
        // xenbus_dev.h:38-39: _IOC(_IOC_NONE, 'B', 0, 0).
        assert_eq!(IOCTL_XENBUS_BACKEND_EVTCHN, 0x4200);
        assert_eq!(size_of::<XenbusBackendEvtchn>(), 0);
        assert_eq!(backend_port(29).unwrap(), 29);
        assert_eq!(backend_port(libc::c_int::MAX).unwrap(), 0x7fff_ffff);
        for bad in [0, -1, libc::c_int::MIN] {
            let e = backend_port(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(e.to_string().ends_with(&format!("got {bad}")), "{e}");
        }
    }

    #[test]
    fn ring_offsets_match_xs_wire() {
        // xs_wire.h:102 XENSTORE_RING_SIZE 1024; lines 108-112.
        assert_eq!(
            [
                RING_REQ_CONS,
                RING_REQ_PROD,
                RING_RSP_CONS,
                RING_RSP_PROD,
                RING_SERVER_FEATURES,
                RING_CONNECTION,
                RING_ERROR
            ],
            [2048, 2052, 2056, 2060, 2064, 2068, 2072]
        );
        assert_eq!(RING_FIELDS_END, 2076);
    }
}
