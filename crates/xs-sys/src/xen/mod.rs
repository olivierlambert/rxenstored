// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The real `XenBackend`: evtchn, privcmd, gntdev and the domain information hypercall.
//!
//! Grant mapping (gntdev) is built only with the `gnttab` feature, off by
//! default: the daemon maps rings by gfn, as oxenstored does on XCP-ng 8.3,
//! and the grant path has never run on a host (`examples/xen_probe.rs`
//! reaches it).
//!
//! Every argument and reply is built and read by the pure functions of
//! `abi`; what is left here issues the system calls. The parts that only
//! succeed on a dom0 are excluded from coverage (docs/coverage-exclusions.md).

mod abi;

pub use abi::{domain_state_of, parse_xsd_port, DomainInfo, XEN_DOMCTL_INTERFACE_VERSION};

use crate::backend::{DeviceNotUsed, Dom0Ring, Dom0Source, DomainState, Pending, Port, XenBackend};
use crate::map::{mmap_result, Mapping, PAGE_SIZE};
use std::fmt;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(feature = "gnttab")]
use std::sync::Arc;

/// How guest rings are mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RingMapping {
    /// The gfn of INTRODUCE through privcmd, as oxenstored does on 8.3.
    #[default]
    Foreign,
    /// Grant `GNTTAB_RESERVED_XENSTORE` through gntdev, as cxenstored
    /// does; the gfn is ignored.
    #[cfg(feature = "gnttab")]
    Grant,
}

/// Where the devices are. The defaults are those of a Linux dom0 and of
/// oxenstored.conf on XCP-ng 8.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XenOptions {
    pub evtchn: PathBuf,
    pub privcmd: PathBuf,
    /// Tried when `privcmd` does not exist, as libxencall does.
    pub privcmd_fallback: PathBuf,
    /// The hypercall buffer device (Linux 4.18 and later); when it does
    /// not exist, buffers are locked anonymous memory, as libxencall does.
    pub hypercall: PathBuf,
    /// Opened in `RingMapping::Grant` mode only.
    #[cfg(feature = "gnttab")]
    pub gntdev: PathBuf,
    /// Dom0's ring page and port are taken from here first; if it cannot
    /// be used, from `xsd_kva` and `xsd_port`. None: from those only.
    pub xenbus_backend: Option<PathBuf>,
    pub xsd_kva: PathBuf,
    pub xsd_port: PathBuf,
    pub ring_mapping: RingMapping,
}

impl Default for XenOptions {
    fn default() -> XenOptions {
        XenOptions {
            evtchn: "/dev/xen/evtchn".into(),
            privcmd: "/dev/xen/privcmd".into(),
            privcmd_fallback: "/proc/xen/privcmd".into(),
            hypercall: "/dev/xen/hypercall".into(),
            #[cfg(feature = "gnttab")]
            gntdev: "/dev/xen/gntdev".into(),
            xenbus_backend: Some("/dev/xen/xenbus_backend".into()),
            xsd_kva: "/proc/xen/xsd_kva".into(),
            xsd_port: "/proc/xen/xsd_port".into(),
            ring_mapping: RingMapping::Foreign,
        }
    }
}

impl XenOptions {
    /// Dom0's ring files as the configuration names them
    /// (`xenstored-kva`, `xenstored-port`). Paths other than the defaults
    /// are used as given and the xenbus backend device is not tried; the
    /// defaults, which XCP-ng's oxenstored.conf sets explicitly, are the
    /// device's fallback.
    pub fn with_dom0_files(self, kva: PathBuf, port: PathBuf) -> XenOptions {
        let d = XenOptions::default();
        let stock = kva == d.xsd_kva && port == d.xsd_port;
        XenOptions {
            xenbus_backend: self.xenbus_backend.filter(|_| stock),
            xsd_kva: kva,
            xsd_port: port,
            ..self
        }
    }
}

pub struct RealXen {
    evtchn: OwnedFd,
    privcmd: OwnedFd,
    rings: Rings,
    /// The one page every hypercall argument lives in: Xen reads and
    /// writes it while the hypercall runs, so it must never fault
    /// (tools/libs/call/linux.c).
    hcall: Mapping,
    /// For `Debug`: which privcmd opened, and where the hypercall page
    /// comes from (None: locked memory).
    privcmd_path: PathBuf,
    hcall_path: Option<PathBuf>,
    xenbus_backend: Option<PathBuf>,
    xsd_kva: PathBuf,
    xsd_port: PathBuf,
}

enum Rings {
    Foreign,
    /// The gntdev descriptor, shared with the mappings that must release
    /// their grant through it.
    #[cfg(feature = "gnttab")]
    Grant(Arc<OwnedFd>),
}

impl fmt::Debug for RealXen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hcall = self
            .hcall_path
            .as_ref()
            .map_or("locked memory".into(), |p| p.display().to_string());
        f.debug_struct("RealXen")
            .field("ring_mapping", &self.ring_mapping())
            .field("privcmd", &self.privcmd_path)
            .field("hypercall_buffer", &hcall)
            .field("xenbus_backend", &self.xenbus_backend)
            .finish_non_exhaustive()
    }
}

fn ctx(e: io::Error, what: fmt::Arguments<'_>) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Opens a Xen device read-write and close-on-exec (the standard library
/// always adds O_CLOEXEC), refusing anything but a character device so
/// that a wrong path fails here rather than at the first ioctl. Errors
/// keep their errno and do not name the path.
fn open_raw(path: &Path, nonblocking: bool) -> io::Result<OwnedFd> {
    let flags = if nonblocking { libc::O_NONBLOCK } else { 0 };
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(flags)
        .open(path)?;
    if !f.metadata()?.file_type().is_char_device() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a character device"));
    }
    Ok(f.into())
}

fn open_device(path: &Path, nonblocking: bool) -> io::Result<OwnedFd> {
    open_raw(path, nonblocking).map_err(|e| ctx(e, format_args!("{}", path.display())))
}

fn missing(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENXIO | libc::ENODEV))
}

/// The ioctl that `arg` is the argument of; its non-negative result on
/// success.
///
/// # Safety
/// Every pointer in `arg` is valid for what the kernel does through it.
unsafe fn ioctl<T: abi::Request>(fd: &impl AsRawFd, arg: &mut T) -> io::Result<libc::c_int> {
    // SAFETY: `T::NR` encodes the size of the `#[repr(C)]` structure `T`
    // (checked by the abi tests), `arg` is valid and writable for it, and
    // the caller vouches for the pointers it holds.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), T::NR as _, arg as *mut T) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// The hypercall page, as libxencall allocates it: from the buffer device
/// if there is one, else anonymous memory locked in, not inherited by a
/// child (a copy-on-write fault during a hypercall would fail it), and
/// touched so that it is already populated. Says which it is.
fn hypercall_page(bufdev: &Path) -> io::Result<(Mapping, Option<PathBuf>)> {
    match open_raw(bufdev, false) {
        Ok(fd) => {
            // SAFETY: the buffer device allocates the page at mmap, and it
            // lives with the mapping.
            let m = unsafe { Mapping::of_fd(&fd, 0, PAGE_SIZE) }
                .map_err(|e| ctx(e, format_args!("mmap of {}", bufdev.display())))?;
            return Ok((m, Some(bufdev.to_owned())));
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(ctx(e, format_args!("{}", bufdev.display()))),
    }
    // SAFETY: a new private mapping at an address the kernel chooses.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_LOCKED,
            -1,
            0,
        )
    };
    let ptr = mmap_result(p).map_err(|e| ctx(e, format_args!("locked hypercall buffer")))?;
    // SAFETY: `ptr` is the live, page-sized mapping just made, owned by
    // nothing else.
    let m = unsafe { Mapping::from_raw(ptr, PAGE_SIZE, None) };
    // SAFETY: plain call on the mapping owned by `m`.
    if unsafe { libc::madvise(p, PAGE_SIZE, libc::MADV_DONTFORK) } < 0 {
        return Err(ctx(
            io::Error::last_os_error(),
            format_args!("madvise of the hypercall buffer"),
        ));
    }
    // SAFETY: inside the mapping, which nothing else uses yet.
    unsafe { m.as_ptr().write_volatile(0) };
    Ok((m, None))
}

/// Releases a gntdev grant once its pages are unmapped. Nothing can be
/// done about a failure at that point, and the grant is released anyway
/// when the device is closed.
#[cfg(feature = "gnttab")]
fn grant_release(gntdev: Arc<OwnedFd>, index: u64) -> crate::map::AfterUnmap {
    Box::new(move || {
        // SAFETY: no pointers in the argument.
        let _ = unsafe { ioctl(&*gntdev, &mut abi::unmap_grant_arg(index)) };
    })
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid and writable for its length.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Reads ports with `read` (of an evtchn descriptor) until it would block.
///
/// EFBIG is the overflow of the device's buffer (Linux 4.19
/// drivers/xen/evtchn.c): a port that fires when the buffer is full is
/// dropped and sets `ring_overflow` (lines 177-187), after which every
/// read fails with EFBIG (213-215) and poll says EPOLLERR (640-641) until
/// IOCTL_EVTCHN_RESET (589-599). The reset only empties the buffer and
/// clears the flag: bindings stay, and so does each port's `enabled`,
/// which the interrupt cleared (170) and only a write sets again
/// (297-299). A port whose entry was dropped, or emptied by the reset, is
/// therefore masked until it is unmasked, and nothing else says so:
/// `Lost` tells the caller to unmask every port after looking at what
/// each one serves. (The buffer has room for an entry per bound port,
/// 318-322: it overflows only on stale entries, of ports unbound, or
/// unmasked, before their entry was read.)
fn drain(
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
    reset: impl FnOnce() -> io::Result<()>,
    out: &mut Vec<Port>,
) -> io::Result<Pending> {
    // The driver returns at most a page of ports per read.
    let mut buf = [0u8; PAGE_SIZE];
    loop {
        match read(&mut buf) {
            Ok(0) => return Ok(Pending::Complete),
            Ok(n) => match buf.get(..n) {
                Some(ports) => abi::decode_ports(ports, out),
                None => {
                    return Err(io::Error::other(format!(
                        "read of pending event channels: {n} bytes into a buffer of {PAGE_SIZE}"
                    )))
                }
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Pending::Complete),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.raw_os_error() == Some(libc::EFBIG) => return reset().map(|()| Pending::Lost),
            Err(e) => return Err(ctx(e, format_args!("read of pending event channels"))),
        }
    }
}

/// Re-enables a port: the evtchn device takes writes of whole ports.
fn write_port(fd: RawFd, port: Port) -> io::Result<()> {
    let b = port.to_ne_bytes();
    // SAFETY: `b` is valid for its length.
    if unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) } < 0 {
        return Err(ctx(
            io::Error::last_os_error(),
            format_args!("unmask of event channel {port}"),
        ));
    }
    Ok(())
}

/// Dom0's ring from the xenbus backend device: the port by ioctl, the
/// page by mmap. The descriptor is closed on return; the mapping holds
/// its own reference to the file.
fn dom0_ring_of_device(path: &Path) -> Result<(Mapping, Port), DeviceNotUsed> {
    let not_used = |error, missing| DeviceNotUsed {
        path: path.to_owned(),
        missing,
        error,
    };
    let fd = open_raw(path, false).map_err(|e| {
        let m = missing(&e);
        not_used(e, m)
    })?;
    // SAFETY: the argument is empty; the driver does not read it.
    let port = unsafe { ioctl(&fd, &mut abi::XenbusBackendEvtchn {}) }
        .and_then(abi::backend_port)
        .map_err(|e| not_used(ctx(e, format_args!("IOCTL_XENBUS_BACKEND_EVTCHN")), false))?;
    // cov:excl-start xen-backend-port
    // SAFETY: the driver maps the kernel's xenstore page, allocated at
    // boot and never freed, and accepts one page at offset 0 (Linux 4.19
    // xenbus_dev_backend.c:92-108); the page is mapped at mmap, not on
    // fault.
    let page =
        unsafe { Mapping::of_fd(&fd, 0, PAGE_SIZE) }.map_err(|e| not_used(ctx(e, format_args!("mmap")), false))?;
    Ok((page, port))
    // cov:excl-stop xen-backend-port
}

/// Dom0's ring from xenfs's files, or files configured in their place.
fn dom0_ring_of_files(kva: &Path, port: &Path) -> io::Result<(Mapping, Port)> {
    let text = std::fs::read_to_string(port).map_err(|e| ctx(e, format_args!("{}", port.display())))?;
    let p = parse_xsd_port(&text).map_err(|e| ctx(e, format_args!("{}", port.display())))?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(kva)
        .map_err(|e| ctx(e, format_args!("{}", kva.display())))?;
    // SAFETY: `xsd_kva` is the kernel's file of dom0's xenstore page,
    // which lives as long as the kernel (or the file root's
    // configuration names in its place, which root must not truncate).
    let m =
        unsafe { Mapping::of_fd(&f, 0, PAGE_SIZE) }.map_err(|e| ctx(e, format_args!("mmap of {}", kva.display())))?;
    Ok((m, p))
}

/// Dom0's ring from `device` if given and usable, else from the files.
/// Any failure of the device falls back: both give the same page and
/// port. If the files fail too, the error names both.
fn dom0_ring_from(
    device: Option<&Path>,
    by_device: impl FnOnce(&Path) -> Result<(Mapping, Port), DeviceNotUsed>,
    kva: &Path,
    port: &Path,
) -> io::Result<Dom0Ring> {
    let tried = match device.map(|d| (d, by_device(d))) {
        Some((d, Ok((page, port)))) => {
            return Ok(Dom0Ring {
                page,
                port,
                source: Dom0Source::Device(d.to_owned()),
            })
        }
        Some((_, Err(e))) => Some(e),
        None => None,
    };
    let (page, p) = dom0_ring_of_files(kva, port).map_err(|f| match &tried {
        Some(d) => io::Error::new(f.kind(), format!("{d}, and {f}")),
        None => f,
    })?;
    Ok(Dom0Ring {
        page,
        port: p,
        source: Dom0Source::Files {
            kva: kva.to_owned(),
            port: port.to_owned(),
            device: tried,
        },
    })
}

fn not_a_guest(domid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("domain {domid} is not an ordinary domain id"),
    )
}

impl RealXen {
    pub fn open(o: &XenOptions) -> io::Result<RealXen> {
        let evtchn = open_device(&o.evtchn, true)?;
        let (privcmd, privcmd_path) = match open_raw(&o.privcmd, false) {
            Err(e) if missing(&e) => (
                open_device(&o.privcmd_fallback, false)
                    .map_err(|f| io::Error::new(f.kind(), format!("{}: {e}, and {f}", o.privcmd.display())))?,
                o.privcmd_fallback.clone(),
            ),
            r => (
                r.map_err(|e| ctx(e, format_args!("{}", o.privcmd.display())))?,
                o.privcmd.clone(),
            ),
        };
        let rings = match o.ring_mapping {
            #[cfg(feature = "gnttab")]
            RingMapping::Grant => Rings::Grant(Arc::new(open_device(&o.gntdev, false)?)),
            RingMapping::Foreign => Rings::Foreign,
        };
        let (hcall, hcall_path) = hypercall_page(&o.hypercall)?;
        Ok(RealXen {
            evtchn,
            privcmd,
            rings,
            hcall,
            privcmd_path,
            hcall_path,
            xenbus_backend: o.xenbus_backend.clone(),
            xsd_kva: o.xsd_kva.clone(),
            xsd_port: o.xsd_port.clone(),
        })
    }

    pub fn ring_mapping(&self) -> RingMapping {
        match self.rings {
            Rings::Foreign => RingMapping::Foreign,
            #[cfg(feature = "gnttab")]
            Rings::Grant(_) => RingMapping::Grant,
        }
    }

    /// Allocates a fresh local port that `remote_domid` may bind to
    /// (`IOCTL_EVTCHN_BIND_UNBOUND_PORT`).
    pub fn bind_unbound_port(&mut self, remote_domid: u32) -> io::Result<Port> {
        let mut a = abi::BindUnboundPort {
            remote_domain: remote_domid,
        };
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&self.evtchn, &mut a) }
            .map(|rc| rc as Port)
            .map_err(|e| {
                ctx(
                    e,
                    format_args!("IOCTL_EVTCHN_BIND_UNBOUND_PORT for domain {remote_domid}"),
                )
            })
    }

    /// Empties the evtchn device's buffer and clears its overflow
    /// (`IOCTL_EVTCHN_RESET`; see `drain`).
    fn reset(&self) -> io::Result<()> {
        // SAFETY: the argument is empty; the driver does not read it.
        unsafe { ioctl(&self.evtchn, &mut abi::Reset {}) }
            .map(drop)
            .map_err(|e| ctx(e, format_args!("IOCTL_EVTCHN_RESET after an overflow")))
    }

    /// What `XEN_DOMCTL_getdomaininfo` says of `domid`: None if there is no
    /// such domain.
    pub fn domain_info(&mut self, domid: u32) -> io::Result<Option<DomainInfo>> {
        let Some(dom) = abi::guest_domid(domid) else {
            return Ok(None);
        };
        let req = abi::getdomaininfo_request(dom);
        let buf = self.hcall.as_ptr();
        // SAFETY: the page is PAGE_SIZE bytes, larger than the request, and
        // only this value (borrowed mutably) uses it.
        unsafe { std::ptr::copy_nonoverlapping(req.as_ptr(), buf, req.len()) };
        let mut call = abi::PrivcmdHypercall {
            op: abi::HYPERVISOR_DOMCTL,
            arg: [buf as u64, 0, 0, 0, 0],
        };
        // SAFETY: the domctl argument is in the hypercall page, which stays
        // mapped and is not touched by anything else during the call.
        match unsafe { ioctl(&self.privcmd, &mut call) } {
            Err(e) => abi::getdomaininfo_error(e),
            // cov:excl-start xen-domctl-reply
            Ok(_) => {
                let mut reply = [0u8; abi::DOMCTL_SIZE];
                // SAFETY: as above; the hypercall has returned, so Xen is
                // done with the page.
                unsafe { std::ptr::copy_nonoverlapping(buf, reply.as_mut_ptr(), reply.len()) };
                Ok(abi::getdomaininfo_reply(dom, &reply))
            } // cov:excl-stop xen-domctl-reply
        }
    }

    fn map_foreign(&mut self, domid: u32, gfn: u64) -> io::Result<Mapping> {
        let dom = abi::guest_domid(domid).ok_or_else(|| not_a_guest(domid))?;
        let what = || format!("foreign mapping of gfn {gfn:#x} of domain {domid}");
        // A privcmd mapping is empty until the batch fills it; dropping it
        // on failure unmaps it.
        // SAFETY: a privcmd page faults until the batch below populates
        // it; the mapping is only handed over once the batch has.
        let m =
            unsafe { Mapping::of_fd(&self.privcmd, 0, PAGE_SIZE) }.map_err(|e| ctx(e, format_args!("{}", what())))?;
        let arr = [gfn];
        let mut err = [0i32];
        let mut a = abi::MmapBatchV2 {
            num: 1,
            dom,
            pad: 0,
            addr: m.as_ptr() as u64,
            arr: arr.as_ptr(),
            err: err.as_mut_ptr(),
        };
        // SAFETY: `addr` is the privcmd mapping `m` of one page, `arr` and
        // `err` are arrays of one element; all three outlive the call.
        let r = unsafe { ioctl(&self.privcmd, &mut a) }.map(drop);
        abi::mmapbatch_outcome(r, err[0]).map_err(|e| ctx(e, format_args!("{}", what())))?;
        Ok(m) // cov:excl-line xen-foreign-mapped
    }

    #[cfg(feature = "gnttab")]
    fn map_grant(gntdev: &Arc<OwnedFd>, domid: u32) -> io::Result<Mapping> {
        let dom = abi::guest_domid(domid).ok_or_else(|| not_a_guest(domid))?;
        let what = || format!("grant mapping of the xenstore grant of domain {domid}");
        let mut a = abi::map_grant_arg(dom);
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&**gntdev, &mut a) }.map_err(|e| ctx(e, format_args!("{}", what())))?;
        // cov:excl-start xen-grant-mapped
        let index = a.index;
        // SAFETY: gntdev keeps the granted page mapped at `index` until the
        // unmap ioctl, which runs only after the munmap (`grant_release`).
        let m = match unsafe { Mapping::of_fd(&**gntdev, index, PAGE_SIZE) } {
            Ok(m) => m,
            Err(e) => {
                // SAFETY: no pointers in the argument.
                let _ = unsafe { ioctl(&**gntdev, &mut abi::unmap_grant_arg(index)) };
                return Err(ctx(e, format_args!("{}", what())));
            }
        };
        // gntdev requires the munmap before the unmap ioctl (gntdev.h:73-76),
        // which is the order `Mapping` runs them in.
        Ok(m.with_after_unmap(grant_release(gntdev.clone(), index)))
        // cov:excl-stop xen-grant-mapped
    }
}

impl XenBackend for RealXen {
    fn event_fd(&self) -> RawFd {
        self.evtchn.as_raw_fd()
    }

    fn pending(&mut self, out: &mut Vec<Port>) -> io::Result<Pending> {
        let fd = self.evtchn.as_raw_fd();
        drain(|buf| read_fd(fd, buf), || self.reset(), out)
    }

    fn unmask(&mut self, local: Port) -> io::Result<()> {
        write_port(self.evtchn.as_raw_fd(), local)
    }

    fn bind_dom_exc(&mut self) -> io::Result<Port> {
        let mut a = abi::BindVirq {
            virq: abi::VIRQ_DOM_EXC,
        };
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&self.evtchn, &mut a) }
            .map(|rc| rc as Port)
            .map_err(|e| ctx(e, format_args!("IOCTL_EVTCHN_BIND_VIRQ VIRQ_DOM_EXC")))
    }

    fn bind_interdomain(&mut self, domid: u32, remote: Port) -> io::Result<Port> {
        let mut a = abi::BindInterdomain {
            remote_domain: domid,
            remote_port: remote,
        };
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&self.evtchn, &mut a) }
            .map(|rc| rc as Port)
            .map_err(|e| {
                ctx(
                    e,
                    format_args!("IOCTL_EVTCHN_BIND_INTERDOMAIN to port {remote} of domain {domid}"),
                )
            })
    }

    fn unbind(&mut self, local: Port) -> io::Result<()> {
        let mut a = abi::Unbind { port: local };
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&self.evtchn, &mut a) }
            .map(drop)
            .map_err(|e| ctx(e, format_args!("IOCTL_EVTCHN_UNBIND of port {local}")))
    }

    fn notify(&mut self, local: Port) -> io::Result<()> {
        let mut a = abi::Notify { port: local };
        // SAFETY: no pointers in the argument.
        unsafe { ioctl(&self.evtchn, &mut a) }
            .map(drop)
            .map_err(|e| ctx(e, format_args!("IOCTL_EVTCHN_NOTIFY of port {local}")))
    }

    fn dom0_ring(&mut self) -> io::Result<Dom0Ring> {
        dom0_ring_from(
            self.xenbus_backend.as_deref(),
            dom0_ring_of_device,
            &self.xsd_kva,
            &self.xsd_port,
        )
    }

    fn map_ring(&mut self, domid: u32, gfn: u64) -> io::Result<Mapping> {
        match &self.rings {
            Rings::Foreign => self.map_foreign(domid, gfn),
            #[cfg(feature = "gnttab")]
            Rings::Grant(gntdev) => RealXen::map_grant(gntdev, domid),
        }
    }

    fn domain_state(&mut self, domid: u32) -> io::Result<DomainState> {
        self.domain_info(domid).map(domain_state_of)
    }
}

/// The control fields of a xenstore ring page, as read once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingFields {
    pub req_cons: u32,
    pub req_prod: u32,
    pub rsp_cons: u32,
    pub rsp_prod: u32,
    pub server_features: u32,
    pub connection: u32,
    pub error: u32,
}

/// Reads the control fields of a ring page without writing anything, for
/// diagnostics: each is read once, and the peer may change them at any
/// time, so they need not agree with each other. None if the mapping is
/// too small to be a ring page.
pub fn ring_fields(m: &Mapping) -> Option<RingFields> {
    if m.len() < abi::RING_FIELDS_END {
        return None;
    }
    let at = |off: usize| {
        // SAFETY: `off + 4 <= RING_FIELDS_END <= len`, so the word is inside
        // the mapping, which outlives the call; the mapping is page-aligned
        // and `off` a multiple of 4, so it is aligned. The peer may write
        // the word at any time: an atomic load is no data race (a volatile
        // one would be, `ring.rs`), and every access to these words is a
        // 4-byte atomic one (`ring::Page::word`).
        unsafe { std::sync::atomic::AtomicU32::from_ptr(m.as_ptr().add(off).cast()) }
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    Some(RingFields {
        req_cons: at(abi::RING_REQ_CONS),
        req_prod: at(abi::RING_REQ_PROD),
        rsp_cons: at(abi::RING_RSP_CONS),
        rsp_prod: at(abi::RING_RSP_PROD),
        server_features: at(abi::RING_SERVER_FEATURES),
        connection: at(abi::RING_CONNECTION),
        error: at(abi::RING_ERROR),
    })
}

#[cfg(test)]
mod tests;
