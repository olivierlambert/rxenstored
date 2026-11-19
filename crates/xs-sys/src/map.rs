// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! A region of shared memory mapped in this process, unmapped on drop.

use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;

/// Size of a Xen page, and of a xenstore ring page.
pub const PAGE_SIZE: usize = 4096;

/// What a device needs done once its mapping is gone (gntdev: release the
/// grant).
pub type AfterUnmap = Box<dyn FnOnce() + Send>;

/// An owned `MAP_SHARED`, read-write mapping. The memory is shared with
/// another party (a guest, a test thread): nothing here reads or writes
/// it, and users must not create references to it.
pub struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
    after_unmap: Option<AfterUnmap>,
}

// SAFETY: the mapping is plain memory owned by this value; moving it to
// another thread moves the ownership with it.
unsafe impl Send for Mapping {}

impl Mapping {
    /// Maps `len` bytes of `fd` from `offset`, shared, read-write. For a
    /// memfd, `fd::Memfd::map` does it safely.
    ///
    /// # Safety
    /// Every page of the range must stay backed for as long as the mapping
    /// lives: an access to a page that is not (a file truncated below
    /// `offset + len` by anyone, a device page never populated) raises
    /// SIGBUS, which kills the process. So `fd` must be a file that cannot
    /// shrink (a sealed memfd), or a device whose pages live with the
    /// mapping and are populated before the memory is used.
    pub unsafe fn of_fd(fd: &impl AsRawFd, offset: u64, len: usize) -> io::Result<Mapping> {
        // SAFETY: a new mapping at an address the kernel chooses; no
        // existing memory is affected.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset as libc::off_t,
            )
        };
        Ok(Mapping {
            ptr: mmap_result(p)?,
            len,
            after_unmap: None,
        })
    }

    /// Takes over a mapping made by other means (privcmd, gntdev).
    ///
    /// # Safety
    /// `ptr` is the start of a live mapping of `len` bytes that nothing
    /// else unmaps; it is unmapped when the value is dropped, and
    /// `after_unmap` runs after that. A mapping starts on a page boundary;
    /// `ring::Ring::new` refuses one that does not.
    pub unsafe fn from_raw(ptr: NonNull<u8>, len: usize, after_unmap: Option<AfterUnmap>) -> Mapping {
        Mapping { ptr, len, after_unmap }
    }

    /// Runs `after_unmap` once the mapping is gone (see `from_raw`).
    pub fn with_after_unmap(mut self, after_unmap: AfterUnmap) -> Mapping {
        self.after_unmap = Some(after_unmap);
        self
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The address an `mmap` without `MAP_FIXED` returned, or its error. Such
/// an `mmap` does not return null (Linux keeps the first pages unmapped,
/// `vm.mmap_min_addr`); were it to, it is an error rather than a panic.
pub(crate) fn mmap_result(p: *mut libc::c_void) -> io::Result<NonNull<u8>> {
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    NonNull::new(p.cast()).ok_or_else(|| io::Error::other("mmap returned a null address"))
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping is owned by this value (see `from_raw`) and
        // no pointer into it outlives the value.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
        if let Some(f) = self.after_unmap.take() {
            f();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn file(len: u64) -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "xs-sys-map-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        f.set_len(len).unwrap();
        f
    }

    #[test]
    #[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
    fn a_mapping_shares_the_file() {
        let f = file(2 * PAGE_SIZE as u64);
        f.write_at(b"second page", PAGE_SIZE as u64).unwrap();
        // SAFETY: the test owns the file and does not truncate it.
        let m = unsafe { Mapping::of_fd(&f, PAGE_SIZE as u64, PAGE_SIZE) }.unwrap();
        assert_eq!((m.len(), m.is_empty()), (PAGE_SIZE, false));
        // SAFETY: inside the mapping; this test is the only user of the file.
        let seen = unsafe { std::slice::from_raw_parts(m.as_ptr(), 11) }.to_vec();
        assert_eq!(seen, b"second page");
        // SAFETY: as above.
        unsafe { m.as_ptr().add(7).write(b'P') };
        let mut back = [0; 11];
        f.read_at(&mut back, PAGE_SIZE as u64).unwrap();
        assert_eq!(&back, b"second Page");
    }

    #[test]
    fn a_bad_descriptor_is_an_error() {
        let f = file(0);
        // SAFETY: nothing is mapped.
        assert!(
            unsafe { Mapping::of_fd(&f, 0, 0) }.is_err(),
            "an empty mapping is refused by the kernel"
        );
    }

    #[test]
    fn a_null_address_from_mmap_is_an_error() {
        let e = mmap_result(std::ptr::null_mut()).unwrap_err();
        assert_eq!(e.to_string(), "mmap returned a null address");
    }

    #[test]
    fn a_mapping_of_no_byte_is_empty() {
        // SAFETY: no byte to access, and never dropped, so never unmapped.
        let m = std::mem::ManuallyDrop::new(unsafe { Mapping::from_raw(NonNull::dangling(), 0, None) });
        assert_eq!((m.is_empty(), m.len()), (true, 0));
    }

    #[test]
    #[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
    fn a_hook_added_to_a_mapping_runs_after_the_unmap() {
        let f = file(PAGE_SIZE as u64);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        // SAFETY: the test owns the file and does not truncate it.
        let m = unsafe { Mapping::of_fd(&f, 0, PAGE_SIZE) }
            .unwrap()
            .with_after_unmap(Box::new(move || flag.store(true, Ordering::SeqCst)));
        assert!(!ran.load(Ordering::SeqCst));
        drop(m);
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    #[cfg_attr(miri, ignore = "file-backed mmap: not emulated by Miri")]
    fn from_raw_unmaps_then_runs_the_hook() {
        let f = file(PAGE_SIZE as u64);
        // SAFETY: the test owns the file and does not truncate it.
        let first = unsafe { Mapping::of_fd(&f, 0, PAGE_SIZE) }.unwrap();
        let (ptr, len) = (NonNull::new(first.as_ptr()).unwrap(), first.len());
        std::mem::forget(first);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        // SAFETY: the mapping above, whose owner was forgotten.
        let m = unsafe { Mapping::from_raw(ptr, len, Some(Box::new(move || flag.store(true, Ordering::SeqCst)))) };
        assert!(!ran.load(Ordering::SeqCst));
        drop(m);
        assert!(ran.load(Ordering::SeqCst));
    }
}
