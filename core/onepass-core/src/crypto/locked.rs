//! Page-locked storage for 32-byte secrets.
//!
//! A process-wide pool of page-aligned pages, each locked in RAM with
//! `mlock` once (Unix; best effort), cut into 32-byte slots. Pages are never
//! unlocked nor freed: a freed slot is wiped and handed out again. A key gets
//! its own slot, so dropping one key can never `munlock` a page that still
//! holds another (Ruling 10).
//!
//! When `mlock` fails (RLIMIT_MEMLOCK reached, for example) the page is used
//! unlocked and [`lock_failures`] counts it. Non-Unix targets never lock.
//!
//! This is the only module of the crate with `unsafe` code.

use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroize;

/// Size of one slot, in bytes.
pub const SLOT_LEN: usize = 32;

/// Used when the system page size cannot be read.
const FALLBACK_PAGE_SIZE: usize = 4096;

static LOCK_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Number of pages that could not be locked in RAM since the process started.
pub fn lock_failures() -> usize {
    LOCK_FAILURES.load(Ordering::Relaxed)
}

static GLOBAL: Mutex<Pool> = Mutex::new(Pool::new());

/// Pointer to one slot inside a pool page.
struct SlotPtr(NonNull<[u8; SLOT_LEN]>);

// SAFETY: a `SlotPtr` in the free list points into a page that is never
// freed, and it is only dereferenced by the `LockedSlot` that owns it after
// it leaves the list (under the pool mutex), so moving it across threads is
// sound.
unsafe impl Send for SlotPtr {}

struct Pool {
    /// System page size, read on first growth (0 until then).
    page_size: usize,
    /// Base of every page ever allocated, kept so the pages stay reachable.
    pages: Vec<SlotPtr>,
    /// Wiped slots ready to be handed out (LIFO).
    free: Vec<SlotPtr>,
    #[cfg(test)]
    force_lock_failure: bool,
}

impl Pool {
    const fn new() -> Pool {
        Pool {
            page_size: 0,
            pages: Vec::new(),
            free: Vec::new(),
            #[cfg(test)]
            force_lock_failure: false,
        }
    }

    fn page_size(&mut self) -> usize {
        if self.page_size == 0 {
            let p = system_page_size();
            self.page_size = if p >= SLOT_LEN && p.is_power_of_two() {
                p
            } else {
                FALLBACK_PAGE_SIZE
            };
        }
        self.page_size
    }

    fn take(&mut self) -> SlotPtr {
        if self.free.is_empty() {
            self.grow();
        }
        self.free.pop().expect("a fresh page has free slots")
    }

    /// Allocate one zeroed page, lock it, and add its slots to the free list.
    fn grow(&mut self) {
        let size = self.page_size();
        let layout = Layout::from_size_align(size, size).expect("page layout");
        // SAFETY: `layout` has a non-zero size (at least SLOT_LEN).
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(base) = NonNull::new(raw) else {
            handle_alloc_error(layout)
        };
        #[cfg(test)]
        let forced = self.force_lock_failure;
        #[cfg(not(test))]
        let forced = false;
        if forced || !lock_page(base, size) {
            LOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        self.pages.push(SlotPtr(base.cast()));
        let slots = size / SLOT_LEN;
        self.free.reserve(slots);
        // Pushed in reverse so the lowest slot is handed out first.
        for i in (0..slots).rev() {
            // SAFETY: `i * SLOT_LEN + SLOT_LEN <= size`, so the offset stays
            // inside the `size`-byte allocation starting at `base`, and the
            // result is non-null. Alignment of [u8; 32] is 1.
            let slot = unsafe { base.add(i * SLOT_LEN) };
            self.free.push(SlotPtr(slot.cast()));
        }
    }
}

fn lock(pool: &Mutex<Pool>) -> MutexGuard<'_, Pool> {
    // A panic while holding the lock cannot leave the lists inconsistent
    // (each mutation is a single push or pop), so poisoning is ignored.
    pool.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(all(unix, not(miri)))]
fn system_page_size() -> usize {
    // SAFETY: sysconf has no preconditions; it returns -1 on error.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(p).unwrap_or(FALLBACK_PAGE_SIZE)
}

#[cfg(not(all(unix, not(miri))))]
fn system_page_size() -> usize {
    FALLBACK_PAGE_SIZE
}

/// Lock one page in RAM. Returns false when the system refuses.
#[cfg(all(unix, not(miri)))]
fn lock_page(base: NonNull<u8>, size: usize) -> bool {
    // SAFETY: `base..base + size` is a live allocation owned by the pool
    // and never freed; mlock only changes its paging, not its contents.
    unsafe { libc::mlock(base.as_ptr().cast::<libc::c_void>(), size) == 0 }
}

/// Miri cannot call mlock and non-Unix targets have none: nothing to lock.
#[cfg(not(all(unix, not(miri))))]
fn lock_page(_base: NonNull<u8>, _size: usize) -> bool {
    true
}

/// Exclusive handle on one 32-byte slot of locked memory. Starts zeroed;
/// wiped and returned to the pool on drop. Deliberately not `Clone`.
pub struct LockedSlot {
    ptr: NonNull<[u8; SLOT_LEN]>,
    pool: &'static Mutex<Pool>,
}

// SAFETY: the handle owns its slot exclusively (taken out of the free list
// under the mutex), so sending it to another thread is like sending a
// `Box<[u8; 32]>`.
unsafe impl Send for LockedSlot {}
// SAFETY: shared references only give `&[u8; 32]`; mutation needs `&mut`.
unsafe impl Sync for LockedSlot {}

impl LockedSlot {
    /// A zeroed slot from the process-wide pool.
    #[allow(clippy::new_without_default)]
    pub fn new() -> LockedSlot {
        LockedSlot::new_in(&GLOBAL)
    }

    fn new_in(pool: &'static Mutex<Pool>) -> LockedSlot {
        let SlotPtr(ptr) = lock(pool).take();
        LockedSlot { ptr, pool }
    }

    pub fn as_bytes(&self) -> &[u8; SLOT_LEN] {
        // SAFETY: `ptr` points to a live, initialized (zeroed at page
        // allocation) slot that only this handle can reach until drop.
        unsafe { self.ptr.as_ref() }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        // SAFETY: as in `as_bytes`, and `&mut self` makes the access unique.
        unsafe { self.ptr.as_mut() }
    }
}

impl Drop for LockedSlot {
    fn drop(&mut self) {
        // Volatile wipe before the slot can be handed out again.
        self.as_bytes_mut().zeroize();
        lock(self.pool).free.push(SlotPtr(self.ptr));
    }
}

#[cfg(test)]
fn page_count(pool: &Mutex<Pool>) -> usize {
    lock(pool).pages.len()
}
#[cfg(test)]
fn free_count(pool: &Mutex<Pool>) -> usize {
    lock(pool).free.len()
}
#[cfg(test)]
fn slots_per_page(pool: &Mutex<Pool>) -> usize {
    lock(pool).page_size() / SLOT_LEN
}
#[cfg(test)]
fn force_lock_failure(pool: &Mutex<Pool>) {
    lock(pool).force_lock_failure = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A private pool, so the counts below do not race with other tests.
    fn private_pool() -> &'static Mutex<Pool> {
        Box::leak(Box::new(Mutex::new(Pool::new())))
    }

    fn addr(s: &LockedSlot) -> usize {
        s.as_bytes().as_ptr() as usize
    }

    #[test]
    fn new_slot_is_zeroed() {
        let s = LockedSlot::new();
        assert_eq!(s.as_bytes(), &[0u8; SLOT_LEN]);
    }

    #[test]
    fn freed_slot_is_reused_and_zeroed() {
        let pool = private_pool();
        let mut a = LockedSlot::new_in(pool);
        a.as_bytes_mut().copy_from_slice(&[0xAA; SLOT_LEN]);
        let first = addr(&a);
        drop(a);
        let b = LockedSlot::new_in(pool);
        assert_eq!(addr(&b), first, "the freed slot is handed out again");
        assert_eq!(b.as_bytes(), &[0u8; SLOT_LEN], "and it comes back wiped");
        assert_eq!(page_count(pool), 1);
    }

    #[test]
    fn many_slots_span_several_pages() {
        let pool = private_pool();
        let per_page = slots_per_page(pool);
        let n = 3 * per_page + 1;
        let mut slots: Vec<LockedSlot> = (0..n).map(|_| LockedSlot::new_in(pool)).collect();
        for (i, s) in slots.iter_mut().enumerate() {
            s.as_bytes_mut()[..8].copy_from_slice(&(i as u64).to_le_bytes());
        }
        let addrs: HashSet<usize> = slots.iter().map(addr).collect();
        assert_eq!(addrs.len(), n, "every slot is distinct");
        for (i, s) in slots.iter().enumerate() {
            assert_eq!(&s.as_bytes()[..8], &(i as u64).to_le_bytes());
            assert_eq!(&s.as_bytes()[8..], &[0u8; SLOT_LEN - 8]);
        }
        assert_eq!(page_count(pool), 4);
        drop(slots);
        assert_eq!(free_count(pool), 4 * per_page);
        // Reallocating the same number does not grow the pool.
        let again: Vec<LockedSlot> = (0..n).map(|_| LockedSlot::new_in(pool)).collect();
        assert!(again.iter().all(|s| s.as_bytes() == &[0u8; SLOT_LEN]));
        assert_eq!(page_count(pool), 4);
    }

    #[test]
    fn concurrent_allocation_from_eight_threads() {
        let pool = private_pool();
        let rounds = if cfg!(miri) { 20 } else { 500 };
        let handles: Vec<_> = (0..8u8)
            .map(|t| {
                std::thread::spawn(move || {
                    let mut held = Vec::new();
                    for r in 0..rounds {
                        let mut s = LockedSlot::new_in(pool);
                        assert_eq!(s.as_bytes(), &[0u8; SLOT_LEN]);
                        s.as_bytes_mut().fill(t.wrapping_add(1));
                        held.push(s);
                        if r % 3 == 0 {
                            held.swap_remove(0);
                        }
                    }
                    for s in &held {
                        assert!(s.as_bytes().iter().all(|&b| b == t.wrapping_add(1)));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(free_count(pool), page_count(pool) * slots_per_page(pool));
    }

    #[test]
    fn global_slots_work_across_threads() {
        let handles: Vec<_> = (0..8u8)
            .map(|t| {
                std::thread::spawn(move || {
                    let mut s = LockedSlot::new();
                    s.as_bytes_mut().fill(t);
                    s
                })
            })
            .collect();
        for (t, h) in handles.into_iter().enumerate() {
            let s = h.join().unwrap();
            assert!(s.as_bytes().iter().all(|&b| b == t as u8));
        }
    }

    #[test]
    fn lock_failure_is_not_fatal() {
        let pool = private_pool();
        force_lock_failure(pool);
        let before = lock_failures();
        let mut s = LockedSlot::new_in(pool);
        assert!(lock_failures() > before, "the failed lock is counted");
        s.as_bytes_mut().fill(5);
        assert_eq!(
            s.as_bytes(),
            &[5u8; SLOT_LEN],
            "the slot still works unlocked"
        );
    }
}
