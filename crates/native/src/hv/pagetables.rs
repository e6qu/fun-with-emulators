//! The guest's stage-1 page tables: what each guest page maps to in the
//! VM's guest-physical (IPA) space, and with which EL0 permissions — the
//! translation the guest's own accesses go through, as under Linux. The
//! 4 KiB granule (Linux's page size on arm64) with a 40-bit address space:
//! a level-0 table of two entries, then level 1 (1 GiB), level 2 (2 MiB)
//! and level 3 (4 KiB pages). Only level-3 pages are used, so changing a
//! page never needs a block split.
//!
//! The tables live in a pool of host memory that is mapped into the VM once
//! (the VM's stage 2 never changes for them); this module writes the
//! descriptors in the architecture's format and the hardware walks them.
//! The rules for editing tables a running vCPU may be walking:
//!
//! - every descriptor is written with one 64-bit store;
//! - a new table is filled before it is linked in, with a barrier between;
//! - making a page accessible needs no TLB maintenance (invalid entries are
//!   never cached); taking access away — unmapping, or reducing its
//!   permissions — does, and the change reports it ([`Change::flush`]), so
//!   the caller has the TLBs invalidated before the guest relies on it;
//! - a table emptied by an unmapping is only reused after that invalidation
//!   ([`PageTables::flushed`]), since a walk may still be using it.

/// What a guest page may be used for at EL0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    /// A BTI guarded page (`PROT_BTI`): indirect branches must land on a
    /// `bti` landing pad.
    pub guarded: bool,
}

impl Perms {
    /// No access at all: the page is not mapped in the tables.
    pub fn none(&self) -> bool {
        !self.read && !self.write && !self.exec
    }
}

/// The result of an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub struct Change {
    /// Some access was taken away: the TLBs must be invalidated before the
    /// guest may rely on the change.
    pub flush: bool,
}

pub const PAGE: u64 = 4 << 10;
const TABLE_ENTRIES: u64 = 512;
/// The guest address space: 40 bits.
pub const VA_BITS: u32 = 40;
pub const VA_LIMIT: u64 = 1 << VA_BITS;

// Descriptor bits (VMSAv8-64, 4 KiB granule).
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // at levels 0-2: a table; at level 3: a page
const ATTR_NORMAL: u64 = 0 << 2; // MAIR attribute 0: normal write-back
const AP_EL0: u64 = 1 << 6; // EL0 may access
const AP_RO: u64 = 1 << 7; // read-only
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11; // not global: tagged with the ASID
const GP: u64 = 1 << 50; // BTI guarded page
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

/// The level-3 descriptor for a page at `ipa` with `p` (not `p.none()`).
pub fn page_descriptor(ipa: u64, p: Perms) -> u64 {
    let mut d = (ipa & ADDR_MASK) | VALID | TABLE | ATTR_NORMAL | AP_EL0 | SH_INNER | AF | NG | PXN;
    if !p.write {
        d |= AP_RO;
    }
    if !p.exec {
        d |= UXN;
    }
    if p.guarded {
        d |= GP;
    }
    d
}

/// The level-3 descriptor for a page of fwe's own EL1 code at `ipa`: read
/// only, executable at EL1, out of EL0's reach.
pub fn el1_code_descriptor(ipa: u64) -> u64 {
    (ipa & ADDR_MASK) | VALID | TABLE | ATTR_NORMAL | AP_RO | SH_INNER | AF | UXN
}

/// What a level-3 descriptor grants, if it is a valid page.
pub fn decode(d: u64) -> Option<(u64, Perms)> {
    if d & (VALID | TABLE) != VALID | TABLE {
        return None;
    }
    let p = Perms {
        read: d & AP_EL0 != 0,
        write: d & AP_EL0 != 0 && d & AP_RO == 0,
        exec: d & UXN == 0,
        guarded: d & GP != 0,
    };
    Some((d & ADDR_MASK, p))
}

/// Where the tables live: page-sized tables in host memory, each with its
/// guest-physical address.
pub trait Pool {
    /// A zeroed table: its IPA and its host address.
    fn alloc(&mut self) -> Option<(u64, *mut u64)>;
    /// Give back the table at `ipa` (no walk can reach it any more).
    fn free(&mut self, ipa: u64);
    /// The host address of the table at `ipa`.
    fn host(&self, ipa: u64) -> *mut u64;
}

/// The tables of one address space.
pub struct PageTables<P: Pool> {
    pool: P,
    root: u64,
    /// Tables emptied by unmappings, `(table, generation)`: freed once an
    /// invalidation covers the generation of the edit that emptied them.
    retired: Vec<(u64, u64)>,
    /// The generation edits now belong to ([`PageTables::set_generation`]).
    generation: u64,
}

/// Make the stores to a table visible to the table walker before the
/// table is linked in, or a descriptor change before what depends on it.
fn barrier() {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a data synchronisation barrier; no memory or register effects
    // beyond ordering.
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags))
    };
}

impl<P: Pool> PageTables<P> {
    pub fn new(mut pool: P) -> Option<Self> {
        let (root, _) = pool.alloc()?;
        Some(PageTables { pool, root, retired: Vec::new(), generation: 0 })
    }

    /// The level-0 table's IPA, for `TTBR0_EL1`.
    pub fn root(&self) -> u64 {
        self.root
    }

    fn entry(&self, table: u64, index: u64) -> *mut u64 {
        // SAFETY: index < 512 within a page-sized table of the pool.
        unsafe { self.pool.host(table).add(index as usize) }
    }

    fn read(&self, table: u64, index: u64) -> u64 {
        // SAFETY: an aligned descriptor in a table of the pool.
        unsafe { std::ptr::read_volatile(self.entry(table, index)) }
    }

    fn write(&self, table: u64, index: u64, d: u64) {
        // SAFETY: an aligned descriptor in a table of the pool: one 64-bit
        // store, which a concurrent walk sees whole.
        unsafe { std::ptr::write_volatile(self.entry(table, index), d) }
    }

    fn index(va: u64, level: u32) -> u64 {
        (va >> (12 + 9 * (3 - level))) & (TABLE_ENTRIES - 1)
    }

    /// The level-3 table for `va`, made (and linked in) if `make`.
    fn leaf_table(&mut self, va: u64, make: bool) -> Option<u64> {
        let mut table = self.root;
        for level in 0..3 {
            let i = Self::index(va, level);
            let d = self.read(table, i);
            table = if d & (VALID | TABLE) == VALID | TABLE {
                d & ADDR_MASK
            } else if make {
                let (next, _) = self.pool.alloc()?;
                // The new table is zeroed: visible before it is linked.
                barrier();
                self.write(table, i, next | VALID | TABLE);
                next
            } else {
                return None;
            };
        }
        Some(table)
    }

    /// Map `[va, va + len)` to `[ipa, ipa + len)` with `p`, replacing what
    /// was there. `p.none()` unmaps instead. Fails if the pool is full.
    pub fn map(&mut self, va: u64, len: u64, ipa: u64, p: Perms) -> Result<Change, ()> {
        if p.none() {
            return Ok(self.unmap(va, len));
        }
        let mut change = Change::default();
        let mut at = va;
        while at < va + len {
            let table = self.leaf_table(at, true).ok_or(())?;
            let i = Self::index(at, 3);
            let old = self.read(table, i);
            let new = page_descriptor(ipa + (at - va), p);
            if let Some((old_ipa, old_p)) = decode(old) {
                // Anything an old translation allowed that the new one does
                // not, or a different page, must leave the TLBs.
                if old_ipa != ipa + (at - va)
                    || (old_p.write && !p.write)
                    || (old_p.exec && !p.exec)
                    || (!old_p.guarded && p.guarded)
                {
                    change.flush = true;
                }
            }
            self.write(table, i, new);
            at += PAGE;
        }
        barrier();
        Ok(change)
    }

    /// Map one page of fwe's EL1 code at `va` (see [`el1_code_descriptor`]).
    pub fn map_el1_code(&mut self, va: u64, ipa: u64) -> Result<(), ()> {
        let table = self.leaf_table(va, true).ok_or(())?;
        self.write(table, Self::index(va, 3), el1_code_descriptor(ipa));
        barrier();
        Ok(())
    }

    /// Unmap `[va, va + len)`.
    pub fn unmap(&mut self, va: u64, len: u64) -> Change {
        let mut change = Change::default();
        let mut at = va;
        let end = va + len;
        while at < end {
            // The rest of this level-3 table's 2 MiB.
            let span_end = ((at | ((PAGE * TABLE_ENTRIES) - 1)) + 1).min(end);
            if let Some(table) = self.leaf_table(at, false) {
                let mut i = Self::index(at, 3);
                let mut a = at;
                while a < span_end {
                    if self.read(table, i) & VALID != 0 {
                        self.write(table, i, 0);
                        change.flush = true;
                    }
                    a += PAGE;
                    i += 1;
                }
                if change.flush && (0..TABLE_ENTRIES).all(|j| self.read(table, j) & VALID == 0) {
                    self.unlink(at, table);
                }
            }
            at = span_end;
        }
        barrier();
        change
    }

    /// Take the empty level-3 table for `va` out of the tree; it is freed
    /// after the next invalidation.
    fn unlink(&mut self, va: u64, leaf: u64) {
        let mut table = self.root;
        for level in 0..2 {
            table = self.read(table, Self::index(va, level)) & ADDR_MASK;
        }
        let i = Self::index(va, 2);
        if self.read(table, i) & ADDR_MASK == leaf {
            self.write(table, i, 0);
            self.retired.push((leaf, self.generation));
        }
    }

    /// The generation the edits that follow belong to: a table they empty
    /// waits for an invalidation that covers it.
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// The TLBs were invalidated for every edit up to generation `upto`:
    /// tables those edits emptied can be reused.
    pub fn flushed(&mut self, upto: u64) {
        let (free, later): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.retired).into_iter().partition(|&(_, g)| g <= upto);
        self.retired = later;
        for (t, _) in free {
            self.pool.free(t);
        }
    }

    /// What `va` translates to, as the hardware would walk it.
    pub fn translate(&self, va: u64) -> Option<(u64, Perms)> {
        let mut table = self.root;
        for level in 0..3 {
            let d = self.read(table, Self::index(va, level));
            if d & (VALID | TABLE) != VALID | TABLE {
                return None;
            }
            table = d & ADDR_MASK;
        }
        let (ipa, p) = decode(self.read(table, Self::index(va, 3)))?;
        Some((ipa | (va & (PAGE - 1)), p))
    }
}

/// The translation regime these tables are walked with, for `TCR_EL1`:
/// T0SZ = 24 (40 bits), 4 KiB granule (TG0 = 0), inner shareable write-back walks,
/// no TTBR1 walks, 40-bit IPAs, top byte ignored (as Linux sets it for user
/// space), ASIDs of 16 bits.
pub fn tcr() -> u64 {
    let t0sz = 64 - u64::from(VA_BITS);
    t0sz | (1 << 8) | (1 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32) | (1 << 36) | (1 << 37)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool of page-sized tables in a vector, at IPAs from a base.
    struct VecPool {
        base: u64,
        mem: Vec<u64>,
        free: Vec<u64>,
        next: u64,
    }

    impl VecPool {
        fn new(tables: usize) -> Self {
            VecPool { base: 0x40_0000_0000, mem: vec![0; tables * 512], free: Vec::new(), next: 0 }
        }
    }

    impl Pool for VecPool {
        fn alloc(&mut self) -> Option<(u64, *mut u64)> {
            let ipa = match self.free.pop() {
                Some(ipa) => ipa,
                None => {
                    if (self.next as usize + 1) * 512 > self.mem.len() {
                        return None;
                    }
                    self.next += 1;
                    self.base + (self.next - 1) * PAGE
                }
            };
            let h = self.host(ipa);
            // SAFETY: a page-sized table inside the vector.
            unsafe { std::ptr::write_bytes(h, 0, 512) };
            Some((ipa, h))
        }
        fn free(&mut self, ipa: u64) {
            self.free.push(ipa);
        }
        fn host(&self, ipa: u64) -> *mut u64 {
            let i = ((ipa - self.base) / PAGE) as usize * 512;
            self.mem[i..].as_ptr() as *mut u64
        }
    }

    const RW: Perms = Perms { read: true, write: true, exec: false, guarded: false };
    const RX: Perms = Perms { read: true, write: false, exec: true, guarded: false };
    const R: Perms = Perms { read: true, write: false, exec: false, guarded: false };

    #[test]
    fn pages_translate_with_their_permissions() {
        let mut t = PageTables::new(VecPool::new(16)).unwrap();
        assert_eq!(t.root(), 0x40_0000_0000, "the first table is the root");
        assert!(!t.map(0x40_0000, 0x3000, 0x1000_0000, RX).unwrap().flush);
        assert_eq!(t.translate(0x40_1234), Some((0x1000_1234, RX)));
        assert_eq!(t.translate(0x40_3000), None);
        assert_eq!(t.translate(0x8f_ffff_f000), None);
        // A page at the top of the 40-bit space.
        let _ = t.map(VA_LIMIT - PAGE, PAGE, 0x2000_0000, RW).unwrap();
        assert_eq!(t.translate(VA_LIMIT - 8), Some((0x2000_0ff8, RW)));
    }

    #[test]
    fn descriptors_are_the_architectures() {
        let d = page_descriptor(0x1234_5000, RX);
        // Valid page, EL0-accessible, read-only, executable at EL0 only,
        // access flag, inner shareable, not global.
        assert_eq!(d & 0b11, 0b11);
        assert_ne!(d & AP_EL0, 0);
        assert_ne!(d & AP_RO, 0);
        assert_eq!(d & UXN, 0);
        assert_ne!(d & PXN, 0);
        assert_eq!(d & ADDR_MASK, 0x1234_5000);
        let g = page_descriptor(0, Perms { guarded: true, ..RX });
        assert_ne!(g & GP, 0);
    }

    #[test]
    fn taking_access_away_needs_a_flush_and_adding_it_does_not() {
        let mut t = PageTables::new(VecPool::new(16)).unwrap();
        let _ = t.map(0x10_0000, 0x2000, 0x50_0000, R).unwrap();
        assert!(!t.map(0x10_0000, 0x2000, 0x50_0000, RW).unwrap().flush, "R -> RW adds");
        assert!(t.map(0x10_0000, 0x1000, 0x50_0000, R).unwrap().flush, "RW -> R takes away");
        assert!(!t.map(0x10_0000, 0x1000, 0x50_0000, RX).unwrap().flush, "R -> RX adds");
        assert!(t.map(0x10_0000, 0x1000, 0x50_0000, R).unwrap().flush, "RX -> R takes away");
        assert!(t.unmap(0x10_0000, 0x2000).flush);
        assert!(!t.unmap(0x10_0000, 0x2000).flush, "nothing left to take away");
        assert!(t.map(0x10_0000, 0x1000, 0x60_0000, R).unwrap().flush.eq(&false));
        assert!(t.map(0x10_0000, 0x1000, 0x70_0000, R).unwrap().flush, "another page");
    }

    #[test]
    fn emptied_tables_are_reused_only_after_the_flush() {
        let mut t = PageTables::new(VecPool::new(6)).unwrap();
        // Root, L1, L2 and an L3 table.
        let _ = t.map(0x20_0000, 0x1000, 0x50_0000, R).unwrap();
        let before = t.pool.next;
        t.set_generation(1);
        let _ = t.unmap(0x20_0000, 0x1000);
        assert_eq!(t.retired.len(), 1, "the L3 table waits for the flush");
        // A mapping in another 2 MiB needs a new L3 table; the retired one
        // is not handed out yet.
        let _ = t.map(0x40_0000, 0x1000, 0x60_0000, R).unwrap();
        assert_eq!(t.pool.next, before + 1);
        t.flushed(0);
        assert!(t.pool.free.is_empty(), "a flush older than the unmapping frees nothing");
        t.flushed(1);
        assert_eq!(t.pool.free.len(), 1);
        let _ = t.map(0x60_0000, 0x1000, 0x70_0000, R).unwrap();
        assert_eq!(t.pool.next, before + 1, "the freed table was reused");
        assert_eq!(t.translate(0x60_0000), Some((0x70_0000, R)));
    }

    #[test]
    fn el1_code_is_out_of_el0s_reach() {
        let mut t = PageTables::new(VecPool::new(16)).unwrap();
        t.map_el1_code(VA_LIMIT - PAGE, 0x3000_0000).unwrap();
        let (ipa, p) = t.translate(VA_LIMIT - PAGE).unwrap();
        assert_eq!(ipa, 0x3000_0000);
        assert!(!p.read && !p.write && !p.exec, "EL0 may not touch it");
        let d = el1_code_descriptor(0);
        assert_eq!(d & PXN, 0, "EL1 executes it");
    }

    #[test]
    fn a_full_pool_fails_the_mapping() {
        let mut t = PageTables::new(VecPool::new(4)).unwrap();
        let _ = t.map(0x0, 0x1000, 0x50_0000, R).unwrap();
        // Another 1 GiB region needs new L2 and L3 tables: no room.
        assert!(t.map(0x4000_0000, 0x1000, 0x60_0000, R).is_err());
    }

    #[test]
    fn the_regime_is_40_bits_with_a_4k_granule() {
        let tcr = tcr();
        assert_eq!(tcr & 0x3f, 24);
        assert_eq!((tcr >> 14) & 0b11, 0b00, "TG0 = 4 KiB");
        assert_ne!(tcr & (1 << 23), 0, "EPD1: no TTBR1 walks");
        assert_ne!(tcr & (1 << 37), 0, "TBI0");
    }
}
