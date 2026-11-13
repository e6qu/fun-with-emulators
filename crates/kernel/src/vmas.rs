//! An address space's mappings as Linux keeps them: non-overlapping ranges
//! of pages, each with what it maps (its protections, its backing), split
//! and replaced as `mmap`, `munmap`, `mprotect` and `mremap` cut through
//! them, and merged again where neighbours continue each other.
//!
//! It is the bookkeeping only; a backend that manages guest memory itself
//! (the hypervisor backend, whose guest has page tables of its own) applies
//! each change to its memory and tables.

use std::collections::BTreeMap;

/// What one mapping maps. `at(offset)` is the same mapping seen from
/// `offset` bytes into it — a file mapping's offset or a backing address
/// moves with the start — so a range cut out of a mapping keeps the right
/// value, and two ranges are one mapping where the second is the first
/// seen from its end.
pub trait Mapping: Clone + PartialEq + std::fmt::Debug {
    fn at(&self, offset: u64) -> Self;
}

/// A range `[start, end)` and what it maps.
#[derive(Debug, Clone, PartialEq)]
pub struct Piece<V> {
    pub start: u64,
    pub end: u64,
    pub value: V,
}

/// The mappings, by start address.
#[derive(Debug, Clone)]
pub struct Vmas<V> {
    map: BTreeMap<u64, (u64, V)>,
}

impl<V> Default for Vmas<V> {
    fn default() -> Self {
        Vmas { map: BTreeMap::new() }
    }
}

impl<V: Mapping> Vmas<V> {
    pub const fn new() -> Self {
        Vmas { map: BTreeMap::new() }
    }

    /// Every mapping, in address order.
    pub fn iter(&self) -> impl Iterator<Item = Piece<&V>> {
        self.map.iter().map(|(&start, (end, value))| Piece { start, end: *end, value })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// How many mappings there are.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// The mapping containing `addr`.
    pub fn get(&self, addr: u64) -> Option<Piece<&V>> {
        let (&start, (end, value)) = self.map.range(..=addr).next_back()?;
        (addr < *end).then_some(Piece { start, end: *end, value })
    }

    /// The parts of `[start, end)` that are mapped, cut to it, in order.
    /// The mappings that overlap `[start, end)`, whole and unclipped.
    pub fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = Piece<&V>> {
        let before = self.map.range(..start).next_back().filter(|(_, (e, _))| *e > start);
        before.into_iter().chain(self.map.range(start..end)).map(|(&start, (end, value))| Piece {
            start,
            end: *end,
            value,
        })
    }

    pub fn pieces(&self, start: u64, end: u64) -> Vec<Piece<V>> {
        let mut out = Vec::new();
        // The mapping that may begin before `start`.
        if let Some((&s, (e, v))) = self.map.range(..start).next_back()
            && *e > start
        {
            out.push(Piece { start, end: (*e).min(end), value: v.at(start - s) });
        }
        for (&s, (e, v)) in self.map.range(start..end) {
            out.push(Piece { start: s, end: (*e).min(end), value: v.clone() });
        }
        out
    }

    /// Whether every page of `[start, end)` is mapped.
    pub fn covered(&self, start: u64, end: u64) -> bool {
        let mut at = start;
        for p in self.pieces(start, end) {
            if p.start != at {
                return false;
            }
            at = p.end;
        }
        at >= end
    }

    /// Whether any page of `[start, end)` is mapped.
    pub fn any(&self, start: u64, end: u64) -> bool {
        !self.pieces(start, end).is_empty()
    }

    /// Unmap `[start, end)`, returning what was mapped there.
    pub fn remove(&mut self, start: u64, end: u64) -> Vec<Piece<V>> {
        if start >= end {
            return Vec::new();
        }
        let removed = self.pieces(start, end);
        self.cut(start);
        self.cut(end);
        let keys: Vec<u64> = self.map.range(start..end).map(|(&s, _)| s).collect();
        for k in keys {
            self.map.remove(&k);
        }
        removed
    }

    /// Map `[start, end)` to `value`, replacing what was there (as
    /// `MAP_FIXED` does); returns what it replaced.
    pub fn insert(&mut self, start: u64, end: u64, value: V) -> Vec<Piece<V>> {
        let replaced = self.remove(start, end);
        if start < end {
            self.map.insert(start, (end, value));
            self.merge_around(start, end);
        }
        replaced
    }

    /// Give every mapped part of `[start, end)` the value `f` makes of its
    /// own (`mprotect`); unmapped parts stay unmapped. Returns the parts as
    /// they were.
    pub fn update(&mut self, start: u64, end: u64, f: impl Fn(&V) -> V) -> Vec<Piece<V>> {
        let before = self.pieces(start, end);
        self.cut(start);
        self.cut(end);
        let keys: Vec<u64> = self.map.range(start..end).map(|(&s, _)| s).collect();
        for k in keys {
            if let Some((_, v)) = self.map.get_mut(&k) {
                *v = f(v);
            }
        }
        self.merge_around(start, end);
        before
    }

    /// The lowest (or, with `top_down`, highest) start of `len` free bytes
    /// inside `[lo, hi)`, aligned to `align` (a power of two).
    pub fn find_free(&self, len: u64, lo: u64, hi: u64, align: u64, top_down: bool) -> Option<u64> {
        let up = |a: u64| a.checked_add(align - 1).map(|v| v & !(align - 1));
        let down = |a: u64| a & !(align - 1);
        // The gaps between mappings inside [lo, hi), in order.
        let mut gaps = Vec::new();
        let mut at = lo;
        for (&s, (e, _)) in self.map.range(..hi) {
            if *e <= lo {
                continue;
            }
            if s > at {
                gaps.push((at, s.min(hi)));
            }
            at = at.max(*e);
        }
        if at < hi {
            gaps.push((at, hi));
        }
        let fits = |&(gs, ge): &(u64, u64)| -> Option<u64> {
            if top_down {
                let start = down(ge.checked_sub(len)?);
                (start >= gs).then_some(start)
            } else {
                let start = up(gs)?;
                (start.checked_add(len)? <= ge).then_some(start)
            }
        };
        if top_down { gaps.iter().rev().find_map(fits) } else { gaps.iter().find_map(fits) }
    }

    /// Split the mapping containing `addr` there, if it starts before it.
    fn cut(&mut self, addr: u64) {
        let Some((&s, &(e, _))) = self.map.range(..addr).next_back() else { return };
        if e <= addr {
            return;
        }
        let (_, v) = self.map.get(&s).unwrap().clone();
        self.map.insert(s, (addr, v.clone()));
        self.map.insert(addr, (e, v.at(addr - s)));
    }

    /// Merge the mappings in and next to `[start, end)` that continue each
    /// other.
    fn merge_around(&mut self, start: u64, end: u64) {
        let from = self.map.range(..start).next_back().map_or(start, |(&s, _)| s);
        let keys: Vec<u64> = self.map.range(from..=end).map(|(&s, _)| s).collect();
        let Some(&first) = keys.first() else { return };
        let mut cur = first;
        for &next in &keys[1..] {
            let continues = {
                let (ce, cv) = &self.map[&cur];
                let (_, nv) = &self.map[&next];
                *ce == next && cv.at(next - cur) == *nv
            };
            if continues {
                let (ne, _) = self.map.remove(&next).unwrap();
                self.map.get_mut(&cur).unwrap().0 = ne;
            } else {
                cur = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test mapping: protections and a backing offset that moves along.
    #[derive(Debug, Clone, PartialEq)]
    struct M {
        prot: u8,
        off: u64,
    }

    impl Mapping for M {
        fn at(&self, offset: u64) -> M {
            M { prot: self.prot, off: self.off + offset }
        }
    }

    fn m(prot: u8, off: u64) -> M {
        M { prot, off }
    }

    fn list(v: &Vmas<M>) -> Vec<(u64, u64, u8, u64)> {
        v.iter().map(|p| (p.start, p.end, p.value.prot, p.value.off)).collect()
    }

    #[test]
    fn fixed_mappings_replace_and_split() {
        let mut v = Vmas::new();
        v.insert(0x1000, 0x9000, m(3, 0));
        let replaced = v.insert(0x3000, 0x5000, m(1, 100));
        assert_eq!(replaced, vec![Piece { start: 0x3000, end: 0x5000, value: m(3, 0x2000) }]);
        assert_eq!(
            list(&v),
            vec![(0x1000, 0x3000, 3, 0), (0x3000, 0x5000, 1, 100), (0x5000, 0x9000, 3, 0x4000)]
        );
    }

    #[test]
    fn unmapping_cuts_out_the_middle() {
        let mut v = Vmas::new();
        v.insert(0x1000, 0x9000, m(3, 0));
        let gone = v.remove(0x2000, 0x4000);
        assert_eq!(gone.len(), 1);
        assert_eq!(list(&v), vec![(0x1000, 0x2000, 3, 0), (0x4000, 0x9000, 3, 0x3000)]);
        assert!(!v.covered(0x1000, 0x9000));
        assert!(v.covered(0x4000, 0x9000));
        assert!(v.get(0x2800).is_none());
        assert_eq!(v.get(0x4800).unwrap().start, 0x4000);
    }

    #[test]
    fn protections_split_and_merge_back() {
        let mut v = Vmas::new();
        v.insert(0x1000, 0x5000, m(3, 0));
        v.update(0x2000, 0x3000, |x| m(1, x.off));
        assert_eq!(
            list(&v),
            vec![(0x1000, 0x2000, 3, 0), (0x2000, 0x3000, 1, 0x1000), (0x3000, 0x5000, 3, 0x2000)]
        );
        v.update(0x2000, 0x3000, |x| m(3, x.off));
        assert_eq!(list(&v), vec![(0x1000, 0x5000, 3, 0)]);
    }

    #[test]
    fn neighbours_merge_only_when_they_continue() {
        let mut v = Vmas::new();
        v.insert(0x1000, 0x2000, m(3, 0));
        v.insert(0x2000, 0x3000, m(3, 0x1000));
        v.insert(0x3000, 0x4000, m(3, 0x9000));
        assert_eq!(list(&v), vec![(0x1000, 0x3000, 3, 0), (0x3000, 0x4000, 3, 0x9000)]);
    }

    #[test]
    fn updating_leaves_holes_unmapped() {
        let mut v = Vmas::new();
        v.insert(0x1000, 0x2000, m(3, 0));
        v.insert(0x3000, 0x4000, m(3, 0x2000));
        v.update(0x0, 0x8000, |x| m(1, x.off));
        assert_eq!(list(&v), vec![(0x1000, 0x2000, 1, 0), (0x3000, 0x4000, 1, 0x2000)]);
    }

    #[test]
    fn free_space_is_found_from_either_end() {
        let mut v = Vmas::new();
        v.insert(0x10000, 0x20000, m(3, 0));
        v.insert(0x30000, 0x40000, m(3, 0));
        assert_eq!(v.find_free(0x8000, 0x0, 0x100000, 0x1000, false), Some(0x0));
        assert_eq!(v.find_free(0x10000, 0x8000, 0x100000, 0x1000, false), Some(0x20000));
        assert_eq!(v.find_free(0x10000, 0x0, 0x40000, 0x1000, true), Some(0x20000));
        assert_eq!(v.find_free(0x10001, 0x10000, 0x40000, 0x1000, false), None);
        assert_eq!(v.find_free(0x1000, 0x12000, 0x50000, 0x10000, false), Some(0x20000));
        // Aligned to 64 KiB, 0x18000 bytes fit only past the last mapping.
        assert_eq!(v.find_free(0x18000, 0x0, 0x80000, 0x10000, false), Some(0x40000));
    }
}
