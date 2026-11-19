//! A block's words as the translator makes them ([`crate::jit`]): two
//! sections, hot and cold, each a run of words with what each stands for,
//! and branches to labels resolved once the sections' places are known.
//!
//! The hot section holds what runs each time the block runs; the cold one
//! what runs only on the way into fwe or out of the common case (a
//! conditional branch's way out until it is linked, a lookup's second
//! look, its miss), placed apart so the hot words of many blocks lie
//! close.
//!
//! A branch to a label is made with its offset field clear; finishing the
//! block at the sections' addresses fills it in, and fails loudly where the
//! label is not bound, the field is not clear or the target is out of the
//! field's reach. One label stands outside the block, for the place its
//! ways out go ([`STUB`]).

/// A section of a block's words.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Sec {
    Hot = 0,
    Cold = 1,
}

/// A word's place: its section and its index there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Pos {
    pub sec: Sec,
    pub k: usize,
}

impl Pos {
    pub(crate) const fn hot(k: usize) -> Pos {
        Pos { sec: Sec::Hot, k }
    }
}

/// A place branched to, bound once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Label(usize);

/// The label of the place outside the block its ways out branch to,
/// bound to its address as the block is finished ([`Asm::finish`]).
pub(crate) const STUB: Label = Label(0);

/// Where a label is: a word of the block, or an address outside it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    At(Pos),
    Addr(u64),
}

/// The offset field of a branch, in words: `b` and `bl` (26 bits at 0),
/// `b.cond`, `cbz` and `cbnz` (19 bits at 5), `tbz` and `tbnz` (14 bits
/// at 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    Imm26,
    Imm19,
    Imm14,
}

impl Field {
    /// Its shift and width.
    const fn bits(self) -> (u32, u32) {
        match self {
            Field::Imm26 => (0, 26),
            Field::Imm19 => (5, 19),
            Field::Imm14 => (5, 14),
        }
    }

    /// `w` with its field set to `words`, the offset in words; `None`
    /// out of the field's reach.
    pub(crate) fn set(self, w: u32, words: i64) -> Option<u32> {
        let (shift, width) = self.bits();
        let half = 1i64 << (width - 1);
        if !(-half..half).contains(&words) {
            return None;
        }
        let mask = ((1u32 << width) - 1) << shift;
        Some((w & !mask) | (((words as u32) << shift) & mask))
    }

    /// Whether `w`'s field is clear.
    fn clear(self, w: u32) -> bool {
        let (shift, width) = self.bits();
        w & (((1u32 << width) - 1) << shift) == 0
    }
}

/// A branch whose offset is filled in at resolving: its word, its field
/// and its target.
struct Fixup {
    at: Pos,
    field: Field,
    to: Label,
}

/// A block's words in the making, with `W` what each stands for.
pub(crate) struct Asm<W> {
    words: [Vec<u32>; 2],
    info: [Vec<W>; 2],
    labels: Vec<Option<Target>>,
    fixups: Vec<Fixup>,
}

impl<W: Copy> Asm<W> {
    /// An empty block, its hot words made in `words` and `info` (cleared;
    /// their room kept).
    pub(crate) fn new(mut words: Vec<u32>, mut info: Vec<W>) -> Asm<W> {
        words.clear();
        info.clear();
        Asm {
            words: [words, Vec::new()],
            info: [info, Vec::new()],
            labels: vec![None],
            fixups: Vec::new(),
        }
    }

    /// The number of words in section `s`.
    pub(crate) fn len(&self, s: Sec) -> usize {
        self.words[s as usize].len()
    }

    /// Where the next word of section `s` goes.
    pub(crate) fn here(&self, s: Sec) -> Pos {
        Pos { sec: s, k: self.len(s) }
    }

    /// Word `w`, standing for `i`, at the end of section `s`: its place.
    pub(crate) fn push(&mut self, s: Sec, w: u32, i: W) -> Pos {
        let at = self.here(s);
        self.words[s as usize].push(w);
        self.info[s as usize].push(i);
        at
    }

    /// Words `ws`, each standing for `i`, at the end of section `s`.
    pub(crate) fn extend(&mut self, s: Sec, ws: impl IntoIterator<Item = u32>, i: W) {
        for w in ws {
            self.push(s, w, i);
        }
    }

    /// A new label, not yet bound.
    pub(crate) fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    /// A label bound at `at`.
    pub(crate) fn label_at(&mut self, at: Pos) -> Label {
        self.labels.push(Some(Target::At(at)));
        Label(self.labels.len() - 1)
    }

    /// Bind `l` where the next word of section `s` goes.
    pub(crate) fn bind(&mut self, l: Label, s: Sec) {
        let at = self.here(s);
        let slot = &mut self.labels[l.0];
        assert!(slot.is_none(), "a label bound twice");
        *slot = Some(Target::At(at));
    }

    /// Bind `l` at `at`, a word made already.
    pub(crate) fn bind_at(&mut self, l: Label, at: Pos) {
        let slot = &mut self.labels[l.0];
        assert!(slot.is_none(), "a label bound twice");
        *slot = Some(Target::At(at));
    }

    /// Branch `w` (its `field` clear), standing for `i`, at the end of
    /// section `s`, to `to`: its place.
    pub(crate) fn branch(&mut self, s: Sec, w: u32, field: Field, to: Label, i: W) -> Pos {
        assert!(field.clear(w), "a branch {w:#010x} made with its offset set");
        let at = self.push(s, w, i);
        self.fixups.push(Fixup { at, field, to });
        at
    }

    /// The word at `at`.
    pub(crate) fn word(&self, at: Pos) -> u32 {
        self.words[at.sec as usize][at.k]
    }

    /// What the word at `at` stands for.
    pub(crate) fn info_mut(&mut self, at: Pos) -> &mut W {
        &mut self.info[at.sec as usize][at.k]
    }

    /// The index of the word at `at` in [`Asm::finish`]'s run (the hot
    /// words, then the cold), once every word is made.
    pub(crate) fn flat(&self, at: Pos) -> usize {
        match at.sec {
            Sec::Hot => at.k,
            Sec::Cold => self.len(Sec::Hot) + at.k,
        }
    }

    /// Fill in every branch's offset, the sections placed at the byte
    /// addresses `at` (hot, cold).
    fn resolve(&mut self, at: [u64; 2]) {
        let addr = |p: Pos| at[p.sec as usize] + 4 * p.k as u64;
        for f in std::mem::take(&mut self.fixups) {
            let to = match self.labels[f.to.0].expect("a branch to a label never bound") {
                Target::At(p) => addr(p),
                Target::Addr(a) => a,
            };
            let words = (to as i64 - addr(f.at) as i64) / 4;
            let w = &mut self.words[f.at.sec as usize][f.at.k];
            *w = f.field.set(*w, words).unwrap_or_else(|| {
                panic!(
                    "a branch at {f:?} to {to:#x}, {words} words away, out of its reach",
                    f = f.at
                )
            });
        }
    }

    /// The block's words and what each stands for in one run, the hot
    /// then the cold, its branches resolved for the sections placed at the
    /// byte addresses `at` (hot, cold) and [`STUB`] at `stub`.
    pub(crate) fn finish(mut self, at: [u64; 2], stub: u64) -> (Vec<u32>, Vec<W>) {
        self.labels[STUB.0] = Some(Target::Addr(stub));
        self.resolve(at);
        let [mut words, cold] = self.words;
        let [mut info, cold_info] = self.info;
        words.extend(cold);
        info.extend(cold_info);
        (words, info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u32 = 0x1400_0000;
    const CBZ: u32 = 0xb400_0000;
    const TBZ: u32 = 0x3600_0000;

    /// Branches forward and back, within a section and across, resolve to
    /// their targets' distance in words in each field.
    #[test]
    fn branches_reach_their_labels() {
        let mut a: Asm<u8> = Asm::new(Vec::new(), Vec::new());
        let back = a.label_at(Pos::hot(0));
        a.push(Sec::Hot, 1, 0);
        let fwd = a.label();
        let cold = a.label();
        a.branch(Sec::Hot, B, Field::Imm26, fwd, 0);
        a.branch(Sec::Hot, CBZ, Field::Imm19, cold, 0);
        a.branch(Sec::Hot, TBZ, Field::Imm14, back, 0);
        a.bind(fwd, Sec::Hot);
        a.push(Sec::Hot, 2, 0);
        a.push(Sec::Cold, 3, 0);
        a.bind(cold, Sec::Cold);
        a.branch(Sec::Cold, B, Field::Imm26, back, 0);
        a.branch(Sec::Cold, B, Field::Imm26, STUB, 0);
        // The cold words 100 words past the hot, the stub 50 before them.
        let (w, _) = a.finish([0x1000, 0x1000 + 4 * 100], 0x1000 - 4 * 50);
        // Each branch back in two's complement: -101 is 2^26 - 101.
        let back = |n: u32| (1 << 26) - n;
        assert_eq!(
            w,
            vec![
                1,
                B | 3,
                CBZ | 99 << 5,
                TBZ | (0x3fff - 2) << 5,
                2,
                3,
                B | back(101),
                B | back(152)
            ]
        );
    }

    /// Words made in turns land in their sections' runs, the hot first.
    #[test]
    fn words_land_in_their_sections() {
        let mut a: Asm<u8> = Asm::new(vec![9], vec![9]);
        a.push(Sec::Hot, 1, 1);
        a.push(Sec::Cold, 2, 2);
        a.push(Sec::Hot, 3, 3);
        assert_eq!(a.flat(Pos { sec: Sec::Cold, k: 0 }), 2);
        assert_eq!(a.finish([0, 8], 0), (vec![1, 3, 2], vec![1, 3, 2]));
    }

    /// Each field reaches as far as its bits do, and no further.
    #[test]
    fn fields_reach_as_far_as_their_bits() {
        for (f, w, bits) in
            [(Field::Imm26, B, 26), (Field::Imm19, CBZ, 19), (Field::Imm14, TBZ, 14)]
        {
            let half = 1i64 << (bits - 1);
            assert!(f.set(w, half - 1).is_some());
            assert!(f.set(w, -half).is_some());
            assert!(f.set(w, half).is_none());
            assert!(f.set(w, -half - 1).is_none());
        }
    }

    /// A branch out of its field's reach fails loudly.
    #[test]
    #[should_panic(expected = "out of its reach")]
    fn a_branch_out_of_reach_fails() {
        let mut a: Asm<u8> = Asm::new(Vec::new(), Vec::new());
        let l = a.label();
        a.branch(Sec::Hot, TBZ, Field::Imm14, l, 0);
        for _ in 0..1 << 13 {
            a.push(Sec::Hot, 0, 0);
        }
        a.bind(l, Sec::Hot);
        a.finish([0, 0], 0);
    }
}
