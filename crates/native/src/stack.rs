//! The initial process stack: argc, argv, envp, the auxiliary vector and the
//! strings they point to, laid out as the Linux kernel does at `execve`.

use fwe_abi::auxv;

/// Inputs for the initial stack.
pub struct InitialStack<'a> {
    pub args: &'a [&'a [u8]],
    pub env: &'a [&'a [u8]],
    /// Path of the executed file (`AT_EXECFN`).
    pub execfn: &'a [u8],
    /// Auxiliary vector entries. `AT_RANDOM`, `AT_EXECFN`, `AT_PLATFORM` and
    /// `AT_NULL` are added by [`InitialStack::build`].
    pub auxv: &'a [(u64, u64)],
    /// The 16 bytes `AT_RANDOM` points to.
    pub random: [u8; 16],
}

/// A built stack image to be copied to `[sp, top)`.
pub struct StackImage {
    pub sp: u64,
    pub bytes: Vec<u8>,
    /// The auxiliary vector's words, `AT_NULL` included, as
    /// `/proc/self/auxv` shows them.
    pub auxv: Vec<u8>,
}

const PLATFORM: &[u8] = b"aarch64";

impl InitialStack<'_> {
    /// Lay out the stack so that it ends at `top` (exclusive).
    pub fn build(&self, top: u64) -> StackImage {
        assert_eq!(top % 16, 0);
        let strings_len: usize =
            self.args.iter().chain(self.env).map(|s| s.len() + 1).sum::<usize>()
                + self.execfn.len()
                + 1
                + PLATFORM.len()
                + 1
                + self.random.len()
                + 8; // Trailing zero word, as Linux leaves at the very top.
        let strings_start = (top - strings_len as u64) & !15;

        let auxv_len = self.auxv.len() + 4; // RANDOM, EXECFN, PLATFORM, NULL
        let words = 1 + (self.args.len() + 1) + (self.env.len() + 1) + 2 * auxv_len;
        let sp = (strings_start - 8 * words as u64) & !15;

        let mut bytes = vec![0u8; (top - sp) as usize];
        let mut cursor = strings_start;
        let mut put = |bytes: &mut Vec<u8>, data: &[u8], nul: bool| -> u64 {
            let at = cursor;
            let o = (at - sp) as usize;
            bytes[o..o + data.len()].copy_from_slice(data);
            cursor += data.len() as u64 + nul as u64;
            at
        };

        let random = put(&mut bytes, &self.random, false);
        let platform = put(&mut bytes, PLATFORM, true);
        let args: Vec<u64> = self.args.iter().map(|s| put(&mut bytes, s, true)).collect();
        let env: Vec<u64> = self.env.iter().map(|s| put(&mut bytes, s, true)).collect();
        let execfn = put(&mut bytes, self.execfn, true);
        debug_assert!(cursor <= top - 8);

        let mut table: Vec<u64> = Vec::with_capacity(words);
        table.push(self.args.len() as u64);
        table.extend(&args);
        table.push(0);
        table.extend(&env);
        table.push(0);
        for &(k, v) in self.auxv {
            table.extend([k, v]);
        }
        table.extend([auxv::AT_RANDOM, random]);
        table.extend([auxv::AT_EXECFN, execfn]);
        table.extend([auxv::AT_PLATFORM, platform]);
        table.extend([auxv::AT_NULL, 0]);
        debug_assert_eq!(table.len(), words);
        for (i, w) in table.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let first = words - 2 * auxv_len;
        let auxv = table[first..].iter().flat_map(|w| w.to_le_bytes()).collect();
        StackImage { sp, bytes, auxv }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(img: &StackImage, addr: u64) -> u64 {
        let o = (addr - img.sp) as usize;
        u64::from_le_bytes(img.bytes[o..o + 8].try_into().unwrap())
    }

    fn cstr(img: &StackImage, addr: u64) -> &[u8] {
        let o = (addr - img.sp) as usize;
        let end = img.bytes[o..].iter().position(|&b| b == 0).unwrap();
        &img.bytes[o..o + end]
    }

    #[test]
    fn layout_matches_linux() {
        let top = 0x7fff_0000;
        let stack = InitialStack {
            args: &[b"/bin/prog", b"hello"],
            env: &[b"A=1"],
            execfn: b"/bin/prog",
            auxv: &[(auxv::AT_PAGESZ, 16384)],
            random: [7; 16],
        };
        let img = stack.build(top);
        assert_eq!(img.sp % 16, 0);
        assert_eq!(img.sp + img.bytes.len() as u64, top);

        let mut p = img.sp;
        let mut next = || {
            let w = word(&img, p);
            p += 8;
            w
        };
        assert_eq!(next(), 2);
        assert_eq!(cstr(&img, next()), b"/bin/prog");
        assert_eq!(cstr(&img, next()), b"hello");
        assert_eq!(next(), 0);
        assert_eq!(cstr(&img, next()), b"A=1");
        assert_eq!(next(), 0);
        assert_eq!((next(), next()), (auxv::AT_PAGESZ, 16384));
        assert_eq!(next(), auxv::AT_RANDOM);
        let random = next();
        assert_eq!(&img.bytes[(random - img.sp) as usize..][..16], &[7; 16]);
        assert_eq!(next(), auxv::AT_EXECFN);
        assert_eq!(cstr(&img, next()), b"/bin/prog");
        assert_eq!(next(), auxv::AT_PLATFORM);
        assert_eq!(cstr(&img, next()), b"aarch64");
        assert_eq!((next(), next()), (auxv::AT_NULL, 0));
    }
}
