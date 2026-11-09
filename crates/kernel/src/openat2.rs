//! `openat2(dirfd, path, how, size)`: `openat` with its flags and mode in a
//! `struct open_how`, checked strictly, and a `resolve` set that limits how
//! the path is walked:
//!
//! - `RESOLVE_NO_SYMLINKS`: no symbolic link on the way (`ELOOP`);
//! - `RESOLVE_NO_MAGICLINKS`: none of `/proc`'s links to open files and
//!   places (`exe`, `cwd`, `root`, `fd/<n>`, `ns/<kind>`: `ELOOP`);
//! - `RESOLVE_NO_XDEV`: no mount crossed (`EXDEV`);
//! - `RESOLVE_BENEATH`: nothing above `dirfd`, by `..`, an absolute path or
//!   a link (`EXDEV`);
//! - `RESOLVE_IN_ROOT`: `dirfd` taken for the root, `..` stopping there and
//!   absolute paths and links starting there;
//! - `RESOLVE_CACHED`: Linux's lookup from its caches alone, which fwe's
//!   lookups always are, but never for a call that creates or truncates
//!   (`EAGAIN`).
//!
//! The path is walked here, one component at a time, each link read and
//! its target walked in its place, and the place it leads to opened as
//! `openat` would.

use crate::fsops::LinkKind;
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{err, errno, fcntl};
use std::collections::VecDeque;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const RESOLVE_ALL: u64 = 0x3f;

/// `struct open_how`'s first size: `flags`, `mode`, `resolve`.
const OPEN_HOW_SIZE_VER0: u64 = 24;
/// The links a walk follows before giving up (`ELOOP`), as Linux's.
const MAX_LINKS: u32 = 40;

/// The open flags Linux knows (`VALID_OPEN_FLAGS`).
const VALID_OPEN_FLAGS: u64 = fcntl::O_ACCMODE
    | fcntl::O_CREAT
    | fcntl::O_EXCL
    | fcntl::O_NOCTTY
    | fcntl::O_TRUNC
    | fcntl::O_APPEND
    | fcntl::O_NONBLOCK
    | fcntl::O_DSYNC
    | fcntl::O_ASYNC
    | fcntl::O_DIRECTORY
    | fcntl::O_NOFOLLOW
    | fcntl::O_DIRECT
    | fcntl::O_LARGEFILE
    | fcntl::O_NOATIME
    | fcntl::O_CLOEXEC
    | fcntl::O_SYNC
    | fcntl::O_PATH
    | fcntl::O_TMPFILE;
/// What `O_PATH` may come with.
const O_PATH_FLAGS: u64 = fcntl::O_DIRECTORY | fcntl::O_NOFOLLOW | fcntl::O_PATH | fcntl::O_CLOEXEC;

impl<P: Platform> Kernel<P> {
    pub(crate) fn sys_openat2(&mut self, dirfd: u64, path: u64, how: u64, size: u64) -> i64 {
        if size < OPEN_HOW_SIZE_VER0 {
            return err(errno::EINVAL);
        }
        if size > 4096 {
            return err(errno::E2BIG);
        }
        let raw = guest!(uaccess::read_bytes(how, size as usize));
        // A newer structure is fine as long as what fwe does not know is 0.
        if raw[OPEN_HOW_SIZE_VER0 as usize..].iter().any(|&b| b != 0) {
            return err(errno::E2BIG);
        }
        let word = |i: usize| u64::from_ne_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        let (flags, mode, resolve) = (word(0), word(1), word(2));
        let creates = flags & fcntl::O_CREAT != 0 || flags & fcntl::O_TMPFILE == fcntl::O_TMPFILE;
        if flags & !VALID_OPEN_FLAGS != 0
            || resolve & !RESOLVE_ALL != 0
            || (resolve & RESOLVE_BENEATH != 0 && resolve & RESOLVE_IN_ROOT != 0)
            || (creates && mode & !0o7777 != 0)
            || (!creates && mode != 0)
            || (flags & fcntl::O_PATH != 0 && flags & !O_PATH_FLAGS != 0)
        {
            return err(errno::EINVAL);
        }
        if resolve & RESOLVE_CACHED != 0 && (creates || flags & fcntl::O_TRUNC != 0) {
            return err(errno::EAGAIN);
        }
        let path = match uaccess::read_cstr(path, uaccess::PATH_MAX) {
            Ok(p) => p,
            Err(e) => {
                crate::fs::drop_fifo();
                return err(e);
            }
        };
        if resolve & !RESOLVE_CACHED == 0 {
            return self.open_with(dirfd, path, flags, mode);
        }
        match self.walk(dirfd as i32, &path, resolve, flags) {
            Ok(place) => self.open_with(fcntl::AT_FDCWD as u64, place, flags, mode),
            Err(e) => {
                crate::fs::drop_fifo();
                err(e)
            }
        }
    }

    /// Walk `path` from `dirfd` as `resolve` allows: the absolute path it
    /// leads to.
    fn walk(&self, dirfd: i32, path: &[u8], resolve: u64, flags: u64) -> Result<Vec<u8>, i32> {
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let fs = self.fs();
        let base = if dirfd == fcntl::AT_FDCWD as i32 || path.starts_with(b"/") {
            fs.absolute_path(dirfd, b".")
        } else {
            // A directory, to walk from.
            let st = crate::fsops::linux_fstat(dirfd)?;
            if st.st_mode & fwe_abi::stat::S_IFMT != fwe_abi::stat::S_IFDIR {
                return Err(errno::ENOTDIR);
            }
            fs.absolute_path(dirfd, b".")
        }
        .ok_or(errno::EBADF)?;
        let beneath = resolve & RESOLVE_BENEATH != 0;
        let in_root = resolve & RESOLVE_IN_ROOT != 0;
        // Where `..` stops: `dirfd`'s directory for either, else `/`.
        let floor = if beneath || in_root { base.clone() } else { b"/".to_vec() };
        let start_mount = fs.mount_of(&base).0.id;
        let crossed =
            |at: &[u8]| resolve & RESOLVE_NO_XDEV != 0 && fs.mount_of(at).0.id != start_mount;
        let mut at = base.clone();
        let mut todo: VecDeque<Vec<u8>> = VecDeque::new();
        let mut links = 0;
        let start = |at: &mut Vec<u8>, p: &[u8], todo: &mut VecDeque<Vec<u8>>| -> Result<(), i32> {
            if p.starts_with(b"/") {
                if beneath {
                    return Err(errno::EXDEV);
                }
                *at = if in_root { floor.clone() } else { b"/".to_vec() };
                if crossed(at) {
                    return Err(errno::EXDEV);
                }
            }
            for c in p.split(|&b| b == b'/').rev().filter(|c| !c.is_empty()) {
                todo.push_front(c.to_vec());
            }
            Ok(())
        };
        start(&mut at, path, &mut todo)?;
        let follow_last = flags & fcntl::O_NOFOLLOW == 0;
        while let Some(c) = todo.pop_front() {
            match &c[..] {
                b"." => continue,
                b".." => {
                    if at == floor {
                        if beneath {
                            return Err(errno::EXDEV);
                        }
                        // In the root, or at `/`: it stays.
                        continue;
                    }
                    at = crate::fs::normalize(&at, b"..");
                }
                name => {
                    let next = crate::mounts::join(&at, name);
                    let last = todo.is_empty();
                    if last && !follow_last {
                        at = next;
                    } else {
                        match self.link_kind(&next) {
                            Ok(LinkKind::Magic)
                                if resolve
                                    & (RESOLVE_NO_MAGICLINKS
                                        | RESOLVE_NO_SYMLINKS
                                        | RESOLVE_BENEATH
                                        | RESOLVE_IN_ROOT)
                                    != 0 =>
                            {
                                return Err(errno::ELOOP);
                            }
                            // A link to an open file or a place, which only
                            // opening it follows: the rest goes from there.
                            Ok(LinkKind::Magic) => {
                                if resolve & RESOLVE_NO_XDEV != 0 {
                                    return Err(errno::EXDEV);
                                }
                                let rest: Vec<Vec<u8>> = todo.drain(..).collect();
                                return Ok(rest
                                    .iter()
                                    .fold(next, |p, c| crate::mounts::join(&p, c)));
                            }
                            Ok(LinkKind::Symlink(_)) if resolve & RESOLVE_NO_SYMLINKS != 0 => {
                                return Err(errno::ELOOP);
                            }
                            Ok(LinkKind::Symlink(target)) => {
                                links += 1;
                                if links > MAX_LINKS {
                                    return Err(errno::ELOOP);
                                }
                                start(&mut at, &target, &mut todo)?;
                                continue;
                            }
                            Ok(LinkKind::None) => at = next,
                            // To be made, by the open.
                            Err(errno::ENOENT) if last => at = next,
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            if crossed(&at) {
                return Err(errno::EXDEV);
            }
        }
        Ok(at)
    }
}
