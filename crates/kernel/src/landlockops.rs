//! The calls a Landlock domain restricts ([`crate::landlock`]), checked
//! before they run: what each asks of which file or directory, port or
//! process.

// `libc::stat` mode types differ by host.
#![allow(clippy::unnecessary_cast)]

use crate::landlock::{self as ll};
use crate::{Kernel, Platform, uaccess};
use fwe_abi::{fcntl, nr};
use std::os::fd::AsRawFd;

/// `MAKE_*` for a file of mode `mode`'s kind.
fn make_right(mode: u32) -> u64 {
    match mode & libc::S_IFMT as u32 {
        m if m == libc::S_IFDIR as u32 => ll::MAKE_DIR,
        m if m == libc::S_IFCHR as u32 => ll::MAKE_CHAR,
        m if m == libc::S_IFBLK as u32 => ll::MAKE_BLOCK,
        m if m == libc::S_IFIFO as u32 => ll::MAKE_FIFO,
        m if m == libc::S_IFSOCK as u32 => ll::MAKE_SOCK,
        m if m == libc::S_IFLNK as u32 => ll::MAKE_SYM,
        _ => ll::MAKE_REG,
    }
}

/// `REMOVE_*` for a file of mode `mode`'s kind.
fn remove_right(mode: u32) -> u64 {
    if mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32 {
        ll::REMOVE_DIR
    } else {
        ll::REMOVE_FILE
    }
}

/// The host mode of what is at host path `path` (following a final link
/// if `follow`), if anything is.
fn host_mode(path: &[u8], follow: bool) -> Option<u32> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: an all-zero `stat` is a valid out-parameter; a NUL-terminated
    // path.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let r = unsafe {
        if follow { libc::stat(c.as_ptr(), &mut st) } else { libc::lstat(c.as_ptr(), &mut st) }
    };
    (r == 0).then_some(st.st_mode as u32)
}

/// A guest `sockaddr`'s family and its port (an inet one) or path bytes
/// (a Unix one).
fn sockaddr(addr: u64, len: u64) -> Option<(u16, u16, Vec<u8>)> {
    let len = len.min(110) as usize;
    // (An abstract name runs to the address's length.)
    if len < 2 {
        return None;
    }
    let b = uaccess::read_bytes(addr, len).ok()?;
    let family = u16::from_ne_bytes([b[0], b[1]]);
    let port = if len >= 4 { u16::from_be_bytes([b[2], b[3]]) } else { 0 };
    Some((family, port, b[2..].to_vec()))
}

fn stream(fd: i32) -> bool {
    let mut ty: libc::c_int = 0;
    let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a valid out-parameter of its length.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut l,
        )
    };
    ty == libc::SOCK_STREAM
}

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// A `connect` of socket `fd` to the guest's address: a TCP port, or an
/// abstract socket bound by another process, the domain allows.
pub fn check_connect(fd: i32, addr: u64, len: u64) -> Result<(), i32> {
    let Some((family, port, rest)) = sockaddr(addr, len) else { return Ok(()) };
    match family {
        AF_INET | AF_INET6 if stream(fd) => ll::check_port(port, true),
        AF_UNIX if rest.first() == Some(&0) => match crate::net::abstract_owner(&rest[1..]) {
            Some(owner) => ll::may_connect_abstract(owner),
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

impl<P: Platform> Kernel<P> {
    /// The host paths of what `path` from `dirfd` names and of the
    /// directory it is in.
    fn ll_target(&self, dirfd: u64, path: u64, follow: bool) -> Option<(Vec<u8>, Vec<u8>)> {
        let p = uaccess::read_cstr(path, uaccess::PATH_MAX).ok()?;
        let r = self.fs.as_ref()?.resolve(dirfd as i32, &p, follow).ok()?;
        let dir = crate::fs::host_path_of(r.dir.as_raw_fd())?;
        let obj = if r.name == b"." { dir.clone() } else { [&dir[..], b"/", &r.name[..]].concat() };
        Some((dir, obj))
    }

    /// The checks of call `n` with `a`: whether a descriptor it opens is
    /// one that may not truncate its file.
    pub(crate) fn landlock_before(&self, n: u64, a: &[u64; 6]) -> Result<bool, i32> {
        match n {
            nr::OPENAT | nr::OPENAT2 => {
                let flags =
                    if n == nr::OPENAT2 { uaccess::read::<u64>(a[2]).unwrap_or(0) } else { a[2] };
                if flags & fcntl::O_PATH != 0 {
                    return Ok(false);
                }
                let follow = flags & fcntl::O_NOFOLLOW == 0;
                let Some((dir, obj)) = self.ll_target(a[0], a[1], follow) else { return Ok(false) };
                let acc = flags & fcntl::O_ACCMODE;
                let (read, write) = (acc != fcntl::O_WRONLY, acc != fcntl::O_RDONLY);
                match host_mode(&obj, follow) {
                    Some(m) if m & libc::S_IFMT as u32 == libc::S_IFDIR as u32 => {
                        ll::check_path(&obj, if read { ll::READ_DIR } else { 0 }, true)?;
                        Ok(false)
                    }
                    Some(_) => {
                        let mut need = 0;
                        if read {
                            need |= ll::READ_FILE;
                        }
                        if write {
                            need |= ll::WRITE_FILE;
                        }
                        if write && flags & fcntl::O_TRUNC != 0 {
                            need |= ll::TRUNCATE;
                        }
                        ll::check_path(&obj, need, true)?;
                        Ok(write && ll::truncate_denied(&obj))
                    }
                    None if flags & fcntl::O_CREAT != 0 => {
                        ll::check_path(&dir, ll::MAKE_REG, false)?;
                        Ok(write && ll::truncate_denied(&dir))
                    }
                    None => Ok(false),
                }
            }
            nr::MKDIRAT | nr::MKNODAT | nr::SYMLINKAT => {
                let (dirfd, path, right) = match n {
                    nr::MKDIRAT => (a[0], a[1], ll::MAKE_DIR),
                    nr::MKNODAT => (a[0], a[1], make_right(a[2] as u32)),
                    _ => (a[1], a[2], ll::MAKE_SYM),
                };
                if let Some((dir, _)) = self.ll_target(dirfd, path, false) {
                    ll::check_path(&dir, right, false)?;
                }
                Ok(false)
            }
            nr::UNLINKAT => {
                const AT_REMOVEDIR: u64 = 0x200;
                if let Some((dir, _)) = self.ll_target(a[0], a[1], false) {
                    let right =
                        if a[2] & AT_REMOVEDIR != 0 { ll::REMOVE_DIR } else { ll::REMOVE_FILE };
                    ll::check_path(&dir, right, false)?;
                }
                Ok(false)
            }
            nr::LINKAT => {
                let follow = a[4] & fcntl::AT_SYMLINK_FOLLOW != 0;
                let (Some((from_dir, from)), Some((to_dir, _))) =
                    (self.ll_target(a[0], a[1], follow), self.ll_target(a[2], a[3], false))
                else {
                    return Ok(false);
                };
                ll::check_refer(&from_dir, &to_dir)?;
                let kind = host_mode(&from, follow).unwrap_or(libc::S_IFREG as u32);
                ll::check_path(&to_dir, make_right(kind), false)?;
                Ok(false)
            }
            nr::RENAMEAT | nr::RENAMEAT2 => {
                const RENAME_EXCHANGE: u64 = 2;
                let exchange = n == nr::RENAMEAT2 && a[4] & RENAME_EXCHANGE != 0;
                let (Some((from_dir, from)), Some((to_dir, to))) =
                    (self.ll_target(a[0], a[1], false), self.ll_target(a[2], a[3], false))
                else {
                    return Ok(false);
                };
                ll::check_refer(&from_dir, &to_dir)?;
                let kind = host_mode(&from, false).unwrap_or(libc::S_IFREG as u32);
                ll::check_path(&from_dir, remove_right(kind), false)?;
                ll::check_path(&to_dir, make_right(kind), false)?;
                if let Some(over) = host_mode(&to, false) {
                    ll::check_path(&to_dir, remove_right(over), false)?;
                    if exchange {
                        ll::check_path(&from_dir, make_right(over), false)?;
                    }
                }
                Ok(false)
            }
            nr::TRUNCATE => {
                if let Some((_, obj)) = self.ll_target(fcntl::AT_FDCWD as u64, a[0], true) {
                    ll::check_path(&obj, ll::TRUNCATE, true)?;
                }
                Ok(false)
            }
            nr::FTRUNCATE => ll::may_ftruncate(a[0] as i32).map(|()| false),
            nr::BIND => {
                if let Some((family, port, rest)) = sockaddr(a[1], a[2]) {
                    match family {
                        AF_INET | AF_INET6 if stream(a[0] as i32) => ll::check_port(port, false)?,
                        AF_UNIX if rest.first().is_some_and(|&c| c != 0) => {
                            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                            let path = &rest[..end];
                            let p = self.fs.as_ref().and_then(|fs| {
                                let r = fs.resolve(fcntl::AT_FDCWD as i32, path, false).ok()?;
                                crate::fs::host_path_of(r.dir.as_raw_fd())
                            });
                            if let Some(dir) = p {
                                ll::check_path(&dir, ll::MAKE_SOCK, false)?;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(false)
            }
            nr::KILL | nr::RT_SIGQUEUEINFO | nr::TGKILL | nr::RT_TGSIGQUEUEINFO => {
                let pid = a[0] as i32;
                if pid > 0
                    && let Some(host) = crate::pidns::to_host(pid)
                {
                    ll::may_signal(host)?;
                }
                Ok(false)
            }
            nr::TKILL => {
                let tid = a[0] as i32;
                if let Some(owner) = crate::thread::owner_of_tid(tid) {
                    ll::may_signal(owner)?;
                } else if let Some(host) = crate::pidns::to_host(tid) {
                    ll::may_signal(host)?;
                }
                Ok(false)
            }
            nr::PIDFD_SEND_SIGNAL => {
                if let Some(t) = crate::pidfd::of(a[0] as i32) {
                    ll::may_signal(t.host)?;
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// `EXECUTE` of the program at guest path `path`.
    pub(crate) fn landlock_exec(&self, path: &[u8]) -> Result<(), i32> {
        let Some(fs) = self.fs.as_ref() else { return Ok(()) };
        let Ok(r) = fs.resolve(fcntl::AT_FDCWD as i32, path, true) else { return Ok(()) };
        let Some(dir) = crate::fs::host_path_of(r.dir.as_raw_fd()) else { return Ok(()) };
        ll::check_path(&[&dir[..], b"/", &r.name[..]].concat(), ll::EXECUTE, true)
    }
}
