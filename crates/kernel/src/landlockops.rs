//! The calls a Landlock domain restricts ([`crate::landlock`]), checked
//! before they run: what each asks of which file or directory, port or
//! process.

// `libc::stat` mode types differ by host.
#![allow(clippy::unnecessary_cast)]

use crate::landlock::{self as ll};
use crate::{Kernel, Platform, uaccess};
use fwe_abi::{errno, fcntl, nr};
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

/// What a path names, as a domain's rules see it: the identities above
/// the directory it is in and above it ([`ll::Ids`]), and its mode, if
/// anything is there.
struct Target {
    dir: ll::Ids,
    obj: ll::Ids,
    mode: Option<u32>,
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

/// Whether a datagram to the guest's address `addr` (of `len` bytes)
/// leaves the domain's abstract-socket scope (`EPERM`), as Linux's
/// `unix_may_send` hook checks every send with an address.
fn check_dest(addr: u64, len: u64) -> Result<(), i32> {
    if addr == 0 {
        return Ok(());
    }
    let Some((family, _, rest)) = sockaddr(addr, len) else { return Ok(()) };
    match crate::net::abstract_owner(rest.get(1..).unwrap_or_default()) {
        Some(owner) if family == AF_UNIX && rest.first() == Some(&0) => {
            ll::may_connect_abstract(owner)
        }
        _ => Ok(()),
    }
}

/// The address a guest `msghdr` at `hdr` names (pointer and length).
fn msg_name(hdr: u64) -> (u64, u64) {
    let name = uaccess::read::<u64>(hdr).unwrap_or(0);
    let len = uaccess::read::<u32>(hdr + 8).unwrap_or(0);
    (name, u64::from(len))
}

/// `sendto` (`addr`, `len`), `sendmsg` (`msg`, the message) or
/// `sendmmsg` (`vlen` of them at `msg`): refused if the first (or only)
/// message goes to an abstract socket outside the domain's scope
/// (`sendmmsg` past its first message: [`sendable_messages`]).
pub fn check_send(nr: u64, msg: u64, vlen: u64, addr: u64, len: u64) -> Result<(), i32> {
    match nr {
        nr::SENDTO => check_dest(addr, len),
        nr::SENDMSG => {
            let (a, l) = msg_name(msg);
            check_dest(a, l)
        }
        _ if vlen > 0 => {
            let (a, l) = msg_name(msg);
            check_dest(a, l)
        }
        _ => Ok(()),
    }
}

/// `sendmmsg` of `vlen` messages at `vec`: how many may be sent before
/// the first that goes out of the domain's abstract-socket scope (`None`
/// for all of them).
pub fn sendable_messages(vec: u64, vlen: u64) -> Option<u64> {
    // `struct mmsghdr`: a `msghdr` and the length sent, 64 bytes.
    (0..vlen.min(1024)).find(|&i| {
        let (a, l) = msg_name(vec + i * 64);
        check_dest(a, l).is_err()
    })
}

impl<P: Platform> Kernel<P> {
    /// What `path` from `dirfd` names ([`Target`]): none for a path that
    /// does not resolve, which the call itself refuses as it fails to.
    fn ll_target(&self, dirfd: u64, path: u64, follow: bool) -> Result<Option<Target>, i32> {
        let Ok(p) = uaccess::read_cstr(path, uaccess::PATH_MAX) else { return Ok(None) };
        let Some(fs) = self.fs_opt() else { return Ok(None) };
        let Ok(r) = fs.resolve(dirfd as i32, &p, follow) else { return Ok(None) };
        self.ll_resolved(&r, 0).map(Some)
    }

    /// [`Target`] of what `r` resolved to; `depth` mounts crossed on the
    /// way up so far. What resolved but cannot be placed is refused: a
    /// domain's checks are never skipped.
    fn ll_resolved(&self, r: &crate::fs::Resolved, depth: u32) -> Result<Target, i32> {
        let mode = r.lstat().map(|st| st.st_mode as u32);
        let Some(d) = &r.store else {
            let dir = crate::fs::host_path_of(r.dir.as_raw_fd()).ok_or(errno::EACCES)?;
            let obj =
                if r.name == b"." { dir.clone() } else { [&dir[..], b"/", &r.name[..]].concat() };
            return Ok(Target { dir: ll::ancestry(&dir), obj: ll::ancestry(&obj), mode });
        };
        // In fwe's store: up its directories to the mount's root, then on
        // from the directory the mount is on, as Linux's walk goes past a
        // mount point it hides.
        let dev = crate::host::dev_of(&d.host_stat(d.ino)?);
        let table = self.fs().mounts();
        let m = table.get(r.mount_id).ok_or(errno::EACCES)?;
        let top = crate::fs::StoreDir::at(d.fs.id, &m.root)?.ino;
        let mut dir = Vec::new();
        let mut at = d.ino;
        {
            let t = d.fs.lock()?;
            loop {
                dir.push((dev, at));
                if at == top {
                    break;
                }
                let up = t.lookup(at, b"..")?;
                if up == at {
                    break;
                }
                at = up;
            }
        }
        if m.point != b"/" && depth < 40 {
            // On from the mount point's nearest ancestor there is: the
            // objects a rule can be on (fwe mounts `/dev/shm` in a root
            // with no `/dev`). One outside the process's root is beyond
            // its view, as the walk ends there.
            let mut above = crate::fs::normalize(&m.point, b"..");
            while let Some(path) = self.fs().from_ns(&above) {
                match self.fs().resolve(fcntl::AT_FDCWD as i32, &path, true) {
                    Ok(r) => {
                        dir.extend(self.ll_resolved(&r, depth + 1)?.obj);
                        break;
                    }
                    Err(errno::ENOENT) if above != b"/" => {
                        above = crate::fs::normalize(&above, b"..");
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        // (Nothing there: the directory's, as a host path's ancestry has.)
        let obj = match d.find(&r.name) {
            Ok((ino, _)) if ino != d.ino => [&[(dev, ino)][..], &dir].concat(),
            _ => dir.clone(),
        };
        Ok(Target { dir, obj, mode })
    }

    /// The checks of call `n` with `a`: what a descriptor it opens is
    /// withheld.
    pub(crate) fn landlock_before(&self, n: u64, a: &[u64; 6]) -> Result<ll::Withheld, i32> {
        let none = ll::Withheld::default();
        match n {
            nr::OPENAT | nr::OPENAT2 => {
                let flags =
                    if n == nr::OPENAT2 { uaccess::read::<u64>(a[2]).unwrap_or(0) } else { a[2] };
                if flags & fcntl::O_PATH != 0 {
                    return Ok(none);
                }
                let follow = flags & fcntl::O_NOFOLLOW == 0;
                let Some(Target { dir, obj, mode }) = self.ll_target(a[0], a[1], follow)? else {
                    return Ok(none);
                };
                let acc = flags & fcntl::O_ACCMODE;
                let (read, write) = (acc != fcntl::O_WRONLY, acc != fcntl::O_RDONLY);
                match mode {
                    Some(m) if m & libc::S_IFMT as u32 == libc::S_IFDIR as u32 => {
                        ll::check(&obj, if read { ll::READ_DIR } else { 0 }, true)?;
                        Ok(none)
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
                        ll::check(&obj, need, true)?;
                        Ok(ll::withheld(&obj, write))
                    }
                    None if flags & fcntl::O_CREAT != 0 => {
                        ll::check(&dir, ll::MAKE_REG, false)?;
                        Ok(ll::withheld(&dir, write))
                    }
                    None => Ok(none),
                }
            }
            nr::MKDIRAT | nr::MKNODAT | nr::SYMLINKAT => {
                let (dirfd, path, right) = match n {
                    nr::MKDIRAT => (a[0], a[1], ll::MAKE_DIR),
                    nr::MKNODAT => (a[0], a[1], make_right(a[2] as u32)),
                    _ => (a[1], a[2], ll::MAKE_SYM),
                };
                if let Some(t) = self.ll_target(dirfd, path, false)? {
                    ll::check(&t.dir, right, false)?;
                }
                Ok(none)
            }
            nr::UNLINKAT => {
                const AT_REMOVEDIR: u64 = 0x200;
                if let Some(t) = self.ll_target(a[0], a[1], false)? {
                    let right =
                        if a[2] & AT_REMOVEDIR != 0 { ll::REMOVE_DIR } else { ll::REMOVE_FILE };
                    ll::check(&t.dir, right, false)?;
                }
                Ok(none)
            }
            nr::LINKAT => {
                let follow = a[4] & fcntl::AT_SYMLINK_FOLLOW != 0;
                let (Some(from), Some(to)) =
                    (self.ll_target(a[0], a[1], follow)?, self.ll_target(a[2], a[3], false)?)
                else {
                    return Ok(none);
                };
                ll::check_refer(&from.dir, &to.dir)?;
                let kind = from.mode.unwrap_or(libc::S_IFREG as u32);
                ll::check(&to.dir, make_right(kind), false)?;
                Ok(none)
            }
            nr::RENAMEAT | nr::RENAMEAT2 => {
                const RENAME_EXCHANGE: u64 = 2;
                let exchange = n == nr::RENAMEAT2 && a[4] & RENAME_EXCHANGE != 0;
                let (Some(from), Some(to)) =
                    (self.ll_target(a[0], a[1], false)?, self.ll_target(a[2], a[3], false)?)
                else {
                    return Ok(none);
                };
                ll::check_refer(&from.dir, &to.dir)?;
                let kind = from.mode.unwrap_or(libc::S_IFREG as u32);
                ll::check(&from.dir, remove_right(kind), false)?;
                ll::check(&to.dir, make_right(kind), false)?;
                if let Some(over) = to.mode {
                    ll::check(&to.dir, remove_right(over), false)?;
                    if exchange {
                        ll::check(&from.dir, make_right(over), false)?;
                    }
                }
                Ok(none)
            }
            nr::TRUNCATE => {
                if let Some(t) = self.ll_target(fcntl::AT_FDCWD as u64, a[0], true)? {
                    ll::check(&t.obj, ll::TRUNCATE, true)?;
                }
                Ok(none)
            }
            nr::BIND => {
                if let Some((family, port, rest)) = sockaddr(a[1], a[2]) {
                    match family {
                        AF_INET | AF_INET6 if stream(a[0] as i32) => ll::check_port(port, false)?,
                        AF_UNIX if rest.first().is_some_and(|&c| c != 0) => {
                            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                            let path = &rest[..end];
                            let r = self.fs_opt().and_then(|fs| {
                                fs.resolve(fcntl::AT_FDCWD as i32, path, false).ok()
                            });
                            if let Some(r) = r {
                                let t = self.ll_resolved(&r, 0)?;
                                ll::check(&t.dir, ll::MAKE_SOCK, false)?;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(none)
            }
            nr::KILL | nr::RT_SIGQUEUEINFO | nr::TGKILL | nr::RT_TGSIGQUEUEINFO => {
                let pid = a[0] as i32;
                if pid > 0
                    && let Some(host) = crate::pidns::to_host(pid)
                {
                    ll::may_signal(host)?;
                }
                Ok(none)
            }
            nr::TKILL => {
                let tid = a[0] as i32;
                if let Some(owner) =
                    crate::thread::named(tid).map(|(_, p)| p).or_else(|| crate::pidns::to_host(tid))
                {
                    ll::may_signal(owner)?;
                }
                Ok(none)
            }
            // A domain that restricts the file system may not change what
            // its paths reach (Linux's `sb_mount`, `move_mount`,
            // `sb_umount` and `sb_pivotroot` hooks).
            nr::MOUNT | nr::UMOUNT2 | nr::PIVOT_ROOT | nr::MOVE_MOUNT if ll::handles_fs() => {
                Err(errno::EPERM)
            }
            nr::PIDFD_SEND_SIGNAL => {
                if let Some(t) = crate::pidfd::of(a[0] as i32) {
                    ll::may_signal(t.host)?;
                }
                Ok(none)
            }
            _ => Ok(none),
        }
    }

    /// `EXECUTE` of the program at guest path `path`.
    pub(crate) fn landlock_exec(&self, path: &[u8]) -> Result<(), i32> {
        let Some(fs) = self.fs_opt() else { return Ok(()) };
        let Ok(r) = fs.resolve(fcntl::AT_FDCWD as i32, path, true) else { return Ok(()) };
        ll::check(&self.ll_resolved(&r, 0)?.obj, ll::EXECUTE, true)
    }
}
