//! Descriptors standing for objects of fwe's own that Linux gives an
//! anonymous inode or a pseudo-filesystem's file and that hold nothing the
//! host keeps: a namespace's descriptor ([`crate::nsfd`]), a filesystem
//! context ([`crate::mountapi`]) and a Landlock ruleset
//! ([`crate::landlock`]). Each is the read end of a pipe whose write end
//! is closed: memory only, with an identity (device and inode) of its own
//! while it is open, which [`crate::fdmarks`] and the objects' tables know
//! it by, through `dup`, `fork` and `exec`. A seek fails (`ESPIPE`), as
//! these files' do on Linux; what a read or write, `fstat`, `poll` or
//! `epoll` of one does is its object's ([`is`]).

use fwe_abi::{err, errno};

/// A new such descriptor, close-on-exec if `cloexec`.
pub fn new(cloexec: bool) -> Result<i32, i32> {
    let mut fds = [0i32; 2];
    // SAFETY: plain host call with a 2-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    // SAFETY: closing the write end just made, and setting the read end's
    // flag.
    unsafe {
        libc::close(fds[1]);
        if cloexec {
            libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok(fds[0])
}

/// Whether `fd` is such a descriptor: `poll` reports it as Linux reports
/// a file with no wait of its own (ready to read and write), and `epoll`
/// refuses it (`EPERM`), as Linux refuses a file it cannot wait on.
pub fn is(fd: i32) -> bool {
    crate::nsfd::of(fd).is_some()
        || crate::mountapi::is_context(fd)
        || crate::landlock::is_ruleset(fd)
}

/// A read, write or copy of a descriptor `is_one` says is one whose file
/// has neither: refused (`EINVAL`), as Linux refuses it. `None` for
/// another descriptor.
pub fn refuse_io(nr: u64, a: &[u64; 6], is_one: impl Fn(i32) -> bool) -> Option<i64> {
    use fwe_abi::nr as n;
    let rw = matches!(
        nr,
        n::READ
            | n::PREAD64
            | n::READV
            | n::PREADV
            | n::PREADV2
            | n::WRITE
            | n::PWRITE64
            | n::WRITEV
            | n::PWRITEV
            | n::PWRITEV2
    );
    // Copied from or to one, by `sendfile` (in, out), `splice` and
    // `copy_file_range` (in, out at 0 and 2).
    let copy = match nr {
        n::SENDFILE => is_one(a[0] as i32) || is_one(a[1] as i32),
        n::SPLICE | n::COPY_FILE_RANGE => is_one(a[0] as i32) || is_one(a[2] as i32),
        _ => false,
    };
    ((rw && is_one(a[0] as i32)) || copy).then(|| err(errno::EINVAL))
}
