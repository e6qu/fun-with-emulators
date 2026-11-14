//! The System V IPC system calls, on the objects of [`crate::sysvipc`]: in
//! Linux's order of checks, with its errors.

use crate::shared::Record;
use crate::sysvipc::{self as ipc, Body, Ipc, Kind, Obj, Perm};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::{err, errno};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What a get's flags ask of an existing object: Linux's
/// `(flag >> 6) | (flag >> 3) | flag`, the `rwx` bits.
fn wanted(flags: u64) -> u32 {
    (((flags >> 6) | (flags >> 3) | flags) & 7) as u32
}

/// The outcome of one try of an operation that may have to wait.
enum Try<T> {
    Done(T),
    Wait,
}

/// `semop`'s and `msgsnd`'s and `msgrcv`'s deadline from a relative
/// timeout at guest `timeout` (none if 0).
fn deadline(timeout: u64) -> uaccess::Result<Option<Instant>> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts: fwe_abi::Timespec = uaccess::read(timeout)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(errno::EINVAL);
    }
    Ok(Some(Instant::now() + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)))
}

impl<P: Platform> Kernel<P> {
    /// What a waiting IPC call needs ([`blocking`]).
    pub fn ipc_context(&self) -> Result<IpcContext, i32> {
        Ok(IpcContext { record: self.ipc_table()?, creds: self.creds.clone() })
    }

    /// The calling process's IPC namespace's objects.
    fn ipc_table(&self) -> Result<Arc<Record<Ipc>>, i32> {
        let r = self.fs().ns.ipc.clone().or_else(ipc::initial).ok_or(errno::ENOMEM)?;
        ipc::set_current(&r);
        Ok(r)
    }

    fn new_perm(&self, flags: u64) -> Perm {
        let c = &self.creds;
        Perm { uid: c.euid, gid: c.egid, cuid: c.euid, cgid: c.egid, mode: (flags & 0o777) as u32 }
    }

    /// The common part of the three `*get` calls: the object of `kind` with
    /// `key`, checked by `more` (a size or count it must have) and the
    /// caller's permission, or a new one `make` describes.
    fn ipc_get(
        &mut self,
        kind: Kind,
        key: i32,
        flags: u64,
        limit: fn(&Ipc) -> usize,
        more: impl Fn(&Obj) -> Result<(), i32>,
        make: impl FnOnce(&Ipc) -> Result<Body, i32>,
    ) -> i64 {
        let r = match self.ipc_table() {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let perm = self.new_perm(flags);
        let creds = self.creds.clone();
        let made = r.update_maybe(|t| {
            let reaped = t.reap(&r);
            if key != ipc::IPC_PRIVATE
                && let Some(id) = t.by_key(kind, key)
            {
                if flags & ipc::IPC_CREAT != 0 && flags & ipc::IPC_EXCL != 0 {
                    return Err(errno::EEXIST);
                }
                let o = t.get(kind, id)?;
                more(o)?;
                if !ipc::permits(&creds, &o.perm, wanted(flags)) {
                    return Err(errno::EACCES);
                }
                return Ok(((id, false), reaped));
            }
            if key != ipc::IPC_PRIVATE && flags & ipc::IPC_CREAT == 0 {
                return Err(errno::ENOENT);
            }
            let body = make(t)?;
            let id = t.create(kind, key, perm, body, limit(t))?;
            Ok(((id, true), true))
        });
        match made {
            Ok((id, true)) if kind == Kind::Shm => {
                // The segment's memory: a file of its size beside the record.
                let size = match r.get().objs.get(&(Kind::Shm as u8, id)).map(|o| o.body.clone()) {
                    Some(Body::Shm(s)) => s.size,
                    _ => 0,
                };
                if let Err(e) = make_segment(&r, id, size) {
                    let _ = r.update(|t| {
                        t.objs.remove(&(Kind::Shm as u8, id));
                        Ok(())
                    });
                    return err(e);
                }
                id as i64
            }
            Ok((id, _)) => id as i64,
            Err(e) => err(e),
        }
    }

    pub(crate) fn sys_shmget(&mut self, key: u64, size: u64, flags: u64) -> i64 {
        let me = crate::host::pid();
        self.ipc_get(
            Kind::Shm,
            key as i32,
            flags,
            |t| t.shmmni() as usize,
            |o| match &o.body {
                Body::Shm(s) if size > s.size => Err(errno::EINVAL),
                _ => Ok(()),
            },
            |t| {
                // Huge pages: fwe has no hugetlbfs (nor says so in its
                // config), which Linux without one refuses so.
                if flags & ipc::SHM_HUGETLB != 0 || !(ipc::SHMMIN..=t.shmmax()).contains(&size) {
                    return Err(errno::EINVAL);
                }
                // `kernel.shmall`: the pages of every segment together.
                let pages: u64 = t
                    .objs
                    .values()
                    .filter_map(|o| match &o.body {
                        Body::Shm(s) => Some(s.size.div_ceil(4096)),
                        _ => None,
                    })
                    .sum();
                if pages.saturating_add(size.div_ceil(4096)) > t.shmall() {
                    return Err(errno::ENOSPC);
                }
                Ok(Body::Shm(ipc::Shm { size, cpid: me, ..ipc::Shm::default() }))
            },
        )
    }

    pub(crate) fn sys_semget(&mut self, key: u64, nsems: u64, flags: u64) -> i64 {
        let n = nsems as i32;
        let semmsl = match self.ipc_table() {
            Ok(r) => r.get().sem()[0],
            Err(e) => return err(e),
        };
        if n < 0 || n > semmsl {
            return err(errno::EINVAL);
        }
        self.ipc_get(
            Kind::Sem,
            key as i32,
            flags,
            |t| t.sem()[3].max(0) as usize,
            |o| match &o.body {
                Body::Sem(s) if n as usize > s.vals.len() => Err(errno::EINVAL),
                _ => Ok(()),
            },
            |t| {
                if n == 0 {
                    return Err(errno::EINVAL);
                }
                // `kernel.sem`'s second: the semaphores of every set together.
                let all: usize = t
                    .objs
                    .values()
                    .filter_map(|o| match &o.body {
                        Body::Sem(s) => Some(s.vals.len()),
                        _ => None,
                    })
                    .sum();
                if all + n as usize > t.sem()[1].max(0) as usize {
                    return Err(errno::ENOSPC);
                }
                Ok(Body::Sem(ipc::Sem { vals: vec![(0, 0); n as usize], ..ipc::Sem::default() }))
            },
        )
    }

    pub(crate) fn sys_msgget(&mut self, key: u64, flags: u64) -> i64 {
        self.ipc_get(
            Kind::Msg,
            key as i32,
            flags,
            |t| t.msgmni() as usize,
            |_| Ok(()),
            |t| Ok(Body::Msg(ipc::Msg { qbytes: t.msgmnb(), ..ipc::Msg::default() })),
        )
    }

    /// `shmat(id, addr, flags)`: the segment's file mapped shared, at
    /// `addr` (rounded down to `SHMLBA` with `SHM_RND`) or where fwe places
    /// it.
    pub(crate) fn sys_shmat(&mut self, id: u64, addr: u64, flags: u64) -> i64 {
        let id = id as i32;
        let r = match self.ipc_table() {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let t = r.get();
        let Some(o) = t.objs.get(&(Kind::Shm as u8, id)).filter(|_| id >= 0) else {
            return err(errno::EINVAL);
        };
        let Body::Shm(s) = &o.body else { return err(errno::EINVAL) };
        let mut want = 4;
        let mut prot = fwe_abi::mman::PROT_READ;
        if flags & ipc::SHM_RDONLY == 0 {
            want |= 2;
            prot |= fwe_abi::mman::PROT_WRITE;
        }
        if flags & ipc::SHM_EXEC != 0 {
            want |= 1;
            prot |= fwe_abi::mman::PROT_EXEC;
        }
        if !ipc::permits(&self.creds, &o.perm, want) {
            return err(errno::EACCES);
        }
        let size = (s.size + self.page_size - 1) & !(self.page_size - 1);
        let key = o.key;
        drop(t);
        let mut at = addr;
        if at & (ipc::SHMLBA - 1) != 0 {
            if flags & ipc::SHM_RND == 0 {
                return err(errno::EINVAL);
            }
            at &= !(ipc::SHMLBA - 1);
        }
        let mut map = fwe_abi::mman::MAP_SHARED;
        if at != 0 {
            if flags & ipc::SHM_REMAP == 0 && crate::mm::any_mapped(at, size) {
                return err(errno::EINVAL);
            }
            map |= fwe_abi::mman::MAP_FIXED;
        } else if flags & ipc::SHM_REMAP != 0 {
            return err(errno::EINVAL);
        }
        let Ok(path) = std::ffi::CString::new(ipc::segment_path(&r, id)) else {
            return err(errno::EINVAL);
        };
        let access = if flags & ipc::SHM_RDONLY != 0 { libc::O_RDONLY } else { libc::O_RDWR };
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe { libc::open(path.as_ptr(), access | libc::O_CLOEXEC) };
        if fd < 0 {
            // Removed meanwhile.
            return err(errno::EIDRM);
        }
        let fd = match crate::fdtable::reserve(fd) {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        let mapped = self.sys_mmap(at, size, prot, map, fd as u64, 0);
        // SAFETY: fwe's own descriptor; the mapping holds the file.
        unsafe { libc::close(fd) };
        if mapped < 0 {
            return mapped;
        }
        // Listed as Linux lists a segment: a deleted file of the shared
        // memory filesystem's, named by its key, whose inode is its id.
        crate::maps::record().rename(
            mapped as u64,
            size,
            crate::maps::Object {
                name: crate::maps::Name::Path(
                    format!("/SYSV{key:08x} (deleted)").into_bytes().into(),
                ),
                dev: crate::devnodes::makedev(0, 1),
                ino: id as u64,
                offset: 0,
            },
        );
        crate::maps::publish();
        let me = ipc::me();
        ipc::note_attached(mapped as u64, id, size);
        let _ = r.update(|t| {
            ipc::attach_count(t, id, me, 1);
            if let Some(Obj { body: Body::Shm(s), .. }) = t.objs.get_mut(&(Kind::Shm as u8, id)) {
                s.atime = now();
                s.lpid = me.0;
            }
            Ok(())
        });
        mapped
    }

    /// `shmdt(addr)`: the attachment at `addr` goes, and a segment marked
    /// for removal with it if it was its last.
    pub(crate) fn sys_shmdt(&mut self, addr: u64) -> i64 {
        let Some((id, size)) = ipc::attached(addr) else { return err(errno::EINVAL) };
        let r = match self.ipc_table() {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let unmapped = self.sys_munmap(addr, size);
        if unmapped < 0 {
            return unmapped;
        }
        ipc::note_detached(addr);
        let me = ipc::me();
        let _ = r.update(|t| {
            ipc::attach_count(t, id, me, -1);
            if let Some(Obj { body: Body::Shm(s), .. }) = t.objs.get_mut(&(Kind::Shm as u8, id)) {
                s.dtime = now();
                s.lpid = me.0;
            }
            t.reap(&r);
            Ok(())
        });
        0
    }

    /// The `*_STAT`, `IPC_STAT`, `IPC_SET` and `IPC_RMID` part of the three
    /// `*ctl` calls. `ds` makes the structure `*_STAT` writes; `set` takes
    /// what `IPC_SET` gives (`buf`'s bytes) into the object; `rmid`
    /// removes it (or marks it).
    #[allow(clippy::too_many_arguments)]
    fn ipc_ctl_common(
        &mut self,
        kind: Kind,
        id: i32,
        cmd: u64,
        buf: u64,
        stat: (u64, u64),
        ds: fn(&Obj, i32) -> Vec<u8>,
        set_len: usize,
        set: impl FnOnce(&mut Obj, &[u8], &crate::creds::Creds) -> Result<(), i32>,
    ) -> Option<i64> {
        let r = match self.ipc_table() {
            Ok(r) => r,
            Err(e) => return Some(err(e)),
        };
        let creds = self.creds.clone();
        let (stat_index, stat_any) = stat;
        if cmd == stat_index || cmd == stat_any || cmd == ipc::IPC_STAT {
            let t = r.get();
            let found = if cmd == ipc::IPC_STAT {
                (id >= 0).then_some(id).filter(|i| t.objs.contains_key(&(kind as u8, *i)))
            } else {
                t.by_index(kind, id)
            };
            let Some(real) = found else { return Some(err(errno::EINVAL)) };
            let o = &t.objs[&(kind as u8, real)];
            if cmd != stat_any && !ipc::permits(&creds, &o.perm, 4) {
                return Some(err(errno::EACCES));
            }
            let bytes = ds(o, real);
            if let Err(e) = uaccess::write_from(buf, &bytes) {
                return Some(err(e));
            }
            return Some(if cmd == ipc::IPC_STAT { 0 } else { real as i64 });
        }
        match cmd {
            ipc::IPC_SET => {
                let given = match uaccess::read_bytes(buf, set_len) {
                    Ok(b) => b,
                    Err(e) => return Some(err(e)),
                };
                Some(
                    match r.update(|t| {
                        let o = t.get(kind, id)?;
                        if !ipc::owns(&creds, &o.perm) {
                            return Err(errno::EPERM);
                        }
                        set(o, &given, &creds)?;
                        ipc::read_set(&given, &mut o.perm);
                        o.ctime = now();
                        Ok(())
                    }) {
                        Ok(()) => 0,
                        Err(e) => err(e),
                    },
                )
            }
            ipc::IPC_RMID => Some(
                match r.update(|t| {
                    let o = t.get(kind, id)?;
                    if !ipc::owns(&creds, &o.perm) {
                        return Err(errno::EPERM);
                    }
                    match &o.body {
                        // A segment still attached is marked, its key let go.
                        Body::Shm(s) if !s.attached.is_empty() => {
                            o.removed = true;
                            o.key = ipc::IPC_PRIVATE;
                            o.ctime = now();
                        }
                        _ => {
                            t.objs.remove(&(kind as u8, id));
                            if kind == Kind::Shm {
                                remove_segment(&r, id);
                            }
                        }
                    }
                    Ok(())
                }) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                },
            ),
            _ => None,
        }
    }

    pub(crate) fn sys_shmctl(&mut self, id: u64, cmd: u64, buf: u64) -> i64 {
        let (id, cmd) = (id as i32, ipc::command(cmd));
        let used = |r: &Record<Ipc>| (r.get().highest(Kind::Shm), r.get().count(Kind::Shm));
        match cmd {
            ipc::IPC_INFO => {
                let r = match self.ipc_table() {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };
                let mut b = vec![0u8; 72];
                let t = r.get();
                for (i, v) in
                    [t.shmmax(), ipc::SHMMIN, t.shmmni(), t.shmmni(), t.shmall()].iter().enumerate()
                {
                    b[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
                }
                guest!(uaccess::write_from(buf, &b));
                used(&r).0 as i64
            }
            ipc::SHM_INFO => {
                let r = match self.ipc_table() {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };
                let (highest, count) = used(&r);
                let pages: u64 = r
                    .get()
                    .objs
                    .values()
                    .filter_map(|o| match &o.body {
                        Body::Shm(s) => Some(s.size.div_ceil(self.page_size)),
                        _ => None,
                    })
                    .sum();
                let mut b = vec![0u8; 48];
                b[0..4].copy_from_slice(&(count as i32).to_ne_bytes());
                b[8..16].copy_from_slice(&pages.to_ne_bytes());
                // Resident pages: fwe cannot tell (the host has them);
                // none, as for segments no one has touched.
                guest!(uaccess::write_from(buf, &b));
                highest as i64
            }
            ipc::SHM_LOCK | ipc::SHM_UNLOCK => {
                let r = match self.ipc_table() {
                    Ok(r) => r,
                    Err(e) => return err(e),
                };
                let creds = self.creds.clone();
                match r.update(|t| {
                    let o = t.get(Kind::Shm, id)?;
                    if !creds.has(crate::caps::CAP_IPC_LOCK) && !ipc::owns(&creds, &o.perm) {
                        return Err(errno::EPERM);
                    }
                    if let Body::Shm(s) = &mut o.body {
                        s.locked = cmd == ipc::SHM_LOCK;
                    }
                    Ok(())
                }) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                }
            }
            _ => self
                .ipc_ctl_common(
                    Kind::Shm,
                    id,
                    cmd,
                    buf,
                    (ipc::SHM_STAT, ipc::SHM_STAT_ANY),
                    ipc::shmid_ds,
                    48,
                    |_, _, _| Ok(()),
                )
                .unwrap_or(err(errno::EINVAL)),
        }
    }

    pub(crate) fn sys_semctl(&mut self, id: u64, num: u64, cmd: u64, arg: u64) -> i64 {
        let (id, num, cmd) = (id as i32, num as i32, ipc::command(cmd));
        let r = match self.ipc_table() {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let creds = self.creds.clone();
        match cmd {
            ipc::IPC_INFO | ipc::SEM_INFO => {
                let t = r.get();
                let (sets, sems): (i32, i32) =
                    t.objs.values().fold((0, 0), |(a, b), o| match &o.body {
                        Body::Sem(s) => (a + 1, b + s.vals.len() as i32),
                        _ => (a, b),
                    });
                let info = cmd == ipc::SEM_INFO;
                let [semmsl, semmns, semopm, semmni] = t.sem();
                let v = [
                    semmns,
                    semmni,
                    semmns,
                    semmns,
                    semmsl,
                    semopm,
                    semopm,
                    if info { sets } else { 20 },
                    ipc::SEMVMX,
                    if info { sems } else { ipc::SEMAEM },
                ];
                let b: Vec<u8> = v.iter().flat_map(|x| x.to_ne_bytes()).collect();
                guest!(uaccess::write_from(arg, &b));
                return t.highest(Kind::Sem) as i64;
            }
            ipc::GETVAL | ipc::GETPID | ipc::GETNCNT | ipc::GETZCNT | ipc::GETALL => {
                let t = r.get();
                let Some(o) = t.objs.get(&(Kind::Sem as u8, id)).filter(|_| id >= 0) else {
                    return err(errno::EINVAL);
                };
                let Body::Sem(s) = &o.body else { return err(errno::EINVAL) };
                if !ipc::permits(&creds, &o.perm, 4) {
                    return err(errno::EACCES);
                }
                if cmd == ipc::GETALL {
                    let b: Vec<u8> =
                        s.vals.iter().flat_map(|&(v, _)| (v as u16).to_ne_bytes()).collect();
                    guest!(uaccess::write_from(arg, &b));
                    return 0;
                }
                let Some(&(val, pid)) = s.vals.get(num as usize).filter(|_| num >= 0) else {
                    return err(errno::EINVAL);
                };
                let waiting = |zero: bool| {
                    s.waiting.iter().filter(|&&(_, n, z)| n as i32 == num && z == zero).count()
                        as i64
                };
                return match cmd {
                    ipc::GETVAL => val as i64,
                    ipc::GETPID => ipc::guest_pid(pid) as i64,
                    ipc::GETNCNT => waiting(false),
                    _ => waiting(true),
                };
            }
            ipc::SETVAL | ipc::SETALL => {
                let all = if cmd == ipc::SETALL {
                    let n = match r.get().objs.get(&(Kind::Sem as u8, id)).map(|o| o.body.clone()) {
                        Some(Body::Sem(s)) if id >= 0 => s.vals.len(),
                        _ => return err(errno::EINVAL),
                    };
                    let b = guest!(uaccess::read_bytes(arg, n * 2));
                    Some(
                        b.chunks(2)
                            .map(|c| u16::from_ne_bytes([c[0], c[1]]) as i32)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                };
                let me = ipc::me();
                return match r.update(|t| {
                    let o = t.get(Kind::Sem, id)?;
                    if !ipc::permits(&creds, &o.perm, 2) {
                        return Err(errno::EACCES);
                    }
                    let Body::Sem(s) = &mut o.body else { return Err(errno::EINVAL) };
                    match &all {
                        Some(vals) => {
                            if vals.iter().any(|&v| v > ipc::SEMVMX) {
                                return Err(errno::ERANGE);
                            }
                            for (slot, &v) in s.vals.iter_mut().zip(vals) {
                                *slot = (v, me.0);
                            }
                            s.undo.clear();
                        }
                        None => {
                            let val = arg as i32;
                            let Some(slot) = s.vals.get_mut(num as usize).filter(|_| num >= 0)
                            else {
                                return Err(errno::EINVAL);
                            };
                            if !(0..=ipc::SEMVMX).contains(&val) {
                                return Err(errno::ERANGE);
                            }
                            *slot = (val, me.0);
                            // Its undo adjustments go, in every process.
                            for (_, adj) in s.undo.iter_mut() {
                                adj.retain(|&(n, _)| n as i32 != num);
                            }
                        }
                    }
                    o.ctime = now();
                    Ok(())
                }) {
                    Ok(()) => 0,
                    Err(e) => err(e),
                };
            }
            _ => {}
        }
        self.ipc_ctl_common(
            Kind::Sem,
            id,
            cmd,
            arg,
            (ipc::SEM_STAT, ipc::SEM_STAT_ANY),
            ipc::semid_ds,
            48,
            |_, _, _| Ok(()),
        )
        .unwrap_or(err(errno::EINVAL))
    }

    pub(crate) fn sys_msgctl(&mut self, id: u64, cmd: u64, buf: u64) -> i64 {
        let (id, cmd) = (id as i32, ipc::command(cmd));
        if cmd == ipc::IPC_INFO || cmd == ipc::MSG_INFO {
            let r = match self.ipc_table() {
                Ok(r) => r,
                Err(e) => return err(e),
            };
            let t = r.get();
            let (queues, msgs, bytes) =
                t.objs.values().fold((0i32, 0i32, 0i32), |(q, m, b), o| match &o.body {
                    Body::Msg(x) => (
                        q + 1,
                        m + x.msgs.len() as i32,
                        b + x.msgs.iter().map(|(_, t)| t.len() as i32).sum::<i32>(),
                    ),
                    _ => (q, m, b),
                });
            let info = cmd == ipc::MSG_INFO;
            let (max, mnb, mni) = (t.msgmax() as i32, t.msgmnb() as i32, t.msgmni() as i32);
            let v = [
                if info { queues } else { (mni as i64 * mnb as i64 / 1024) as i32 },
                if info { msgs } else { mnb },
                max,
                mnb,
                mni,
                16,
                if info { bytes } else { mnb },
            ];
            let mut b: Vec<u8> = v.iter().flat_map(|x| x.to_ne_bytes()).collect();
            b.extend_from_slice(&0xffffu16.to_ne_bytes());
            b.extend_from_slice(&[0, 0]);
            guest!(uaccess::write_from(buf, &b));
            return t.highest(Kind::Msg) as i64;
        }
        let mnb = self.ipc_table().map_or(ipc::MSGMNB, |r| r.get().msgmnb());
        self.ipc_ctl_common(
            Kind::Msg,
            id,
            cmd,
            buf,
            (ipc::MSG_STAT, ipc::MSG_STAT_ANY),
            ipc::msqid_ds,
            120,
            |o, given, creds| {
                let qbytes = u64::from_ne_bytes(given[88..96].try_into().unwrap());
                if let Body::Msg(m) = &mut o.body {
                    // Past `kernel.msgmnb` takes CAP_SYS_RESOURCE.
                    if qbytes > mnb && !creds.has(crate::caps::CAP_SYS_RESOURCE) {
                        return Err(errno::EPERM);
                    }
                    m.qbytes = qbytes;
                }
                Ok(())
            },
        )
        .unwrap_or(err(errno::EINVAL))
    }
}

/// Run `step` (one try of an operation, under the record's lock) until
/// it is done, waiting for the record to change between tries: up to
/// `until` (`EAGAIN`), and no longer than a signal for the guest
/// (`EINTR`). `gone` is what the object having gone while it waited
/// gives (`EIDRM`).
fn ipc_wait<T>(
    r: &Arc<Record<Ipc>>,
    until: Option<Instant>,
    mut step: impl FnMut(&mut Ipc, bool) -> Result<(Try<T>, bool), i32>,
    cancel: impl Fn(&mut Ipc) -> bool,
) -> Result<T, i32> {
    let mut waited = false;
    loop {
        let seen = r.generation();
        match r.update_maybe(|t| {
            let reaped = t.reap(r);
            let (out, changed) = step(t, waited)?;
            Ok((out, changed || reaped))
        }) {
            Ok(Try::Done(v)) => return Ok(v),
            Ok(Try::Wait) => {}
            Err(e) => return Err(e),
        }
        waited = true;
        if let Err(e) = r.wait_change(seen, until) {
            let _ = r.update_maybe(|t| Ok(((), cancel(t))));
            return Err(e);
        }
    }
}

/// `semtimedop(id, sops, nsops, timeout)` (and `semop`, with none): all
/// the operations at once, or none, waiting until they can be done.
fn semtimedop(ctx: &IpcContext, id: u64, sops: u64, nsops: u64, timeout: u64) -> i64 {
    let (id, n) = (id as i32, nsops as i64);
    if n < 1 || id < 0 {
        return err(errno::EINVAL);
    }
    if n > ctx.record.get().sem()[2] as i64 {
        return err(errno::E2BIG);
    }
    let raw = guest!(uaccess::read_bytes(sops, n as usize * 6));
    let ops: Vec<(u16, i16, i16)> = raw
        .chunks(6)
        .map(|c| {
            (
                u16::from_ne_bytes([c[0], c[1]]),
                i16::from_ne_bytes([c[2], c[3]]),
                i16::from_ne_bytes([c[4], c[5]]),
            )
        })
        .collect();
    let until = guest!(deadline(timeout));
    let (r, creds) = (&ctx.record, &ctx.creds);
    let me = ipc::me();
    let alter = ops.iter().any(|&(_, op, _)| op != 0);
    let result = ipc_wait(
        r,
        until,
        |t, waited| {
            let o = match t.get(Kind::Sem, id) {
                Ok(o) => o,
                Err(_) if waited => return Err(errno::EIDRM),
                Err(e) => return Err(e),
            };
            let Body::Sem(s) = &mut o.body else { return Err(errno::EINVAL) };
            if ops.iter().any(|&(num, _, _)| num as usize >= s.vals.len()) {
                return Err(errno::EFBIG);
            }
            if !ipc::permits(creds, &o.perm, if alter { 2 } else { 4 }) {
                return Err(errno::EACCES);
            }
            let mut vals: Vec<i32> = s.vals.iter().map(|&(v, _)| v).collect();
            for &(num, op, flg) in &ops {
                let v = &mut vals[num as usize];
                let blocked = if op > 0 {
                    if *v + op as i32 > ipc::SEMVMX {
                        return Err(errno::ERANGE);
                    }
                    *v += op as i32;
                    None
                } else if op < 0 {
                    if *v + (op as i32) < 0 {
                        Some(false)
                    } else {
                        *v += op as i32;
                        None
                    }
                } else if *v != 0 {
                    Some(true)
                } else {
                    None
                };
                if let Some(zero) = blocked {
                    if flg as u64 & ipc::IPC_NOWAIT != 0 {
                        return Err(errno::EAGAIN);
                    }
                    let entry = (me, num, zero);
                    let registered = s.waiting.contains(&entry);
                    s.waiting.retain(|&(p, _, _)| p != me);
                    s.waiting.push(entry);
                    return Ok((Try::Wait, !registered));
                }
            }
            // All of them: done.
            for (slot, &v) in s.vals.iter_mut().zip(&vals) {
                slot.0 = v;
            }
            for &(num, op, flg) in &ops {
                s.vals[num as usize].1 = me.0;
                if flg & ipc::SEM_UNDO != 0 && op != 0 {
                    let i = match s.undo.iter().position(|(p, _)| *p == me) {
                        Some(i) => i,
                        None => {
                            s.undo.push((me, Vec::new()));
                            s.undo.len() - 1
                        }
                    };
                    let adj = &mut s.undo[i].1;
                    match adj.iter_mut().find(|(n, _)| *n == num) {
                        Some(a) => a.1 -= op as i32,
                        None => adj.push((num, -(op as i32))),
                    }
                }
            }
            s.waiting.retain(|&(p, _, _)| p != me);
            s.otime = now();
            Ok((Try::Done(()), true))
        },
        |t| {
            let mut changed = false;
            if let Ok(Obj { body: Body::Sem(s), .. }) = t.get(Kind::Sem, id) {
                let before = s.waiting.len();
                s.waiting.retain(|&(p, _, _)| p != me);
                changed = s.waiting.len() != before;
            }
            changed
        },
    );
    match result {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// `msgsnd(id, msgp, msgsz, flags)`: the message (a `long` type, then
/// the text) onto the queue, waiting for room.
fn msgsnd(ctx: &IpcContext, id: u64, msgp: u64, size: u64, flags: u64) -> i64 {
    let id = id as i32;
    if (size as i64) < 0 || size > ctx.record.get().msgmax() || id < 0 {
        return err(errno::EINVAL);
    }
    let mtype: i64 = guest!(uaccess::read(msgp));
    if mtype < 1 {
        return err(errno::EINVAL);
    }
    let text = guest!(uaccess::read_bytes(msgp + 8, size as usize));
    let (r, creds) = (&ctx.record, &ctx.creds);
    let me = ipc::me();
    let result = ipc_wait(
        r,
        None,
        |t, waited| {
            let o = match t.get(Kind::Msg, id) {
                Ok(o) => o,
                Err(_) if waited => return Err(errno::EIDRM),
                Err(e) => return Err(e),
            };
            if !ipc::permits(creds, &o.perm, 2) {
                return Err(errno::EACCES);
            }
            let Body::Msg(m) = &mut o.body else { return Err(errno::EINVAL) };
            let held: u64 = m.msgs.iter().map(|(_, t)| t.len() as u64).sum();
            if held + size > m.qbytes || m.msgs.len() as u64 + 1 > m.qbytes {
                if flags & ipc::IPC_NOWAIT != 0 {
                    return Err(errno::EAGAIN);
                }
                return Ok((Try::Wait, false));
            }
            m.msgs.push_back((mtype, text.clone()));
            m.stime = now();
            m.lspid = me.0;
            Ok((Try::Done(()), true))
        },
        |_| false,
    );
    match result {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// `msgrcv(id, msgp, msgsz, msgtyp, flags)`: a message of the type
/// asked for (`0` the first, `> 0` the first of that type, or not of
/// it with `MSG_EXCEPT`, `< 0` the lowest type up to its magnitude;
/// with `MSG_COPY`, a copy of the one at position `msgtyp`), waiting
/// for one.
fn msgrcv(ctx: &IpcContext, id: u64, msgp: u64, size: u64, msgtyp: u64, flags: u64) -> i64 {
    let (id, msgtyp) = (id as i32, msgtyp as i64);
    if (size as i64) < 0 || id < 0 {
        return err(errno::EINVAL);
    }
    let copy = flags & ipc::MSG_COPY != 0;
    if copy && (flags & ipc::IPC_NOWAIT == 0 || flags & ipc::MSG_EXCEPT != 0) {
        return err(errno::EINVAL);
    }
    let (r, creds) = (&ctx.record, &ctx.creds);
    let me = ipc::me();
    let result = ipc_wait(
        r,
        None,
        |t, waited| {
            let o = match t.get(Kind::Msg, id) {
                Ok(o) => o,
                Err(_) if waited => return Err(errno::EIDRM),
                Err(e) => return Err(e),
            };
            if !ipc::permits(creds, &o.perm, 4) {
                return Err(errno::EACCES);
            }
            let Body::Msg(m) = &mut o.body else { return Err(errno::EINVAL) };
            let at = if copy {
                (msgtyp >= 0 && (msgtyp as usize) < m.msgs.len()).then_some(msgtyp as usize)
            } else if msgtyp == 0 {
                (!m.msgs.is_empty()).then_some(0)
            } else if msgtyp > 0 && flags & ipc::MSG_EXCEPT != 0 {
                m.msgs.iter().position(|(t, _)| *t != msgtyp)
            } else if msgtyp > 0 {
                m.msgs.iter().position(|(t, _)| *t == msgtyp)
            } else {
                let bound = msgtyp.unsigned_abs();
                m.msgs
                    .iter()
                    .enumerate()
                    .filter(|(_, (t, _))| t.unsigned_abs() <= bound)
                    .min_by_key(|(_, (t, _))| *t)
                    .map(|(i, _)| i)
            };
            let Some(at) = at else {
                if flags & ipc::IPC_NOWAIT != 0 {
                    return Err(errno::ENOMSG);
                }
                return Ok((Try::Wait, false));
            };
            let (mtype, text) = m.msgs[at].clone();
            if text.len() as u64 > size && flags & ipc::MSG_NOERROR == 0 {
                return Err(errno::E2BIG);
            }
            if copy {
                return Ok((Try::Done((mtype, text)), false));
            }
            m.msgs.remove(at);
            m.rtime = now();
            m.lrpid = me.0;
            Ok((Try::Done((mtype, text)), true))
        },
        |_| false,
    );
    match result {
        Ok((mtype, mut text)) => {
            text.truncate(size as usize);
            guest!(uaccess::write(msgp, mtype));
            guest!(uaccess::write_from(msgp + 8, &text));
            text.len() as i64
        }
        Err(e) => err(e),
    }
}

/// What a waiting IPC call needs of the kernel, taken under its lock so
/// the call can wait without it ([`blocking`]).
pub struct IpcContext {
    record: Arc<Record<Ipc>>,
    creds: crate::creds::Creds,
}

/// Whether system call `nr` is one of the IPC calls that may wait (the
/// System V ones and a POSIX message queue's send and receive).
pub fn waits(nr: u64) -> bool {
    use fwe_abi::nr as n;
    matches!(
        nr,
        n::SEMOP | n::SEMTIMEDOP | n::MSGSND | n::MSGRCV | n::MQ_TIMEDSEND | n::MQ_TIMEDRECEIVE
    )
}

/// Run waiting IPC call `nr` (see [`waits`]) with `args`, in `ctx`, without
/// the kernel lock: a semaphore another thread of the process posts, or a
/// message it sends, must not wait for this one to let go.
pub fn blocking(ctx: Result<IpcContext, i32>, nr: u64, a: [u64; 6]) -> i64 {
    use fwe_abi::nr as n;
    let ctx = match ctx {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    match nr {
        n::SEMOP => semtimedop(&ctx, a[0], a[1], a[2], 0),
        n::SEMTIMEDOP => semtimedop(&ctx, a[0], a[1], a[2], a[3]),
        n::MSGSND => msgsnd(&ctx, a[0], a[1], a[2], a[3]),
        n::MQ_TIMEDSEND => crate::mqueue::timedsend(&ctx.creds, a[0], a[1], a[2], a[3], a[4]),
        n::MQ_TIMEDRECEIVE => crate::mqueue::timedreceive(a[0], a[1], a[2], a[3], a[4]),
        _ => msgrcv(&ctx, a[0], a[1], a[2], a[3], a[4]),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The file of a new segment `id` of `size` bytes (zeroes).
fn make_segment(r: &Record<Ipc>, id: i32, size: u64) -> Result<(), i32> {
    let path = std::ffi::CString::new(ipc::segment_path(r, id)).map_err(|_| errno::EINVAL)?;
    // SAFETY: a NUL-terminated path in fwe's private directory; the
    // descriptor is closed again.
    unsafe {
        let fd = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600,
        );
        if fd < 0 {
            return Err(crate::host::errno_to_linux(crate::host::last_errno()));
        }
        let ok = libc::ftruncate(fd, size as libc::off_t) == 0;
        libc::close(fd);
        if ok { Ok(()) } else { Err(errno::ENOMEM) }
    }
}

fn remove_segment(r: &Record<Ipc>, id: i32) {
    if let Ok(p) = std::ffi::CString::new(ipc::segment_path(r, id)) {
        // SAFETY: a NUL-terminated path in fwe's private directory.
        unsafe { libc::unlink(p.as_ptr()) };
    }
}
