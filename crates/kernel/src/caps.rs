//! Capabilities: the five sets Linux keeps for a process, the securebits,
//! and how `setuid` and `execve` change them.
//!
//! What a privileged operation needs is a capability in the effective set,
//! as on Linux, not an effective uid of 0: a container runtime that drops
//! capabilities leaves a root that cannot, say, mount or change its uid.
//! `execve` follows Linux's rules, a program's file capabilities
//! (`security.capability`, [`FileCaps`]) and set-ID bits included.

use fwe_abi::errno;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_PACCT: u32 = 20;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_LEASE: u32 = 28;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_BPF: u32 = 39;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_WAKE_ALARM: u32 = 35;
/// The highest capability (`CAP_CHECKPOINT_RESTORE`).
pub const CAP_LAST_CAP: u32 = 40;
/// Every capability.
pub const ALL: u64 = (1 << (CAP_LAST_CAP + 1)) - 1;

/// The capabilities a change of the filesystem uid gains or loses.
const FS_MASK: u64 = 1 << CAP_CHOWN
    | 1 << CAP_DAC_OVERRIDE
    | 1 << CAP_DAC_READ_SEARCH
    | 1 << CAP_FOWNER
    | 1 << CAP_FSETID
    | 1 << CAP_LINUX_IMMUTABLE
    | 1 << CAP_MKNOD
    | 1 << CAP_MAC_OVERRIDE;

/// A program's file capabilities, its `security.capability` attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCaps {
    pub permitted: u64,
    pub inheritable: u64,
    /// Its effective bit: the permitted set is made effective at once.
    pub effective: bool,
}

/// `VFS_CAP_FLAGS_EFFECTIVE` and the revisions of `vfs_cap_data`.
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x1;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;

/// The file capabilities attribute value `v` holds, and the root id a
/// revision-3 value is for (`None` for an earlier revision): `None` for a
/// malformed value, which Linux ignores.
pub fn parse_file_caps(v: &[u8]) -> Option<(FileCaps, Option<u32>)> {
    let word = |i: usize| -> Option<u32> {
        Some(u32::from_le_bytes(v.get(i * 4..i * 4 + 4)?.try_into().ok()?))
    };
    let magic = word(0)?;
    let effective = magic & VFS_CAP_FLAGS_EFFECTIVE != 0;
    let (words, rootid) = match magic & 0xff00_0000 {
        VFS_CAP_REVISION_1 if v.len() == 12 => (1, None),
        VFS_CAP_REVISION_2 if v.len() == 20 => (2, None),
        VFS_CAP_REVISION_3 if v.len() == 24 => (2, Some(word(5)?)),
        _ => return None,
    };
    let (mut permitted, mut inheritable) = (0u64, 0u64);
    for i in 0..words {
        permitted |= u64::from(word(1 + 2 * i)?) << (32 * i);
        inheritable |= u64::from(word(2 + 2 * i)?) << (32 * i);
    }
    Some((
        FileCaps { permitted: permitted & ALL, inheritable: inheritable & ALL, effective },
        rootid,
    ))
}

/// Securebits (`linux/securebits.h`).
pub const SECBIT_NOROOT: u32 = 1 << 0;
pub const SECBIT_NO_SETUID_FIXUP: u32 = 1 << 2;
pub const SECBIT_KEEP_CAPS: u32 = 1 << 4;
pub const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
/// Each settable bit, and the bit above it that locks it.
const SECBITS: u32 = 0x55;

/// `capget`/`capset` header versions.
pub const VERSION_1: u32 = 0x1998_0330;
pub const VERSION_2: u32 = 0x2007_1026;
pub const VERSION_3: u32 = 0x2008_0522;

/// A process's capability sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
    pub securebits: u32,
}

/// What fwe's processes may hold in the initial user namespace: every
/// capability but `CAP_SYS_TIME`, as in a container, since the host's
/// clock is not fwe's to set.
pub const INITIAL: u64 = ALL & !(1 << CAP_SYS_TIME);

impl Default for Caps {
    /// Root's: every capability it may have ([`INITIAL`]), nothing
    /// inheritable or ambient.
    fn default() -> Self {
        Caps {
            effective: INITIAL,
            permitted: INITIAL,
            inheritable: 0,
            bounding: INITIAL,
            ambient: 0,
            securebits: 0,
        }
    }
}

fn bit(cap: u32) -> u64 {
    1 << cap
}

impl Caps {
    /// Whether `cap` is in the effective set.
    pub fn has(&self, cap: u32) -> bool {
        self.effective & bit(cap) != 0
    }

    /// `capset`: the new effective, permitted and inheritable sets, if
    /// Linux would allow them.
    pub fn set(&mut self, effective: u64, permitted: u64, inheritable: u64) -> Result<(), i32> {
        let (effective, permitted, inheritable) =
            (effective & ALL, permitted & ALL, inheritable & ALL);
        // The inheritable set may only grow within what is permitted, or the
        // bounding set with CAP_SETPCAP.
        let inh_limit = if self.has(CAP_SETPCAP) {
            self.inheritable | self.bounding
        } else {
            self.inheritable | self.permitted
        };
        if inheritable & !inh_limit != 0
            || inheritable & !(self.inheritable | self.bounding) != 0
            || permitted & !self.permitted != 0
            || effective & !permitted != 0
        {
            return Err(errno::EPERM);
        }
        self.effective = effective;
        self.permitted = permitted;
        self.inheritable = inheritable;
        // What is neither permitted nor inheritable is no longer ambient.
        self.ambient &= permitted & inheritable;
        Ok(())
    }

    /// `PR_CAPBSET_DROP`.
    pub fn drop_bounding(&mut self, cap: u64) -> Result<(), i32> {
        if cap > CAP_LAST_CAP as u64 {
            return Err(errno::EINVAL);
        }
        if !self.has(CAP_SETPCAP) {
            return Err(errno::EPERM);
        }
        self.bounding &= !bit(cap as u32);
        Ok(())
    }

    /// `PR_CAP_AMBIENT`: `op` (`PR_CAP_AMBIENT_IS_SET` 1, `_RAISE` 2,
    /// `_LOWER` 3, `_CLEAR_ALL` 4) on `cap`.
    pub fn ambient_op(&mut self, op: u64, cap: u64) -> Result<i64, i32> {
        if op == 4 {
            if cap != 0 {
                return Err(errno::EINVAL);
            }
            self.ambient = 0;
            return Ok(0);
        }
        if cap > CAP_LAST_CAP as u64 {
            return Err(errno::EINVAL);
        }
        let b = bit(cap as u32);
        match op {
            1 => Ok(i64::from(self.ambient & b != 0)),
            2 => {
                if self.permitted & b == 0
                    || self.inheritable & b == 0
                    || self.securebits & SECBIT_NO_CAP_AMBIENT_RAISE != 0
                {
                    return Err(errno::EPERM);
                }
                self.ambient |= b;
                Ok(0)
            }
            3 => {
                self.ambient &= !b;
                Ok(0)
            }
            _ => Err(errno::EINVAL),
        }
    }

    /// `PR_SET_SECUREBITS`.
    pub fn set_securebits(&mut self, bits: u64) -> Result<(), i32> {
        let bits = bits as u32;
        if u64::from(bits) != bits as u64 || bits & !(SECBITS | SECBITS << 1) != 0 {
            return Err(errno::EINVAL);
        }
        // A locked bit stays as it is, and a lock stays on.
        let locked = (self.securebits >> 1) & SECBITS;
        if (bits ^ self.securebits) & locked != 0 || self.securebits & !bits & (SECBITS << 1) != 0 {
            return Err(errno::EPERM);
        }
        if !self.has(CAP_SETPCAP) {
            return Err(errno::EPERM);
        }
        self.securebits = bits;
        Ok(())
    }

    /// `PR_SET_KEEPCAPS`.
    pub fn set_keepcaps(&mut self, on: u64) -> Result<(), i32> {
        if on > 1 {
            return Err(errno::EINVAL);
        }
        if self.securebits & (SECBIT_KEEP_CAPS << 1) != 0 {
            return Err(errno::EPERM);
        }
        if on == 1 {
            self.securebits |= SECBIT_KEEP_CAPS;
        } else {
            self.securebits &= !SECBIT_KEEP_CAPS;
        }
        Ok(())
    }

    /// The change the uids `(real, effective, saved)` going from `old` to
    /// `new` makes, as Linux's `setuid` family makes it.
    pub fn after_setuid(&mut self, old: (u32, u32, u32), new: (u32, u32, u32)) {
        if self.securebits & SECBIT_NO_SETUID_FIXUP != 0 {
            return;
        }
        let had_root = old.0 == 0 || old.1 == 0 || old.2 == 0;
        let has_root = new.0 == 0 || new.1 == 0 || new.2 == 0;
        if had_root && !has_root {
            if self.securebits & SECBIT_KEEP_CAPS == 0 {
                self.permitted = 0;
                self.effective = 0;
            }
            self.ambient = 0;
        }
        if old.1 == 0 && new.1 != 0 {
            self.effective = 0;
        }
        if old.1 != 0 && new.1 == 0 {
            self.effective = self.permitted;
        }
    }

    /// The change a filesystem uid going from `old` to `new` makes.
    pub fn after_setfsuid(&mut self, old: u32, new: u32) {
        if self.securebits & SECBIT_NO_SETUID_FIXUP != 0 {
            return;
        }
        if old == 0 && new != 0 {
            self.effective &= !FS_MASK;
        }
        if old != 0 && new == 0 {
            self.effective |= self.permitted & FS_MASK;
        }
    }

    /// `execve` of a program with no file capabilities and no set-ID bits,
    /// by a process with uids `ruid` and `euid` (already the new ones).
    pub fn on_exec(&mut self, ruid: u32, euid: u32) {
        self.on_exec_file(ruid, euid, None, false);
    }

    /// [`on_exec`](Self::on_exec) of a program with file capabilities
    /// `file`, or one that is set-ID (`setid`): such a program clears the
    /// ambient set, and a non-root caller gains what its file
    /// capabilities grant, as Linux computes it.
    pub fn on_exec_file(&mut self, ruid: u32, euid: u32, file: Option<FileCaps>, setid: bool) {
        if file.is_some() || setid {
            self.ambient = 0;
        }
        let root = self.securebits & SECBIT_NOROOT == 0 && (euid == 0 || ruid == 0);
        let (permitted, raise) = if root {
            // Root runs every program as if it had every capability.
            (self.inheritable | self.bounding, euid == 0)
        } else if let Some(f) = file {
            ((self.inheritable & f.inheritable) | (f.permitted & self.bounding), f.effective)
        } else {
            (0, false)
        };
        self.permitted = permitted | self.ambient;
        self.effective = if raise { self.permitted } else { self.ambient };
        // Keep-capabilities does not survive an exec.
        self.securebits &= !SECBIT_KEEP_CAPS;
    }

    /// The `Cap*` lines of `/proc/self/status`.
    pub fn status(&self) -> String {
        format!(
            "CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\n",
            self.inheritable, self.permitted, self.effective, self.bounding, self.ambient
        )
    }

    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        for v in [self.effective, self.permitted, self.inheritable, self.bounding, self.ambient] {
            e.u64(v);
        }
        e.u32(self.securebits);
    }

    pub fn decode(d: &mut crate::snapshot::Dec) -> Caps {
        Caps {
            effective: d.u64(),
            permitted: d.u64(),
            inheritable: d.u64(),
            bounding: d.u64(),
            ambient: d.u64(),
            securebits: d.u32(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container runtime's drop: a small bounding set, capset, the exec
    /// that runs the container's program as root.
    #[test]
    fn a_runtime_drops_capabilities() {
        let mut c = Caps::default();
        let keep = bit(CAP_KILL) | bit(CAP_NET_BIND_SERVICE);
        for cap in 0..=CAP_LAST_CAP as u64 {
            if keep & bit(cap as u32) == 0 && cap != CAP_SETPCAP as u64 {
                c.drop_bounding(cap).unwrap();
            }
        }
        c.drop_bounding(CAP_SETPCAP as u64).unwrap();
        c.set(keep, keep, 0).unwrap();
        // Without CAP_SETPCAP in effect, the bounding set stays.
        assert_eq!(c.drop_bounding(CAP_KILL as u64), Err(errno::EPERM));
        assert_eq!(c.set(ALL, ALL, 0), Err(errno::EPERM));
        c.on_exec(0, 0);
        assert_eq!((c.permitted, c.effective, c.bounding), (keep, keep, keep));
        assert!(!c.has(CAP_SYS_ADMIN));
    }

    /// Dropping root loses the capabilities unless kept; ambient ones
    /// survive an exec as a non-root user.
    #[test]
    fn setuid_and_ambient() {
        let mut c = Caps::default();
        c.after_setuid((0, 0, 0), (1000, 1000, 1000));
        assert_eq!((c.permitted, c.effective), (0, 0));
        let mut c = Caps::default();
        c.set_keepcaps(1).unwrap();
        c.after_setuid((0, 0, 0), (1000, 1000, 1000));
        assert_eq!((c.permitted, c.effective), (INITIAL, 0));
        let b = bit(CAP_NET_BIND_SERVICE);
        c.set(b, INITIAL, b).unwrap();
        assert_eq!(c.ambient_op(2, CAP_NET_BIND_SERVICE as u64), Ok(0));
        assert_eq!(c.ambient_op(2, CAP_SYS_ADMIN as u64), Err(errno::EPERM));
        c.on_exec(1000, 1000);
        assert_eq!((c.permitted, c.effective, c.ambient), (b, b, b));
        assert_eq!(c.ambient_op(1, CAP_NET_BIND_SERVICE as u64), Ok(1));
    }

    /// A program with file capabilities, as `newuidmap` has
    /// `cap_setuid+ep`: run by a user, it has them, within the bounding set,
    /// and the ambient set goes.
    #[test]
    fn file_capabilities_raise_a_users_program() {
        // Revision 2, effective, CAP_SETUID permitted.
        let mut v = (VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE).to_le_bytes().to_vec();
        for w in [1u32 << CAP_SETUID, 0, 0, 0] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        let (f, root) = parse_file_caps(&v).unwrap();
        assert_eq!(
            (f.permitted, f.inheritable, f.effective, root),
            (bit(CAP_SETUID), 0, true, None)
        );
        assert!(parse_file_caps(&v[..16]).is_none());
        let mut c = Caps::default();
        c.after_setuid((0, 0, 0), (1000, 1000, 1000));
        c.on_exec_file(1000, 1000, Some(f), false);
        assert_eq!((c.permitted, c.effective), (bit(CAP_SETUID), bit(CAP_SETUID)));
        // Without the effective bit, permitted only.
        let mut c = Caps::default();
        c.after_setuid((0, 0, 0), (1000, 1000, 1000));
        c.on_exec_file(1000, 1000, Some(FileCaps { effective: false, ..f }), false);
        assert_eq!((c.permitted, c.effective), (bit(CAP_SETUID), 0));
        // Outside the bounding set, nothing.
        let mut c = Caps::default();
        c.drop_bounding(CAP_SETUID as u64).unwrap();
        c.after_setuid((0, 0, 0), (1000, 1000, 1000));
        c.on_exec_file(1000, 1000, Some(f), false);
        assert_eq!(c.permitted, 0);
    }
}
