//! Virtual process credentials.
//!
//! A guest has its own user and group identity, independent of the host
//! process `fwe` runs as. Changing the host process's real credentials would
//! be wrong (one host process backs the guest) and would fail unless `fwe` ran
//! as root, so the identity is tracked here and the `get*`/`set*` id calls act
//! on it with Linux semantics. The default is root (uid 0), the usual identity
//! inside a container image, so a program that drops privileges can do so.
//!
//! Because the identity is virtual, it does not change how the host enforces
//! access to the backing files; `chown` as root is accepted but does not alter
//! host ownership, and `access`/open checks under a virtual root bypass the
//! permission bits as Linux root would.

use fwe_abi::{err, errno};

/// `(uid_t)-1`: "leave unchanged" in the `setre*`/`setres*` calls.
const KEEP: u32 = u32::MAX;

/// Real, effective, saved and filesystem ids for users and groups, plus the
/// supplementary groups.
#[derive(Clone, Debug)]
pub struct Creds {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
}

impl Default for Creds {
    fn default() -> Self {
        Creds {
            uid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: vec![0],
        }
    }
}

fn pick(arg: u32, cur: u32) -> u32 {
    if arg == KEEP { cur } else { arg }
}

impl Creds {
    /// Privileged if the effective uid is root.
    fn privileged(&self) -> bool {
        self.euid == 0
    }

    /// May administer the system: mount, unmount, make namespaces
    /// (`CAP_SYS_ADMIN`).
    pub fn has_admin(&self) -> bool {
        self.privileged()
    }

    /// May change its root directory (`CAP_SYS_CHROOT`).
    pub fn has_chroot(&self) -> bool {
        self.privileged()
    }

    pub fn getuid(&self) -> i64 {
        self.uid as i64
    }
    pub fn geteuid(&self) -> i64 {
        self.euid as i64
    }
    pub fn getgid(&self) -> i64 {
        self.gid as i64
    }
    pub fn getegid(&self) -> i64 {
        self.egid as i64
    }

    /// `setuid(u)`.
    pub fn setuid(&mut self, u: u32) -> i64 {
        if u == KEEP {
            return err(errno::EINVAL);
        }
        if self.privileged() {
            self.uid = u;
            self.euid = u;
            self.suid = u;
            self.fsuid = u;
            0
        } else if u == self.uid || u == self.suid {
            self.euid = u;
            self.fsuid = u;
            0
        } else {
            err(errno::EPERM)
        }
    }

    /// `seteuid(e)`; `-1` is a no-op.
    pub fn seteuid(&mut self, e: u32) -> i64 {
        if e == KEEP {
            return 0;
        }
        if self.privileged() || e == self.uid || e == self.euid || e == self.suid {
            self.euid = e;
            self.fsuid = e;
            0
        } else {
            err(errno::EPERM)
        }
    }

    /// `setreuid(r, e)`.
    pub fn setreuid(&mut self, r: u32, e: u32) -> i64 {
        let old_uid = self.uid;
        let nr = pick(r, self.uid);
        let ne = pick(e, self.euid);
        if !self.privileged() {
            if r != KEEP && !(nr == self.uid || nr == self.euid) {
                return err(errno::EPERM);
            }
            if e != KEEP && !(ne == self.uid || ne == self.euid || ne == self.suid) {
                return err(errno::EPERM);
            }
        }
        let real_changed = r != KEEP && nr != old_uid;
        self.uid = nr;
        self.euid = ne;
        if real_changed || (e != KEEP && ne != old_uid) {
            self.suid = ne;
        }
        self.fsuid = self.euid;
        0
    }

    /// `setresuid(r, e, s)`.
    pub fn setresuid(&mut self, r: u32, e: u32, s: u32) -> i64 {
        let nr = pick(r, self.uid);
        let ne = pick(e, self.euid);
        let ns = pick(s, self.suid);
        if !self.privileged() {
            let cur = [self.uid, self.euid, self.suid];
            if (r != KEEP && !cur.contains(&nr))
                || (e != KEEP && !cur.contains(&ne))
                || (s != KEEP && !cur.contains(&ns))
            {
                return err(errno::EPERM);
            }
        }
        self.uid = nr;
        self.euid = ne;
        self.suid = ns;
        self.fsuid = ne;
        0
    }

    /// `getresuid` values.
    pub fn resuid(&self) -> (u32, u32, u32) {
        (self.uid, self.euid, self.suid)
    }

    /// `setfsuid(f)`; always returns the previous fsuid.
    pub fn setfsuid(&mut self, f: u32) -> i64 {
        let old = self.fsuid;
        if f != KEEP
            && (self.privileged()
                || f == self.uid
                || f == self.euid
                || f == self.suid
                || f == self.fsuid)
        {
            self.fsuid = f;
        }
        old as i64
    }

    /// `setgid(g)`.
    pub fn setgid(&mut self, g: u32) -> i64 {
        if g == KEEP {
            return err(errno::EINVAL);
        }
        if self.privileged() {
            self.gid = g;
            self.egid = g;
            self.sgid = g;
            self.fsgid = g;
            0
        } else if g == self.gid || g == self.sgid {
            self.egid = g;
            self.fsgid = g;
            0
        } else {
            err(errno::EPERM)
        }
    }

    /// `setegid(e)`; `-1` is a no-op.
    pub fn setegid(&mut self, e: u32) -> i64 {
        if e == KEEP {
            return 0;
        }
        if self.privileged() || e == self.gid || e == self.egid || e == self.sgid {
            self.egid = e;
            self.fsgid = e;
            0
        } else {
            err(errno::EPERM)
        }
    }

    /// `setregid(r, e)`.
    pub fn setregid(&mut self, r: u32, e: u32) -> i64 {
        let old_gid = self.gid;
        let nr = pick(r, self.gid);
        let ne = pick(e, self.egid);
        if !self.privileged() {
            if r != KEEP && !(nr == self.gid || nr == self.egid) {
                return err(errno::EPERM);
            }
            if e != KEEP && !(ne == self.gid || ne == self.egid || ne == self.sgid) {
                return err(errno::EPERM);
            }
        }
        let real_changed = r != KEEP && nr != old_gid;
        self.gid = nr;
        self.egid = ne;
        if real_changed || (e != KEEP && ne != old_gid) {
            self.sgid = ne;
        }
        self.fsgid = self.egid;
        0
    }

    /// `setresgid(r, e, s)`.
    pub fn setresgid(&mut self, r: u32, e: u32, s: u32) -> i64 {
        let nr = pick(r, self.gid);
        let ne = pick(e, self.egid);
        let ns = pick(s, self.sgid);
        if !self.privileged() {
            let cur = [self.gid, self.egid, self.sgid];
            if (r != KEEP && !cur.contains(&nr))
                || (e != KEEP && !cur.contains(&ne))
                || (s != KEEP && !cur.contains(&ns))
            {
                return err(errno::EPERM);
            }
        }
        self.gid = nr;
        self.egid = ne;
        self.sgid = ns;
        self.fsgid = ne;
        0
    }

    /// `getresgid` values.
    pub fn resgid(&self) -> (u32, u32, u32) {
        (self.gid, self.egid, self.sgid)
    }

    /// `setfsgid(f)`; always returns the previous fsgid.
    pub fn setfsgid(&mut self, f: u32) -> i64 {
        let old = self.fsgid;
        if f != KEEP
            && (self.privileged()
                || f == self.gid
                || f == self.egid
                || f == self.sgid
                || f == self.fsgid)
        {
            self.fsgid = f;
        }
        old as i64
    }

    /// Current supplementary groups.
    pub fn groups(&self) -> &[u32] {
        &self.groups
    }

    /// `setgroups`: privileged only.
    pub fn setgroups(&mut self, groups: Vec<u32>) -> i64 {
        if !self.privileged() {
            return err(errno::EPERM);
        }
        self.groups = groups;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::errno;

    #[test]
    fn root_drops_and_cannot_regain() {
        let mut c = Creds::default();
        assert_eq!(c.geteuid(), 0);
        // Root setuid sets all four ids.
        assert_eq!(c.setuid(1000), 0);
        assert_eq!(c.resuid(), (1000, 1000, 1000));
        assert_eq!(c.getuid(), 1000);
        // No longer privileged: cannot become root again.
        assert_eq!(c.setuid(0), err(errno::EPERM));
    }

    #[test]
    fn seteuid_switches_within_saved_set() {
        let mut c = Creds::default();
        // Root installs a real/saved split via setresuid.
        assert_eq!(c.setresuid(1000, 0, 0), 0);
        assert_eq!(c.resuid(), (1000, 0, 0));
        // Still euid 0 (privileged): can drop effective to the saved root...
        assert_eq!(c.seteuid(1000), 0);
        assert_eq!(c.resuid(), (1000, 1000, 0));
        // ...and back to the saved-set value 0.
        assert_eq!(c.seteuid(0), 0);
        assert_eq!(c.resuid(), (1000, 0, 0));
    }

    #[test]
    fn unprivileged_setresuid_is_constrained() {
        let mut c = Creds::default();
        assert_eq!(c.setresuid(1000, 1000, 1000), 0);
        // Only values in {uid,euid,suid} = {1000} are allowed now.
        assert_eq!(c.setresuid(KEEP, 0, KEEP), err(errno::EPERM));
        assert_eq!(c.setresuid(KEEP, 1000, KEEP), 0);
    }

    #[test]
    fn setfsuid_returns_previous() {
        let mut c = Creds::default();
        assert_eq!(c.setfsuid(1000), 0); // was 0
        assert_eq!(c.setfsuid(1234), 1000); // was 1000
        assert_eq!(c.fsuid, 1234);
    }

    #[test]
    fn setgroups_needs_privilege() {
        let mut c = Creds::default();
        assert_eq!(c.setgroups(vec![0, 10, 20]), 0);
        assert_eq!(c.groups(), &[0, 10, 20]);
        c.setuid(1000); // drop privilege
        assert_eq!(c.setgroups(vec![5]), err(errno::EPERM));
    }

    #[test]
    fn keep_sentinel_leaves_values() {
        let mut c = Creds::default();
        c.setresuid(1000, 1000, 1000);
        // seteuid(-1) is a no-op success.
        assert_eq!(c.seteuid(KEEP), 0);
        assert_eq!(c.resuid(), (1000, 1000, 1000));
    }
}
