//! Watching a mount table through a mounts file (`/proc/<pid>/mounts`,
//! `mountinfo`): Linux reports such a file `POLLERR | POLLPRI` to `poll`
//! and `epoll` once its namespace's mounts changed since the file was
//! opened or last polled, which programs that follow mounts (systemd's
//! `udisks`, container tools) wait for.
//!
//! The file's descriptor is an anonymous one of fwe's, a regular file the
//! host knows nothing of; fwe keeps, for each such descriptor, its mount
//! namespace's record and the generation of it last seen. The record's
//! generation, which every change of the table moves, is a word every
//! process maps, so a wait reads it without the kernel lock.

use crate::mounts::store::Ns;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Each watched descriptor's namespace, and the generation last seen.
type Watches = HashMap<i32, (Arc<Ns>, u64)>;

pub(crate) static WATCHES: Mutex<Option<Watches>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Watches) -> R) -> R {
    f(WATCHES.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new))
}

/// `fd` was opened on a mounts file of namespace `ns`: changes after now
/// are reported.
pub fn opened(fd: i32, ns: Arc<Ns>) {
    let seen = ns.generation();
    with(|m| m.insert(fd, (ns, seen)));
}

/// `fd` was closed.
pub fn closed(fd: i32) {
    with(|m| m.remove(&fd));
}

/// Whether `fd` is a watched mounts file.
pub fn is(fd: i32) -> bool {
    with(|m| m.contains_key(&fd))
}

/// Whether the mounts of watched file `fd` changed since it was last
/// asked (`None`: not watched). Asking takes the change, as Linux's poll
/// of the file does.
pub fn changed(fd: i32) -> Option<bool> {
    with(|m| {
        let (ns, seen) = m.get_mut(&fd)?;
        let now = ns.generation();
        let changed = now != *seen;
        *seen = now;
        Some(changed)
    })
}
