//! The key types ([`crate::keys`]): what each takes as a payload, whether
//! it can be updated and read, and how `/proc/keys` describes it. Linux's
//! limits: a `user` or `logon` payload of 1 to 32767 bytes, a `logon` key's
//! description a `service:name`, a `big_key` payload up to a megabyte, a
//! `keyring` none, a `dns_resolver` one of more than a byte.

use crate::keys::{Caller, Key, Prepared, Store};
use fwe_abi::errno;

/// The largest `user` and `logon` payload.
const USER_MAX: usize = 32767;
/// The largest `big_key` payload.
const BIG_MAX: usize = 1024 * 1024;
/// A `big_key` payload above this is kept in a file on Linux, which
/// `/proc/keys` shows.
const BIG_FILE_THRESHOLD: usize = 1024;

/// Whether `kind` is a key type there is.
pub fn known(kind: &str) -> bool {
    matches!(
        kind,
        "keyring" | "user" | "logon" | "big_key" | "dns_resolver" | "asymmetric" | "encrypted"
    )
}

/// Whether a key of `kind` can be updated (`KEYCTL_UPDATE`, or `add_key`
/// of one already there).
pub fn updatable(kind: &str) -> bool {
    matches!(kind, "user" | "logon" | "big_key" | "encrypted")
}

/// Whether a key of `kind` can be read (`KEYCTL_READ`).
pub fn readable(kind: &str) -> bool {
    matches!(kind, "keyring" | "user" | "big_key" | "dns_resolver" | "encrypted")
}

/// Check and prepare the payload `data` of a new key of `kind` described
/// `desc` (`None`: none given).
pub fn preparse(
    s: &Store,
    c: &Caller,
    kind: &str,
    desc: Option<&[u8]>,
    data: &[u8],
) -> Result<Prepared, i32> {
    let plain = |payload: Vec<u8>| Ok(Prepared { payload, desc: None });
    match kind {
        "keyring" => {
            if !data.is_empty() {
                return Err(errno::EINVAL);
            }
            plain(Vec::new())
        }
        "user" => plain(user_payload(data)?),
        "logon" => {
            if let Some(d) = desc {
                logon_description(d)?;
            }
            plain(user_payload(data)?)
        }
        "big_key" => {
            if data.is_empty() || data.len() > BIG_MAX {
                return Err(errno::EINVAL);
            }
            plain(data.to_vec())
        }
        "dns_resolver" => {
            if data.len() <= 1 {
                return Err(errno::EINVAL);
            }
            plain(data.to_vec())
        }
        "asymmetric" => crypto::asymmetric(data),
        "encrypted" => crypto::encrypted_new(s, c, data),
        _ => Err(errno::ENODEV),
    }
}

/// Check and prepare `data` as the new payload of key `k` (of `kind`,
/// described `desc`).
pub fn preparse_update(
    s: &Store,
    c: &Caller,
    k: i32,
    kind: &str,
    desc: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, i32> {
    match kind {
        "user" => user_payload(data),
        "logon" => {
            logon_description(desc)?;
            user_payload(data)
        }
        "big_key" => {
            if data.is_empty() || data.len() > BIG_MAX {
                return Err(errno::EINVAL);
            }
            Ok(data.to_vec())
        }
        "encrypted" => crypto::encrypted_update(s, c, k, data),
        _ => Err(errno::EOPNOTSUPP),
    }
}

/// What reading key `k` gives (a key of a readable type, not a keyring).
pub fn read(s: &Store, c: &Caller, k: i32) -> Result<Vec<u8>, i32> {
    let key = s.keys.get(&k).ok_or(errno::ENOKEY)?;
    match key.kind.as_str() {
        "encrypted" => crypto::encrypted_read(s, c, key),
        _ => Ok(key.payload.clone()),
    }
}

/// How `/proc/keys` describes key `k` after its type.
pub fn describe(s: &Store, k: &Key) -> Vec<u8> {
    let mut out = k.desc.clone();
    if k.negative() {
        return out;
    }
    match k.kind.as_str() {
        "keyring" => {
            if k.links.is_empty() {
                out.extend_from_slice(b": empty");
            } else {
                out.extend_from_slice(format!(": {}", k.links.len()).as_bytes());
            }
        }
        "user" | "logon" | "dns_resolver" => {
            out.extend_from_slice(format!(": {}", k.payload.len()).as_bytes());
        }
        "big_key" => {
            let n = k.payload.len();
            let place = if n > BIG_FILE_THRESHOLD { "file" } else { "buff" };
            out.extend_from_slice(format!(": {n} [{place}]").as_bytes());
        }
        "asymmetric" => out.extend_from_slice(&crypto::asymmetric_describe(k)),
        "encrypted" => {}
        _ => {}
    }
    let _ = s;
    out
}

/// Whether asymmetric key `k` is signed by one of `signers` (keys, asymmetric
/// or not), as a keyring restriction checks it.
pub fn signed_by_any(s: &Store, k: &Key, signers: &[i32]) -> Result<(), i32> {
    crypto::signed_by_any(s, k, signers)
}

/// A `user` (or `logon`) payload: 1 to 32767 bytes.
fn user_payload(data: &[u8]) -> Result<Vec<u8>, i32> {
    if data.is_empty() || data.len() > USER_MAX {
        return Err(errno::EINVAL);
    }
    Ok(data.to_vec())
}

/// A `logon` key's description: a non-empty service before a colon.
fn logon_description(d: &[u8]) -> Result<(), i32> {
    match d.iter().position(|&b| b == b':') {
        Some(i) if i > 0 => Ok(()),
        _ => Err(errno::EINVAL),
    }
}

/// The types and operations that need cryptography.
mod crypto {
    use super::*;

    pub fn asymmetric(_data: &[u8]) -> Result<Prepared, i32> {
        Err(errno::ENODEV)
    }

    pub fn asymmetric_describe(_k: &Key) -> Vec<u8> {
        Vec::new()
    }

    pub fn encrypted_new(_s: &Store, _c: &Caller, _data: &[u8]) -> Result<Prepared, i32> {
        Err(errno::ENODEV)
    }

    pub fn encrypted_update(
        _s: &Store,
        _c: &Caller,
        _k: i32,
        _data: &[u8],
    ) -> Result<Vec<u8>, i32> {
        Err(errno::EOPNOTSUPP)
    }

    pub fn encrypted_read(_s: &Store, _c: &Caller, _k: &Key) -> Result<Vec<u8>, i32> {
        Err(errno::EOPNOTSUPP)
    }

    pub fn signed_by_any(_s: &Store, _k: &Key, _signers: &[i32]) -> Result<(), i32> {
        Err(errno::ENOKEY)
    }
}
