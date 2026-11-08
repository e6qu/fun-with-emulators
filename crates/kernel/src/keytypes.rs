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
        "encrypted" => crypto::encrypted_new(s, c, desc.ok_or(errno::EINVAL)?, data),
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
        "encrypted" => crypto::encrypted_update(s, c, s.keys.get(&k).ok_or(errno::ENOKEY)?, data),
        _ => Err(errno::EOPNOTSUPP),
    }
}

/// What reading key `k` gives (a key of a readable type, not a keyring)
/// into a buffer of `len` bytes: an encrypted key read into a shorter one
/// than it needs gives only its length (bytes not copied), without its
/// master key.
pub fn read(s: &Store, c: &Caller, k: i32, len: usize) -> Result<Vec<u8>, i32> {
    let key = s.keys.get(&k).ok_or(errno::ENOKEY)?;
    match key.kind.as_str() {
        "encrypted" => crypto::encrypted_read(s, c, key, len),
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

/// Whether asymmetric key `k` is signed by key `trusted` (or a key in
/// keyring `trusted`), or with `dest` by a key in that keyring, as the
/// `key_or_keyring` restriction checks it.
pub fn signed_by(s: &Store, k: &Key, trusted: Option<&Key>, dest: Option<&Key>) -> Result<(), i32> {
    crypto::signed_by(s, k, trusted, dest)
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

/// The types and operations that need cryptography
/// ([`crate::keycrypto`]).
pub(crate) mod crypto {
    use super::*;
    use crate::keycrypto::{self, Asym, EncryptedKey};
    use crate::snapshot::{Dec, Enc};

    /// An `asymmetric` payload: a certificate or key, parsed and kept
    /// encoded; its description the one Linux makes if none is given.
    pub fn asymmetric(data: &[u8]) -> Result<Prepared, i32> {
        let a = keycrypto::parse_asymmetric(data)?;
        let desc = (!a.description.is_empty()).then(|| a.description.clone());
        Ok(Prepared { payload: a.encode(), desc })
    }

    /// The asymmetric key `k` holds.
    pub fn asym(k: &Key) -> Result<Asym, i32> {
        Asym::decode(&k.payload).ok_or(errno::EINVAL)
    }

    /// `/proc/keys`' words for an asymmetric key, after its description:
    /// its kind and algorithm, and the end of its identifier.
    pub fn asymmetric_describe(k: &Key) -> Vec<u8> {
        let Ok(a) = asym(k) else { return Vec::new() };
        let kind = if a.private { "PKCS8" } else { "X509" };
        let id = &a.fingerprint[a.fingerprint.len().saturating_sub(4)..];
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        format!(": {kind}.rsa {hex} []").into_bytes()
    }

    fn encode(e: &EncryptedKey) -> Vec<u8> {
        let mut enc = Enc::new();
        enc.bytes(&e.format);
        enc.bytes(&e.master_desc);
        enc.bytes(&e.datalen);
        enc.bytes(&e.iv);
        enc.bytes(&e.decrypted);
        enc.into_bytes()
    }

    fn decode(b: &[u8]) -> Result<EncryptedKey, i32> {
        let mut d = Dec::new(b);
        let (format, master_desc, datalen) = (d.bytes(), d.bytes(), d.bytes());
        let iv: [u8; 16] = d.bytes().try_into().map_err(|_| errno::EINVAL)?;
        let decrypted = d.bytes();
        d.finish().map_err(|_| errno::EINVAL)?;
        Ok(EncryptedKey { format, master_desc, datalen, iv, decrypted })
    }

    /// The payload of the master key an encrypted key names: a `user` key
    /// (else a `logon` key) of that whole description the caller's keyrings
    /// reach, as Linux's `request_user_key` finds it.
    fn master<'a>(s: &'a Store, c: &'a Caller) -> impl Fn(&[u8]) -> Option<Vec<u8>> + 'a {
        move |desc: &[u8]| {
            ["user", "logon"].iter().find_map(|kind| {
                let k = s.search_process(c, kind, desc).ok()?;
                Some(s.keys.get(&k)?.payload.clone())
            })
        }
    }

    pub fn encrypted_new(s: &Store, c: &Caller, desc: &[u8], data: &[u8]) -> Result<Prepared, i32> {
        let key =
            EncryptedKey::instantiate(desc, data, &master(s, c), &mut crate::host::fill_random)?;
        Ok(Prepared { payload: encode(&key), desc: None })
    }

    pub fn encrypted_update(_s: &Store, _c: &Caller, k: &Key, data: &[u8]) -> Result<Vec<u8>, i32> {
        let key = decode(&k.payload)?.update(data)?;
        Ok(encode(&key))
    }

    pub fn encrypted_read(s: &Store, c: &Caller, k: &Key, len: usize) -> Result<Vec<u8>, i32> {
        let key = decode(&k.payload)?;
        if len < key.read_len() {
            return Ok(vec![0; key.read_len()]);
        }
        key.read(&master(s, c))
    }

    /// The `key_or_keyring` restriction's check (Linux's
    /// `restrict_link_by_key_or_keyring`): the signer is key `trusted`
    /// when it is the key the certificate names, or the key keyring
    /// `trusted` holds that it names; else, with `dest`, one in the
    /// destination keyring. None found is `ENOKEY`.
    pub fn signed_by(
        s: &Store,
        k: &Key,
        trusted: Option<&Key>,
        dest: Option<&Key>,
    ) -> Result<(), i32> {
        let subject = asym(k)?;
        keycrypto::signature_precheck(&subject)?;
        let in_ring = |ring: &Key| -> Option<Asym> {
            let found = ring
                .links
                .iter()
                .filter_map(|l| s.keys.get(l))
                .filter(|o| o.kind == "asymmetric")
                .filter_map(|o| asym(o).ok())
                .find(|o| keycrypto::keyring_signer_matches(&subject, o))?;
            keycrypto::keyring_signer_accepted(&subject, &found).then_some(found)
        };
        let mut signer = None;
        if let Some(t) = trusted {
            if t.kind == "keyring" {
                signer = in_ring(t);
            } else if t.kind == "asymmetric" {
                let t = asym(t)?;
                if keycrypto::keyring_signer_matches(&subject, &t) {
                    signer = Some(t);
                }
            } else {
                return Err(errno::EOPNOTSUPP);
            }
        }
        if signer.is_none()
            && let Some(d) = dest
        {
            signer = in_ring(d);
        }
        let signer = signer.ok_or(errno::ENOKEY)?;
        keycrypto::verify_cert_signature(&subject, &signer)
    }
}
