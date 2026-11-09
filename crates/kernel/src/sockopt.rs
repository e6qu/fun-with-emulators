//! Socket options at the IP, IPv6 and TCP levels, which Linux and macOS
//! number apart, some with structures laid out apart.
//!
//! Each Linux option the host has is given its host level and name and how
//! its value is laid out ([`Form`]); one the host has not is refused
//! (`ENOPROTOOPT`), as Linux refuses an option it does not know. Levels
//! other than these pass through. On a Linux host every option is its own.
//!
//! The layouts that differ: the multicast TTL and loop flag are an `int`
//! or a byte to Linux and a byte to macOS; `ip_mreq_source` keeps its
//! source and interface in the other order; `group_req` and
//! `group_source_req` are packed to 4 bytes on macOS (8 on Linux), around a
//! `sockaddr_storage` whose header is macOS's (length and family bytes) not
//! Linux's (a 16-bit family); `IP_ADD_MEMBERSHIP` takes Linux's
//! `ip_mreqn` as well as `ip_mreq`, and `IP_MULTICAST_IF` an `ip_mreqn`, an
//! `ip_mreq` or an address, of which the host takes the address.

#[cfg(not(target_os = "linux"))]
use fwe_abi::errno;

/// How an option's value is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// As on the host.
    Same,
    /// An `int` or a byte to Linux, a byte to the host.
    Byte,
    /// `ip_mreq` or `ip_mreqn` to Linux, `ip_mreq` to the host.
    Mreq,
    /// An interface address in an `ip_mreqn`, an `ip_mreq` or alone.
    MulticastIf,
    /// `ip_mreq_source`, its last two fields swapped.
    MreqSource,
    /// `group_req`.
    GroupReq,
    /// `group_source_req`.
    GroupSourceReq,
}

#[cfg(not(target_os = "linux"))]
const IPPROTO_IP: u64 = 0;
#[cfg(not(target_os = "linux"))]
const IPPROTO_TCP: u64 = 6;
#[cfg(not(target_os = "linux"))]
const IPPROTO_IPV6: u64 = 41;

/// The host's level, name and value layout for Linux option `name` at
/// `level`: `ENOPROTOOPT` for one the host has not at the IP, IPv6 or TCP
/// level, the level and name as they are at any other.
pub fn to_host(level: u64, name: u64) -> Result<(i32, i32, Form), i32> {
    #[cfg(target_os = "linux")]
    {
        Ok((level as i32, name as i32, Form::Same))
    }
    #[cfg(not(target_os = "linux"))]
    {
        use Form::*;
        // The multicast group calls, the same at both IP levels.
        let group = |name: u64| -> Option<(i32, Form)> {
            Some(match name {
                42 => (libc::MCAST_JOIN_GROUP, GroupReq),
                45 => (libc::MCAST_LEAVE_GROUP, GroupReq),
                43 => (libc::MCAST_BLOCK_SOURCE, GroupSourceReq),
                44 => (libc::MCAST_UNBLOCK_SOURCE, GroupSourceReq),
                46 => (libc::MCAST_JOIN_SOURCE_GROUP, GroupSourceReq),
                47 => (libc::MCAST_LEAVE_SOURCE_GROUP, GroupSourceReq),
                _ => return None,
            })
        };
        let (host, form) = match level {
            IPPROTO_IP => match name {
                1 => (libc::IP_TOS, Same),
                2 => (libc::IP_TTL, Same),
                3 => (libc::IP_HDRINCL, Same),
                // IP_OPTIONS
                4 => (1, Same),
                32 => (libc::IP_MULTICAST_IF, MulticastIf),
                33 => (libc::IP_MULTICAST_TTL, Byte),
                34 => (libc::IP_MULTICAST_LOOP, Byte),
                35 => (libc::IP_ADD_MEMBERSHIP, Mreq),
                36 => (libc::IP_DROP_MEMBERSHIP, Mreq),
                37 => (libc::IP_UNBLOCK_SOURCE, MreqSource),
                38 => (libc::IP_BLOCK_SOURCE, MreqSource),
                39 => (libc::IP_ADD_SOURCE_MEMBERSHIP, MreqSource),
                40 => (libc::IP_DROP_SOURCE_MEMBERSHIP, MreqSource),
                _ => group(name).ok_or(errno::ENOPROTOOPT)?,
            },
            IPPROTO_IPV6 => match name {
                16 => (libc::IPV6_UNICAST_HOPS, Same),
                17 => (libc::IPV6_MULTICAST_IF, Same),
                18 => (libc::IPV6_MULTICAST_HOPS, Same),
                19 => (libc::IPV6_MULTICAST_LOOP, Same),
                20 => (libc::IPV6_JOIN_GROUP, Same),
                21 => (libc::IPV6_LEAVE_GROUP, Same),
                26 => (libc::IPV6_V6ONLY, Same),
                // IPV6_RTHDR: a routing header, as RFC 3542 has it.
                57 => (51, Same),
                67 => (libc::IPV6_TCLASS, Same),
                _ => group(name).ok_or(errno::ENOPROTOOPT)?,
            },
            IPPROTO_TCP => match name {
                1 => (libc::TCP_NODELAY, Same),
                2 => (libc::TCP_MAXSEG, Same),
                // TCP_CORK: held until uncorked, as TCP_NOPUSH holds it.
                3 => (libc::TCP_NOPUSH, Same),
                // TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
                4 => (libc::TCP_KEEPALIVE, Same),
                5 => (libc::TCP_KEEPINTVL, Same),
                6 => (libc::TCP_KEEPCNT, Same),
                23 => (libc::TCP_FASTOPEN, Same),
                // TCP_NOTSENT_LOWAT
                25 => (0x201, Same),
                _ => return Err(errno::ENOPROTOOPT),
            },
            _ => return Ok((level as i32, name as i32, Same)),
        };
        Ok((level as i32, host, form))
    }
}

/// A Linux `sockaddr` at the start of `linux` (a `sockaddr_storage`'s
/// worth) as the host's, into `host`.
#[cfg(not(target_os = "linux"))]
fn sockaddr_to_host(linux: &[u8], host: &mut [u8]) -> Result<(), i32> {
    let family = u16::from_ne_bytes([linux[0], linux[1]]);
    let (hf, len) = match family as u64 {
        fwe_abi::socket::AF_INET => (libc::AF_INET, 16),
        fwe_abi::socket::AF_INET6 => (libc::AF_INET6, 28),
        _ => return Err(errno::EINVAL),
    };
    host[0] = len as u8;
    host[1] = hf as u8;
    host[2..len].copy_from_slice(&linux[2..len]);
    Ok(())
}

/// Linux value `val` of an option of layout `form` as the host takes it.
pub fn value_to_host(form: Form, val: &[u8]) -> Result<Vec<u8>, i32> {
    #[cfg(target_os = "linux")]
    {
        let _ = form;
        Ok(val.to_vec())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let need = |n: usize| if val.len() < n { Err(errno::EINVAL) } else { Ok(()) };
        Ok(match form {
            Form::Same => val.to_vec(),
            Form::Byte => {
                need(1)?;
                let v = if val.len() >= 4 {
                    i32::from_ne_bytes(val[..4].try_into().unwrap())
                } else {
                    i32::from(val[0])
                };
                // Linux takes -1 as its default TTL.
                if v == -1 { vec![1] } else { vec![u8::try_from(v).map_err(|_| errno::EINVAL)?] }
            }
            Form::Mreq => {
                need(8)?;
                val[..8].to_vec()
            }
            Form::MulticastIf => {
                need(4)?;
                if val.len() >= 8 { val[4..8].to_vec() } else { val[..4].to_vec() }
            }
            Form::MreqSource => {
                need(12)?;
                [&val[0..4], &val[8..12], &val[4..8]].concat()
            }
            Form::GroupReq => {
                need(136)?;
                let mut h = vec![0u8; 132];
                h[..4].copy_from_slice(&val[..4]);
                sockaddr_to_host(&val[8..136], &mut h[4..132])?;
                h
            }
            Form::GroupSourceReq => {
                need(264)?;
                let mut h = vec![0u8; 260];
                h[..4].copy_from_slice(&val[..4]);
                sockaddr_to_host(&val[8..136], &mut h[4..132])?;
                sockaddr_to_host(&val[136..264], &mut h[132..260])?;
                h
            }
        })
    }
}

/// The host's value `host` of an option of layout `form` as Linux gives
/// it to a caller with room for `cap` bytes.
pub fn value_to_linux(form: Form, host: &[u8], cap: usize) -> Vec<u8> {
    match form {
        // Linux gives an `int` to a caller with room for one.
        Form::Byte if cap >= 4 => {
            i32::from(host.first().copied().unwrap_or(0)).to_ne_bytes().to_vec()
        }
        _ => host.to_vec(),
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn group_requests_take_the_hosts_layout() {
        let mut linux = vec![0u8; 136];
        linux[..4].copy_from_slice(&7u32.to_ne_bytes());
        linux[8..10].copy_from_slice(&2u16.to_ne_bytes());
        linux[12..16].copy_from_slice(&[224, 0, 0, 1]);
        let (_, name, form) = to_host(0, 42).unwrap();
        assert_eq!(name, libc::MCAST_JOIN_GROUP);
        let h = value_to_host(form, &linux).unwrap();
        assert_eq!(h.len(), 132);
        assert_eq!(&h[..4], &7u32.to_ne_bytes());
        assert_eq!(&h[4..6], &[16, libc::AF_INET as u8]);
        assert_eq!(&h[8..12], &[224, 0, 0, 1]);
    }

    #[test]
    fn options_the_host_lacks_are_refused() {
        assert_eq!(to_host(0, u32::MAX as u64), Err(errno::ENOPROTOOPT));
        assert_eq!(to_host(6, 12), Err(errno::ENOPROTOOPT));
        assert_eq!(to_host(0, 1).unwrap().1, libc::IP_TOS);
        assert_eq!(to_host(41, 26).unwrap().1, libc::IPV6_V6ONLY);
    }

    #[test]
    fn source_requests_swap_their_last_fields() {
        let v: Vec<u8> = (0..12).collect();
        let h = value_to_host(Form::MreqSource, &v).unwrap();
        assert_eq!(h, [0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7]);
        assert_eq!(value_to_host(Form::Byte, &5i32.to_ne_bytes()).unwrap(), [5]);
        assert_eq!(value_to_linux(Form::Byte, &[5], 4), 5i32.to_ne_bytes());
    }
}
