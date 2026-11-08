//! Terminal attributes (`termios`).
//!
//! `TCGETS`/`TCSETS`/`TCSETSW`/`TCSETSF` carry a `struct termios`. On Linux the
//! guest layout is the host layout, so the `ioctl` passes through. On macOS the
//! structure and its flag bits differ — macOS `tcflag_t` is 64-bit, the control
//! characters are ordered differently, and almost every flag sits in a
//! different bit — so each field is translated with [`libc::tcgetattr`] /
//! [`libc::tcsetattr`]. Baud is reported as a fixed `B38400`; a pty does not
//! have a meaningful line rate.

/// `TCGETS`: read terminal attributes into the guest `termios` at `arg`.
///
/// # Safety
/// `arg` must point to a writable Linux `termios`.
pub unsafe fn tcgetattr(fd: i32, arg: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: guest and host `termios` share a layout; the host validates arg.
    unsafe {
        crate::host::ret(libc::ioctl(fd, libc::TCGETS, arg as *mut libc::termios) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees a writable Linux termios at arg.
    unsafe {
        imp::tcgetattr(fd, arg)
    }
}

/// `TCSETS`/`TCSETSW`/`TCSETSF` (selected by `action`): apply the guest
/// `termios` at `arg`.
///
/// # Safety
/// `arg` must point to a readable Linux `termios`.
pub unsafe fn tcsetattr(fd: i32, action: u64, arg: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: guest and host `termios` share a layout; the host validates arg.
    unsafe {
        use fwe_abi::ioctl;
        let req = match action {
            ioctl::TCSETS => libc::TCSETS,
            ioctl::TCSETSW => libc::TCSETSW,
            ioctl::TCSETSF => libc::TCSETSF,
            _ => return fwe_abi::err(fwe_abi::errno::EINVAL),
        };
        crate::host::ret(libc::ioctl(fd, req, arg as *const libc::termios) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees a readable Linux termios at arg.
    unsafe {
        imp::tcsetattr(fd, action, arg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::ioctl;
    use fwe_abi::term::*;

    /// Open a pty slave, flip it into raw mode through the translation, and
    /// confirm the change reads back. Exercises the host `termios` passthrough
    /// on Linux and the field-by-field translation on macOS.
    #[test]
    fn raw_mode_round_trip() {
        let mut master = 0i32;
        let mut slave = 0i32;
        // SAFETY: valid out pointers; the rest are NULL (defaults).
        let r = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if r != 0 {
            eprintln!("skipping: openpty unavailable");
            return;
        }

        let mut t = [0u8; TERMIOS_SIZE];
        let arg = t.as_mut_ptr() as u64;
        // SAFETY: `t` is a writable Linux termios.
        assert_eq!(unsafe { tcgetattr(slave, arg) }, 0);

        // A fresh pty is in cooked mode: ICANON and ECHO are set.
        let lflag = u32::from_ne_bytes(t[12..16].try_into().unwrap());
        assert_ne!(lflag & ICANON, 0, "fresh pty should be canonical");
        assert_ne!(lflag & ECHO, 0, "fresh pty should echo");

        // Clear them (raw) and set VMIN=1/VTIME=0.
        t[12..16].copy_from_slice(&(lflag & !(ICANON | ECHO)).to_ne_bytes());
        t[17 + VMIN] = 1;
        t[17 + VTIME] = 0;
        // SAFETY: `t` is a readable Linux termios (pointer re-derived after the
        // edits so the writes above are observed).
        assert_eq!(unsafe { tcsetattr(slave, ioctl::TCSETS, t.as_ptr() as u64) }, 0);

        // Read back and confirm the raw settings stuck.
        let mut t2 = [0u8; TERMIOS_SIZE];
        // SAFETY: `t2` is a writable Linux termios.
        assert_eq!(unsafe { tcgetattr(slave, t2.as_mut_ptr() as u64) }, 0);
        let lflag2 = u32::from_ne_bytes(t2[12..16].try_into().unwrap());
        assert_eq!(lflag2 & (ICANON | ECHO), 0, "raw mode should clear ICANON/ECHO");
        assert_eq!(t2[17 + VMIN], 1, "VMIN should round-trip");

        // SAFETY: plain host cleanup.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::guest;
    use crate::host::tty_error;
    use fwe_abi::term::*;
    use fwe_abi::{err, errno, ioctl};

    /// `(linux_bit, host_bit)` pairs for a flag field.
    type FlagMap = &'static [(u32, u64)];

    const IFLAG: FlagMap = &[
        (IGNBRK, libc::IGNBRK),
        (BRKINT, libc::BRKINT),
        (IGNPAR, libc::IGNPAR),
        (PARMRK, libc::PARMRK),
        (INPCK, libc::INPCK),
        (ISTRIP, libc::ISTRIP),
        (INLCR, libc::INLCR),
        (IGNCR, libc::IGNCR),
        (ICRNL, libc::ICRNL),
        (IXON, libc::IXON),
        (IXANY, libc::IXANY),
        (IXOFF, libc::IXOFF),
        (IMAXBEL, libc::IMAXBEL),
        (IUTF8, libc::IUTF8),
    ];

    const OFLAG: FlagMap = &[
        (OPOST, libc::OPOST),
        (ONLCR, libc::ONLCR),
        (OCRNL, libc::OCRNL),
        (ONOCR, libc::ONOCR),
        (ONLRET, libc::ONLRET),
        (OFILL, libc::OFILL),
        (OFDEL, libc::OFDEL),
    ];

    const CFLAG: FlagMap = &[
        (CSTOPB, libc::CSTOPB),
        (CREAD, libc::CREAD),
        (PARENB, libc::PARENB),
        (PARODD, libc::PARODD),
        (HUPCL, libc::HUPCL),
        (CLOCAL, libc::CLOCAL),
    ];

    const LFLAG: FlagMap = &[
        (ISIG, libc::ISIG),
        (ICANON, libc::ICANON),
        (ECHO, libc::ECHO),
        (ECHOE, libc::ECHOE),
        (ECHOK, libc::ECHOK),
        (ECHONL, libc::ECHONL),
        (NOFLSH, libc::NOFLSH),
        (TOSTOP, libc::TOSTOP),
        (ECHOCTL, libc::ECHOCTL),
        (ECHOPRT, libc::ECHOPRT),
        (ECHOKE, libc::ECHOKE),
        (FLUSHO, libc::FLUSHO),
        (PENDIN, libc::PENDIN),
        (IEXTEN, libc::IEXTEN),
        (EXTPROC, libc::EXTPROC),
    ];

    /// `(linux_index, host_index)` pairs for the control characters.
    const CC: &[(usize, usize)] = &[
        (VINTR, libc::VINTR),
        (VQUIT, libc::VQUIT),
        (VERASE, libc::VERASE),
        (VKILL, libc::VKILL),
        (VEOF, libc::VEOF),
        (VTIME, libc::VTIME),
        (VMIN, libc::VMIN),
        (VSTART, libc::VSTART),
        (VSTOP, libc::VSTOP),
        (VSUSP, libc::VSUSP),
        (VEOL, libc::VEOL),
        (VREPRINT, libc::VREPRINT),
        (VDISCARD, libc::VDISCARD),
        (VWERASE, libc::VWERASE),
        (VLNEXT, libc::VLNEXT),
        (VEOL2, libc::VEOL2),
    ];

    fn l2h(v: u32, map: FlagMap) -> libc::tcflag_t {
        let mut out: libc::tcflag_t = 0;
        for &(l, h) in map {
            if v & l != 0 {
                out |= h;
            }
        }
        out
    }

    fn h2l(v: libc::tcflag_t, map: FlagMap) -> u32 {
        let mut out: u32 = 0;
        for &(l, h) in map {
            if v & h != 0 {
                out |= l;
            }
        }
        out
    }

    fn csize_l2h(cflag: u32) -> libc::tcflag_t {
        match cflag & CSIZE {
            CS5 => libc::CS5,
            CS6 => libc::CS6,
            CS7 => libc::CS7,
            _ => libc::CS8,
        }
    }

    fn csize_h2l(cflag: libc::tcflag_t) -> u32 {
        let c = cflag & libc::CSIZE;
        if c == libc::CS5 {
            CS5
        } else if c == libc::CS6 {
            CS6
        } else if c == libc::CS7 {
            CS7
        } else {
            CS8
        }
    }

    pub unsafe fn tcgetattr(fd: i32, arg: u64) -> i64 {
        // SAFETY: a zeroed termios is a valid out-parameter.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: plain host call.
        if unsafe { libc::tcgetattr(fd, &mut t) } < 0 {
            return tty_error();
        }
        let iflag = h2l(t.c_iflag, IFLAG);
        let oflag = h2l(t.c_oflag, OFLAG);
        let cflag = h2l(t.c_cflag, CFLAG) | csize_h2l(t.c_cflag) | B38400;
        let lflag = h2l(t.c_lflag, LFLAG);
        let mut cc = [0u8; NCCS];
        for &(l, h) in CC {
            cc[l] = t.c_cc[h];
        }
        let mut out = [0u8; TERMIOS_SIZE];
        for (i, flag) in [iflag, oflag, cflag, lflag].into_iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&flag.to_ne_bytes());
        }
        // c_line (out[16]) stays 0.
        out[17..17 + NCCS].copy_from_slice(&cc);
        guest!(crate::uaccess::write_from(arg, &out));
        0
    }

    pub unsafe fn tcsetattr(fd: i32, action: u64, arg: u64) -> i64 {
        let act = match action {
            ioctl::TCSETS => libc::TCSANOW,
            ioctl::TCSETSW => libc::TCSADRAIN,
            ioctl::TCSETSF => libc::TCSAFLUSH,
            _ => return err(errno::EINVAL),
        };
        let raw: [u8; TERMIOS_SIZE] = guest!(crate::uaccess::read(arg));
        let word = |i: usize| u32::from_ne_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
        let (iflag, oflag, cflag, lflag) = (word(0), word(1), word(2), word(3));
        // SAFETY: a zeroed termios is a valid starting point.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        t.c_iflag = l2h(iflag, IFLAG);
        t.c_oflag = l2h(oflag, OFLAG);
        t.c_cflag = l2h(cflag, CFLAG) | csize_l2h(cflag);
        t.c_lflag = l2h(lflag, LFLAG);
        for &(l, h) in CC {
            t.c_cc[h] = raw[17 + l];
        }
        // The characters Linux has none of (the status key, Ctrl-T, and the
        // delayed suspend, Ctrl-Y) disabled, as on Linux: 0 would be NUL.
        t.c_cc[libc::VSTATUS] = libc::_POSIX_VDISABLE as libc::cc_t;
        t.c_cc[libc::VDSUSP] = libc::_POSIX_VDISABLE as libc::cc_t;
        t.c_ispeed = 38400;
        t.c_ospeed = 38400;
        // SAFETY: `t` is a fully initialized termios.
        if unsafe { libc::tcsetattr(fd, act, &t) } < 0 {
            return tty_error();
        }
        0
    }
}
