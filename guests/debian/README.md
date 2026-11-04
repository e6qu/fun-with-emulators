# Vendored Debian programs (test fixture)

Unmodified GNU coreutils, bash and git from Debian 12 (bookworm) for `aarch64`,
vendored so the end-to-end tests can run **real distribution binaries** — the
M1 goal of running programs from a Debian rootfs. They are dynamically linked
against glibc and run against the glibc runtime vendored under `guests/glibc`
(`/lib/ld-linux-aarch64.so.1` and `/lib/libc.so.6`).

| File | |
| --- | --- |
| `bin/true`, `bin/false` | Exit status 0 / 1. |
| `bin/echo` | Print arguments. |
| `bin/seq` | Generate a sequence. |
| `bin/env` | Print the environment. |
| `bin/cat` | Copy stdin to stdout. |
| `bin/sort` | Sort lines. |
| `bin/ls` | List a directory; pulls in a shared-library graph. |
| `bin/bash` | The GNU Bourne-Again shell; needs `libtinfo.so.6`. |
| `bin/git` | Git, the first of M2's target programs; needs `libpcre2-8.so.0` and `libz.so.1`. |
| `lib/libselinux.so.1` | Needed by `ls`; in turn needs `libpcre2-8.so.0`. |
| `lib/libpcre2-8.so.0` | Needed by `libselinux`. |
| `lib/libtinfo.so.6` | Needed by `bash`. |
| `lib/libz.so.1` | Needed by `git`. |

`ls` exercises a transitive dependency graph (`ls` → `libselinux` →
`libpcre2`, plus `libc`); `bash` is a large program needing `libtinfo`; the
simpler programs need only `libc.so.6`.

## Provenance

All from Debian 12 (bookworm) `aarch64`, built against glibc 2.36, so nothing
references a symbol version newer than the vendored libc provides (at most
`GLIBC_2.34`), from `https://deb.debian.org/debian/pool/main/`:

- `bin/*` (coreutils) from `coreutils_9.1-1_arm64.deb` (`c/coreutils/`)
- `lib/libselinux.so.1` from `libselinux1_3.4-1+b6_arm64.deb`
  (`libs/libselinux/`)
- `lib/libpcre2-8.so.0` from `libpcre2-8-0_10.42-1_arm64.deb` (`p/pcre2/`),
  renamed from its versioned filename to its soname
- `bin/bash` from `bash_5.2.15-2+b13_arm64.deb` (`b/bash/`)
- `lib/libtinfo.so.6` from `libtinfo6_6.4-4_arm64.deb` (`n/ncurses/`), renamed
  from its versioned filename to its soname
- `bin/git` (`usr/bin/git`) from `git_2.39.5-0+deb12u3_arm64.deb` (`g/git/`,
  SHA-256 `435176549a9f5c8bbadaa126b64a036b38ea34ad9f3eb128dc40b8407a5b5620`);
  the file's own SHA-256 is
  `54af380ba6ca1b36305358e99427a31ae4b0af5dc5cb6d0198c6f2f16e97651d`. The
  package's `usr/lib/git-core` helpers are links to this one binary, which
  the tests recreate
- `lib/libz.so.1` from `zlib1g_1.2.13.dfsg-1_arm64.deb` (`z/zlib/`, SHA-256
  `52b8b8a145bbe1956bba82034f77022cbef0c3d0885c9e32d9817a7932fe1913`),
  renamed from `libz.so.1.2.13` to its soname

Each `.deb` is an `ar` archive whose `data.tar.xz` holds the files.

## License

- GNU coreutils and bash: GNU GPL v3 or later — `COREUTILS-COPYRIGHT`,
  `BASH-COPYRIGHT` and `GPL-3.0.txt`.
- libselinux: public domain — `LIBSELINUX-COPYRIGHT`.
- PCRE2: BSD 3-clause — `LIBPCRE2-COPYRIGHT`.
- ncurses (libtinfo): MIT/X11 — `LIBTINFO-COPYRIGHT`.
- git: GNU GPL v2 (parts under compatible licenses, listed there) —
  `GIT-COPYRIGHT` and `GPL-2.0.txt`.
- zlib: the zlib License — `ZLIB-COPYRIGHT`.

All binaries are redistributed unmodified; source is available from Debian and
each project's upstream.
