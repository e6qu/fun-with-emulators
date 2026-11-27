# Vendored Debian programs (test fixture)

Unmodified GNU coreutils, bash, git, SQLite and lighttpd from Debian 13
(trixie) for `aarch64`, vendored so the end-to-end tests run real
distribution binaries from a Debian rootfs. They are dynamically linked
against the glibc runtime vendored under `guests/glibc`
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
| `bin/git` | Git; needs `libpcre2-8.so.0` and `libz.so.1`. |
| `bin/sqlite3` | The SQLite shell; needs `libsqlite3.so.0`, `libreadline.so.8` and `libz.so.1`. |
| `bin/lighttpd` | The lighttpd web server; needs `libpcre2-8.so.0` and `libnettle.so.8`. |
| `lighttpd/mod_cgi.so`, `lighttpd/mod_dirlisting.so` | lighttpd modules, loaded from `/usr/lib/lighttpd`. |
| `lib/libselinux.so.1` | Needed by `ls`; in turn needs `libpcre2-8.so.0`. |
| `lib/libcap.so.2` | Needed by `ls`. |
| `lib/libpcre2-8.so.0` | Needed by `libselinux`, `git` and `lighttpd`. |
| `lib/libtinfo.so.6` | Needed by `bash`. |
| `lib/libz.so.1` | Needed by `git` and `sqlite3`. |
| `lib/libsqlite3.so.0` | The SQLite library; needs `libm.so.6` (vendored with glibc). |
| `lib/libreadline.so.8` | Needed by `sqlite3`; in turn needs `libtinfo.so.6`. |
| `lib/libnettle.so.8` | Needed by `lighttpd`. |

`ls` exercises a transitive dependency graph (`ls` → `libselinux` →
`libpcre2`, and `libcap`, plus `libc`); `bash` is a large program needing
`libtinfo`; the simpler programs need only `libc.so.6`. Debian 13 builds
them all for BTI and with GCC 14, whose code computes in `x18` where it is
free (git's SHA-1 does).

## Provenance

All from Debian 13 (trixie) `aarch64`, built against glibc 2.41, so nothing
references a symbol version newer than the vendored glibc 2.41 provides (at
most `GLIBC_2.38`), from `https://deb.debian.org/debian/pool/main/`. Each
library is its package's versioned file, renamed to its soname:

| Files | Package (pool directory) | SHA-256 of the package |
| --- | --- | --- |
| `bin/true`, `false`, `echo`, `seq`, `env`, `cat`, `sort`, `ls` | `coreutils_9.7-3_arm64.deb` (`c/coreutils/`) | `99b2531e8d16e4f2d3f239ae3cb57913ec1f43764d2d6cd5c69154cbb1e57f3e` |
| `bin/bash` | `bash_5.2.37-2+b10_arm64.deb` (`b/bash/`) | `9e2d2b3646b250f53be79b6128d9cff5e99cc5ff4a8c84e58efab59ad9bb0ddc` |
| `bin/git` (`usr/bin/git`; the package's `usr/lib/git-core` helpers are links to it, which the tests make) | `git_2.47.3-0+deb13u1_arm64.deb` (`g/git/`) | `8c6b1e96b226211260d7814472215a8a1ed38ee37400c421d454391c1807cb5a` |
| `bin/sqlite3` | `sqlite3_3.46.1-7+deb13u2_arm64.deb` (`s/sqlite3/`) | `ee924a55337dcb0a017122ccee0f7587de355154455f774eff33f09b36cdd2c6` |
| `bin/lighttpd` (`usr/sbin/lighttpd`), `lighttpd/*.so` (`usr/lib/lighttpd/`) | `lighttpd_1.4.79-2_arm64.deb` (`l/lighttpd/`) | `52b3dd58f9bf55154d00d8f54a914bdcb88113ba62323f2ed325f5ae20000379` |
| `lib/libselinux.so.1` | `libselinux1_3.8.1-1_arm64.deb` (`libs/libselinux/`) | `fc13da4c7783b8f4361d92ef1045931f298d1b0ac78ed1a85c2232615f49fc6f` |
| `lib/libcap.so.2` | `libcap2_2.75-10+deb13u1+b3_arm64.deb` (`libc/libcap2/`) | `863aa5b9cdf6f80010b48982d4639126b09a89eeef2c0c5c7be226297c811581` |
| `lib/libpcre2-8.so.0` | `libpcre2-8-0_10.46-1~deb13u3_arm64.deb` (`p/pcre2/`) | `1a02b7129990690ea095fd35d7ace6853742923d158019e1fb4ef27efd2c51a7` |
| `lib/libtinfo.so.6` | `libtinfo6_6.5+20250216-2_arm64.deb` (`n/ncurses/`) | `2a747f7fff3c2347c357387a7133df997410f07ba1b1df1a1461a97bd7fbc2fc` |
| `lib/libz.so.1` | `zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_arm64.deb` (`z/zlib/`) | `0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff` |
| `lib/libsqlite3.so.0` | `libsqlite3-0_3.46.1-7+deb13u2_arm64.deb` (`s/sqlite3/`) | `5b09efca71cb7a16d67f5453af3989ae1a84fe6b68c6dd3913de527cb0ca23aa` |
| `lib/libreadline.so.8` | `libreadline8t64_8.2-6_arm64.deb` (`r/readline/`) | `f78ff432b2a627bc04f7eef0e6e2696501c9e06feca748a5b741d5e594429033` |
| `lib/libnettle.so.8` | `libnettle8t64_3.10.1-1_arm64.deb` (`n/nettle/`) | `16107ce5a7b522da021fa8aba42d42af9c5e90ddabfcda3710aff6ea95808ee0` |

`bin/git`'s own SHA-256 is
`a0e562e4bd3c4c79379e91d8c07a10104b2cefe8fac966dc6bd4874a57a807f3`. Each
`.deb` is an `ar` archive whose `data.tar.xz` holds the files, and each
`*-COPYRIGHT` file is its package's `usr/share/doc/<package>/copyright`.

## Fetched, not vendored

Programs too large to keep here are listed in `fetch/`, one file per
test: each line is a Debian 13 `arm64` package's pool path and its SHA-256
from the trixie index. Each manifest is a whole system: the packages its
header names (`# seeds:`), every package Debian marks Essential (glibc,
dash and bash, coreutils...), and every package they depend on, as
`tools/debian-manifest.py` makes it from that header (`python3
tools/debian-manifest.py guests/debian/fetch/<name>.txt` makes it again
from the current index). The test downloads them from `deb.debian.org`
(or, once a newer version has replaced one there, from the snapshot of the
archive the manifest names, `# snapshot:`, on `snapshot.debian.org`),
checks each checksum, unpacks them into its root filesystem, `base-files`
first (its links, `/bin` to `/usr/bin` and the others, as debootstrap
makes them), and caches them under `target/fetched-packages`
(`FWE_FETCH_CACHE` overrides it; CI caches it). Each root runs with its
own C library, not the vendored one. Nothing fetched is redistributed in
this repository.

| Manifest | Program (beside the Essential packages) | Size |
| --- | --- | --- |
| `fetch/node.txt` | Node.js 20 with V8, the modules Debian packages apart from it, and its libraries: OpenSSL, ICU, libuv, c-ares, nghttp2, brotli, libstdc++ | 49 MB |
| `fetch/apt.txt` | apt 3.0 and dpkg 1.22 with the tools dpkg runs, and their libraries (libsystemd, libseccomp, Sequoia's `sqv` and others) | 31 MB |
| `fetch/apt-repo.txt` | GNU hello 2.10, which the apt test serves from a local repository rather than unpacking (the seed alone, `# only-seeds: yes`) | 53 kB |
| `fetch/rust.txt` | rustc 1.85 with its standard library and LLVM 19, Cargo with libcurl, libgit2 and libssh2, GCC 14 and GNU binutils (`ld`), and the glibc files a program links with | 178 MB |
| `fetch/python.txt` | Python 3.13 and its standard library, with the libraries its C modules use: OpenSSL, SQLite, expat, zlib, bzip2, xz, libffi, ncurses, readline, libuuid, and `media-types` | 32 MB |
| `fetch/gcc.txt` | GCC 14 (the driver, `cc1`, `collect2`) with GMP, MPFR, MPC and ISL, GNU binutils (`as`, `ld`, `ar`), and the glibc files a program builds with (`libc6-dev`, `linux-libc-dev`) | 76 MB |
| `fetch/clang.txt` | clang 19 with LLVM 19 and its libraries, GNU binutils, and the glibc, GCC and libstdc++ files a program builds and links with | 103 MB |
| `fetch/go.txt` | Go 1.24: the `go` command, its tools and the standard library's sources | 74 MB |
| `fetch/podman.txt` | podman 5.4, conmon, crun, catatonit, netavark, the containers configuration, and the libraries they load (gpgme, libseccomp, libsubid, glib, libsystemd, yajl and theirs) | 63 MB |
| `fetch/apps.txt` | what the application tests' programs load: GTK 3, NSS, ALSA's library, GBM, the Vulkan loader, WebKitGTK 4.1, libsecret, fonts and fontconfig, D-Bus, and their libraries ([`guests/apps`](../apps/README.md)) | 184 MB |

## License

- GNU coreutils and bash: GNU GPL v3 or later — `COREUTILS-COPYRIGHT`,
  `BASH-COPYRIGHT` and `GPL-3.0.txt`.
- libselinux: public domain (parts GNU GPL v2, listed there) —
  `LIBSELINUX-COPYRIGHT` and `GPL-2.0.txt`.
- libcap: BSD 3-clause or GNU GPL v2 — `LIBCAP-COPYRIGHT`.
- PCRE2: BSD 3-clause — `LIBPCRE2-COPYRIGHT`.
- ncurses (libtinfo): MIT/X11 — `LIBTINFO-COPYRIGHT`.
- git: GNU GPL v2 (parts under compatible licenses, listed there) —
  `GIT-COPYRIGHT` and `GPL-2.0.txt`.
- zlib: the zlib License — `ZLIB-COPYRIGHT`.
- SQLite: public domain — `SQLITE-COPYRIGHT`.
- GNU readline: GNU GPL v3 or later — `READLINE-COPYRIGHT` and
  `GPL-3.0.txt`.
- lighttpd: BSD 3-clause (parts under other permissive licenses, listed
  there) — `LIGHTTPD-COPYRIGHT`.
- Nettle: GNU LGPL v3 or later, or GNU GPL v2 or later (redistributed here
  under the GPL v2) — `NETTLE-COPYRIGHT` and `GPL-2.0.txt`.

All binaries are redistributed unmodified; source is available from Debian and
each project's upstream.
