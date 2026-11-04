# Vendored Debian programs (test fixture)

Unmodified GNU coreutils, bash, git, SQLite and lighttpd from Debian 12
(bookworm) for `aarch64`,
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
| `bin/sqlite3` | The SQLite shell, M2's database; needs `libsqlite3.so.0`, `libreadline.so.8` and `libz.so.1`. |
| `bin/lighttpd` | The lighttpd web server, M2's web server; needs `libpcre2-8.so.0`, `libnettle.so.8` and `libxxhash.so.0`. |
| `lighttpd/mod_cgi.so`, `lighttpd/mod_dirlisting.so` | lighttpd modules, loaded from `/usr/lib/lighttpd`. |
| `lib/libselinux.so.1` | Needed by `ls`; in turn needs `libpcre2-8.so.0`. |
| `lib/libpcre2-8.so.0` | Needed by `libselinux`. |
| `lib/libtinfo.so.6` | Needed by `bash`. |
| `lib/libz.so.1` | Needed by `git` and `sqlite3`. |
| `lib/libsqlite3.so.0` | The SQLite library; needs `libm.so.6` (vendored with glibc). |
| `lib/libreadline.so.8` | Needed by `sqlite3`; in turn needs `libtinfo.so.6`. |
| `lib/libnettle.so.8`, `lib/libxxhash.so.0` | Needed by `lighttpd`. |

`ls` exercises a transitive dependency graph (`ls` → `libselinux` →
`libpcre2`, plus `libc`); `bash` is a large program needing `libtinfo`; the
simpler programs need only `libc.so.6`.

## Provenance

All from Debian 12 (bookworm) `aarch64`, built against glibc 2.36, so nothing
references a symbol version newer than the vendored glibc 2.36 provides (at
most `GLIBC_2.36`, which lighttpd needs), from `https://deb.debian.org/debian/pool/main/`:

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

- `bin/sqlite3` from `sqlite3_3.40.1-2+deb12u2_arm64.deb` (`s/sqlite3/`,
  SHA-256 `1f14747c3e019164bc6ed4c1aba47d9705fd7ec990594669b073cd8e3ddc737d`)
- `lib/libsqlite3.so.0` from `libsqlite3-0_3.40.1-2+deb12u2_arm64.deb`
  (`s/sqlite3/`, SHA-256
  `a690f7f2aa6435bd1fd7cbbd2216acb9acbb8c48c9721f2c195766375439eb13`),
  renamed from `libsqlite3.so.0.8.6` to its soname
- `lib/libreadline.so.8` from `libreadline8_8.2-1.3_arm64.deb`
  (`r/readline/`, SHA-256
  `f3b162b7c1e05430607e792ebdbfc417cbd1f1d32cf83664133ae63d811a72d2`),
  renamed from `libreadline.so.8.2` to its soname
- `bin/lighttpd` (`usr/sbin/lighttpd`) and `lighttpd/*.so`
  (`usr/lib/lighttpd/`) from `lighttpd_1.4.69-1_arm64.deb` (`l/lighttpd/`,
  SHA-256 `cca639162f3a9954bfcd6bec5d2e16db0a97d2ada4db803773685364ca70efc3`)
- `lib/libnettle.so.8` from `libnettle8_3.8.1-2_arm64.deb` (`n/nettle/`,
  SHA-256 `c945ff210df69cf7b95e935b8fa936e81c1c1f475355e3d5db83510b174f0cd6`),
  renamed from `libnettle.so.8.6` to its soname
- `lib/libxxhash.so.0` from `libxxhash0_0.8.1-1_arm64.deb` (`x/xxhash/`,
  SHA-256 `a3eed3901eb1804f2882dc7676f174d619745539e66ac9e92e09cd96ca0cfd73`),
  renamed from `libxxhash.so.0.8.1` to its soname

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
- SQLite: public domain — `SQLITE-COPYRIGHT`.
- GNU readline: GNU GPL v3 or later — `READLINE-COPYRIGHT` and
  `GPL-3.0.txt`.
- lighttpd: BSD 3-clause (parts under other permissive licenses, listed
  there) — `LIGHTTPD-COPYRIGHT`.
- Nettle: GNU LGPL v3 or later, or GNU GPL v2 or later (redistributed here
  under the GPL v2) — `NETTLE-COPYRIGHT` and `GPL-2.0.txt`.
- xxHash: BSD 2-clause — `XXHASH-COPYRIGHT`.

All binaries are redistributed unmodified; source is available from Debian and
each project's upstream.
