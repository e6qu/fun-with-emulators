# Vendored Debian coreutils (test fixture)

Unmodified GNU coreutils programs from Debian 12 (bookworm) for `aarch64`,
vendored so the end-to-end tests can run **real distribution binaries** — the
M1 goal of running programs from a Debian rootfs. They are dynamically linked
against glibc and run against the glibc runtime vendored under `guests/glibc`
(`/lib/ld-linux-aarch64.so.1` and `/lib/libc.so.6`).

Only programs whose sole shared dependency is `libc.so.6` are vendored here;
programs that pull in further libraries (`ls` needs `libselinux`, `libcap`)
come later with those libraries.

| File | |
| --- | --- |
| `bin/true`, `bin/false` | Exit status 0 / 1. |
| `bin/echo` | Print arguments. |
| `bin/seq` | Generate a sequence. |
| `bin/env` | Print the environment. |
| `bin/cat` | Copy stdin to stdout. |
| `bin/sort` | Sort lines. |

## Provenance

Extracted from `coreutils_9.1-1_arm64.deb` (Debian 12, coreutils `9.1`), built
against glibc 2.36, from
`https://deb.debian.org/debian/pool/main/c/coreutils/`. The version is matched
to the vendored glibc 2.36 so the programs reference no newer symbol version
(they need at most `GLIBC_2.34`). The `.deb` is an `ar` archive whose
`data.tar.xz` holds the binaries under `bin/`.

## License

GNU coreutils is distributed under the GNU GPL v3 or later; see
`COREUTILS-COPYRIGHT` (Debian's copyright file) and `GPL-3.0.txt`. These
binaries are redistributed unmodified. Source is available from Debian and
from <https://ftp.gnu.org/gnu/coreutils/>.
