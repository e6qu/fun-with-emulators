# Vendored glibc runtime (test fixture)

An unmodified prebuilt [GNU C Library](https://www.gnu.org/software/libc/) for
`aarch64`, vendored so the end-to-end tests can exercise **real glibc dynamic
linking** — the case a Debian rootfs needs. macOS has no glibc, so the runtime
is checked in rather than built from source here.

Unlike musl, glibc's dynamic linker and shared libc are separate files, so the
linker maps `libc.so.6` itself at run time through our `mmap`; that library's
code segment also holds its symbol, string and hash tables, which the rewrite
must leave alone (`Elf::exec_file_ranges`).

| File | Purpose |
| --- | --- |
| `lib/ld-linux-aarch64.so.1` | The glibc dynamic linker (soname `ld-linux-aarch64.so.1`). The interpreter at run time. |
| `lib/libc.so.6` | The shared libc (soname `libc.so.6`), mapped by the dynamic linker; also the link target for the guests. |
| `lib/libm.so.6` | glibc's maths library, needed by the vendored Debian SQLite. |
| `lib/Scrt1.o`, `lib/crti.o`, `lib/crtn.o` | glibc C runtime startup objects for a PIE, used to link `guests/c/dynhello.c`. |
| `lib/libc_nonshared.a` | The small static companion glibc links beside `libc.so.6`. |
| `COPYRIGHT` | Debian's glibc copyright and license summary. |
| `LGPL-2.1.txt` | The GNU LGPL v2.1, glibc's primary license. |

## Provenance

Extracted from Debian 12 (bookworm) `aarch64` packages, glibc `2.36-9+deb12u14`:

- `ld-linux-aarch64.so.1`, `libc.so.6`, `libm.so.6` from
  `libc6_2.36-9+deb12u14_arm64.deb` (SHA-256
  `01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4`)
- `Scrt1.o`, `crti.o`, `crtn.o`, `libc_nonshared.a` from
  `libc6-dev_2.36-9+deb12u14_arm64.deb`

from `https://deb.debian.org/debian/pool/main/g/glibc/`. The `.deb` files are
`ar` archives whose `data.tar.xz` holds the files above.

## License

glibc is distributed under the GNU LGPL v2.1 or later (with some components
under other free licenses); see `COPYRIGHT` and `LGPL-2.1.txt`. These files are
redistributed unmodified, and the library is used only through its normal
dynamic-linking interface. Source is available from Debian and from
<https://sourceware.org/git/glibc.git>.
