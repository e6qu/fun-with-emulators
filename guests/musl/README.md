# Vendored musl runtime (test fixture)

These files are an unmodified prebuilt [musl libc](https://musl.libc.org/)
for `aarch64`, vendored so the end-to-end tests can exercise **real** dynamic
linking — loading a genuine dynamic linker, resolving symbols against a shared
libc, and applying relocations — rather than a hand-written stand-in. macOS has
no musl, so the runtime is checked in rather than built from source here.

| File | Purpose |
| --- | --- |
| `lib/ld-musl-aarch64.so.1` | The musl dynamic linker, which is also the shared libc (soname `libc.musl-aarch64.so.1`). Used both as the interpreter at run time and as the link target when building the dynamic guests. |
| `lib/Scrt1.o`, `lib/crti.o`, `lib/crtn.o` | musl C runtime startup objects for a PIE, used to link `guests/c/dynhello.c`. |
| `COPYRIGHT` | musl's license (MIT). |

## Provenance

Extracted from Alpine Linux 3.21 `aarch64` packages, musl `1.2.5-r12`:

- `ld-musl-aarch64.so.1` from `musl-1.2.5-r12.apk`
- `Scrt1.o`, `crti.o`, `crtn.o` from `musl-dev-1.2.5-r12.apk`

from `https://dl-cdn.alpinelinux.org/alpine/v3.21/main/aarch64/`. The linker and
the crt objects come from the same package version so their ABI matches.

To refresh, download those two `.apk` files (they are `.tar.gz`), extract
`lib/ld-musl-aarch64.so.1` and `usr/lib/{Scrt1,crti,crtn}.o`, and replace the
files here.

## License

musl is MIT licensed; see `COPYRIGHT`. These are redistributed unmodified.
