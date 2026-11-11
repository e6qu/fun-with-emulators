# Alpine Linux test fixtures

The container and debugger tests use Alpine Linux, whose `aarch64` builds
of the container tools and debuggers are position-independent, so they
run in fwe's native backend (Debian's podman, containerd and runc are
not, and would need the VM). Nothing is vendored here.

## Fetched, not vendored

Each file in `fetch/` lists what one test downloads from
`https://dl-cdn.alpinelinux.org/alpine/`: a path under that URL and the
file's SHA-256. The test checks each checksum, unpacks the files in order
into its root filesystem and caches them under `target/fetched-packages`
(`FWE_FETCH_CACHE` overrides it; CI caches it). Alpine 3.20 is past its end
of life, so the files no longer change.

| Manifest | Contents | Size |
| --- | --- | --- |
| `fetch/crun.txt` | The 3.20.10 minirootfs (the root filesystem of the standard `alpine` image, used both as the test's root and as the container's image), crun 1.17, libcap, libseccomp and yajl | 4 MB |
| `fetch/podman.txt` | The minirootfs (the test's root, and the one layer of the `alpine` image the test builds an OCI archive of), podman 5.2.5, conmon, crun, netavark, containers-common, catatonit and their libraries (gpgme, libassuan, libgpg-error, sqlite, glib, pcre2, libintl, libgcc, libcap, libseccomp, yajl) | 22 MB |
| `fetch/containerd.txt` | The minirootfs (the test's root, and the `alpine` image's layer), containerd 1.7.17 with its runc shim, ctr, runc 1.1.14 and libseccomp | 33 MB |
| `fetch/docker.txt` | The minirootfs (the test's root, and the `alpine` image's layer), Docker Engine 26.1.5 (`dockerd`), the docker CLI with its buildx 0.14 and Compose 2.27 plugins, containerd 1.7.17, runc 1.1.14, tini, iptables and their libraries (libmnl, libnftnl, libxtables, libseccomp) | 88 MB |
| `fetch/podman-further.txt` | What `podman.txt` lists, distribution's registry 2.8.3 (`docker-registry`), and shadow's `newuidmap`/`newgidmap` with their libraries (shadow-libs, libbsd, libmd, linux-pam, skalibs, utmps) | 31 MB |
| `fetch/ptrace.txt` | The minirootfs (the tests' root), strace 6.9 with elfutils' libdw and libelf, gdb 14.2 with the Python 3.12 it embeds, musl's debug information, and their libraries (gmp, mpfr, readline, ncurses, expat, libstdc++, libgcc, OpenSSL, libffi, gdbm, mpdecimal, sqlite, zlib, zstd, xz, bzip2, musl-fts) | 21 MB |

## License

What the tests fetch keeps the licenses Alpine ships it under, recorded in
each package's metadata: crun GPL-2.0-or-later and LGPL-2.1-or-later;
libcap BSD-3-Clause or GPL-2.0-only; libseccomp LGPL-2.1-or-later; yajl MIT;
podman, conmon, netavark, containers-common, containerd, ctr, runc,
dockerd, the docker CLI, buildx, Compose and the registry Apache-2.0;
shadow, libbsd and linux-pam BSD-3-Clause; libmd BSD-3-Clause,
BSD-2-Clause, ISC, Beerware and public domain; skalibs and utmps ISC; tini MIT; iptables,
libnftnl and libxtables GPL-2.0-or-later; libmnl LGPL-2.1-or-later; catatonit
GPL-2.0-or-later; gpgme LGPL-2.1-or-later and GPL-3.0-or-later; libassuan,
glib and libintl LGPL-2.1-or-later; libgpg-error and libgcc
GPL-2.0-or-later and LGPL-2.1-or-later; sqlite the SQLite blessing; pcre2
BSD-3-Clause;
strace BSD-3-Clause; gdb GPL-3.0-or-later and LGPL-3.0-or-later; libdw and
libelf GPL-3.0-or-later and (GPL-2.0-or-later or LGPL-3.0-or-later); Python
PSF-2.0; gmp LGPL-3.0-or-later or GPL-2.0-or-later; mpfr LGPL-3.0-or-later;
readline and gdbm GPL-3.0-or-later; ncurses X11; expat, libffi and musl MIT;
libstdc++ GPL-2.0-or-later and LGPL-2.1-or-later; OpenSSL Apache-2.0;
mpdecimal BSD-2-Clause; musl-fts BSD-3-Clause; zlib Zlib; zstd BSD-3-Clause
or GPL-2.0-or-later; xz-libs GPL-2.0-or-later, 0BSD, public domain and
LGPL-2.1-or-later; bzip2 bzip2-1.0.6;
the minirootfs's packages (BusyBox GPL-2.0-only, musl MIT, and others) their
own.
