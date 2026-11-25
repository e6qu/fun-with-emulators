# Alpine Linux test fixtures

The container, debugger, Wine, JDK, display and benchmark tests, and
those of language runtimes that make code as they run, use Alpine Linux.
Its `aarch64` programs are built position-independent (GCC's own
compilers and SBCL aside), so they run in fwe's native backend; Debian's
podman, containerd and runc are not, and need the VM. Nothing is
vendored here.

## Fetched, not vendored

Each file in `fetch/` lists what one test downloads from
`https://dl-cdn.alpinelinux.org/alpine/`: a path under that URL and the
file's SHA-256. The test checks each checksum, unpacks the files in order
into its root filesystem and caches them under `target/fetched-packages`
(`FWE_FETCH_CACHE` overrides it; CI caches it). Alpine 3.20 is past its
end of life, so its files do not change; 3.24 and 3.25 are supported, and
a package rebuilt there fails its checksum.

| Manifest | Contents | Size |
| --- | --- | --- |
| `fetch/crun.txt` | The 3.20.10 minirootfs (the root filesystem of the standard `alpine` image, used both as the test's root and as the container's image), crun 1.17, libcap, libseccomp and yajl | 4 MB |
| `fetch/podman.txt` | The minirootfs (the test's root, and the one layer of the `alpine` image the test builds an OCI archive of), podman 5.2.5, conmon, crun, netavark, containers-common, catatonit and their libraries (gpgme, libassuan, libgpg-error, sqlite, glib, pcre2, libintl, libgcc, libcap, libseccomp, yajl) | 22 MB |
| `fetch/containerd.txt` | The minirootfs (the test's root, and the `alpine` image's layer), containerd 1.7.17 with its runc shim, ctr, runc 1.1.14 and libseccomp | 33 MB |
| `fetch/docker.txt` | The minirootfs (the test's root, and the `alpine` image's layer), Docker Engine 26.1.5 (`dockerd`), the docker CLI with its buildx 0.14 and Compose 2.27 plugins, containerd 1.7.17, runc 1.1.14, tini, iptables and their libraries (libmnl, libnftnl, libxtables, libseccomp) | 88 MB |
| `fetch/podman-further.txt` | What `podman.txt` lists, distribution's registry 2.8.3 (`docker-registry`), and shadow's `newuidmap`/`newgidmap` with their libraries (shadow-libs, libbsd, libmd, linux-pam, skalibs, utmps) | 31 MB |
| `fetch/wine.txt` | The 3.24.4 minirootfs (the test's root) and Wine 11.0, its Windows modules ARM64 PE (and its x86 and ARM64EC parts, unused) | 76 MB |
| `fetch/clang.txt` | The 3.24.4 minirootfs and clang 22 with LLVM's libraries, binutils 2.45, musl's headers, make 4.4 and GCC 15.2 (whose start files and libgcc clang links with; GCC's own compilers are not position-independent and are not run), and their libraries (gmp, mpfr, mpc, isl, jansson, libstdc++, libgcc, libatomic, libgomp, libffi, libxml2, xz, zlib, zstd), for the benchmarks' C build (`tools/bench/run.py`, which also fetches Lua 5.4.7's source from lua.org, MIT) | 170 MB |
| `fetch/jdk.txt` | The 3.24.4 minirootfs and OpenJDK 25.0.5: the headless runtime (HotSpot, and the module image, the compiler's module among them) and the JDK's tools (`javac`), for the JDK test and the benchmarks' JDK workload (`tools/bench/workloads/jdk`) | 88 MB |
| `fetch/workloads.txt` | The 3.24.4 minirootfs with SQLite 3.53, git 2.54, xz 5.8 and Python 3.14, and their libraries (libcurl, OpenSSL, nghttp2, c-ares, brotli, libidn2, libunistring, libpsl, pcre2, zlib, zstd, expat, bzip2, libffi, mpdecimal, readline, ncurses, libgcc, libstdc++, ca-certificates), for the benchmarks' workloads (`tools/bench/run.py`) | 25 MB |
| `fetch/postgres.txt` | The 3.24.4 minirootfs and PostgreSQL 18 (the server, and its client programs, `psql` and `pgbench` among them) with its libraries (ICU with its English data, libpq, OpenLDAP's libldap and Cyrus SASL, liburing, lz4, zstd, libxml2, OpenSSL, readline, ncurses, xz, gdbm, libstdc++, libgcc), postgresql-common and tzdata, for the benchmarks' System V user at work (`tools/bench/workloads/postgres.sh`) | 17 MB |
| `fetch/nodejs.txt` | The 3.24.4 minirootfs and Node.js 24 (V8's compilers, regular expressions and WebAssembly), ICU's full locale data, and their libraries (zstd, libstdc++, libgcc, sqlite, simdutf, simdjson, nghttp2, c-ares, brotli, ada, ca-certificates) | 40 MB |
| `fetch/luajit.txt` | The 3.24.4 minirootfs and LuaJIT 2.1 with libgcc | 5 MB |
| `fetch/sbcl.txt` | The 3.24.4 minirootfs and Steel Bank Common Lisp 2.6 (linked at `0x400000`, so run in the VM) with zstd | 18 MB |
| `fetch/racket.txt` | The 3.24.4 minirootfs and Racket 9 (Racket CS) with ncurses, lz4 and ca-certificates | 47 MB |
| `fetch/guile.txt` | The 3.24.4 minirootfs and GNU Guile 3.0 with libunistring, gmp, the Boehm GC, libstdc++, libgcc and libffi | 17 MB |
| `fetch/python.txt` | The 3.24.4 minirootfs and Python 3.14 with its libraries (sqlite, readline, ncurses, mpdecimal, libstdc++, libgcc, xz, libffi, expat, bzip2) | 15 MB |
| `fetch/ptrace.txt` | The minirootfs (the tests' root), strace 6.9 with elfutils' libdw and libelf, gdb 14.2 with the Python 3.12 it embeds, musl's debug information, and their libraries (gmp, mpfr, readline, ncurses, expat, libstdc++, libgcc, OpenSSL, libffi, gdbm, mpdecimal, sqlite, zlib, zstd, xz, bzip2, musl-fts) | 21 MB |
| `fetch/display.txt` | The 3.24.4 minirootfs, X11 clients (xeyes, xclock, xterm, xdpyinfo, xwininfo, xdotool, xwd) with fonts, Weston 14 with its X11 back end and clients, foot and Xwayland, glxgears (mesa-utils) with Mesa's drivers (mesa-dri-gallium: its software renderer, and Zink, OpenGL on fwe's Vulkan driver), Xvfb 21.1 (an X server with GLX), Vulkan's loader with vulkaninfo and vkcube (vulkan-tools), and their libraries (libX11 and the other X libraries, xcb, Wayland, pixman, cairo, pango, fontconfig, freetype, libinput and theirs). Mesa is 3.25's (26.3), with the LLVM 23 and musl it is built with | 123 MB |
| `fetch/toolkits.txt` | The 3.24.4 minirootfs, Python 3.14 with tkinter (Tcl/Tk 8.6), GTK 3's and GTK 4's demo programs with glycin's image loaders, PyQt6 with Qt 6.11's X11 and Wayland platforms, a font, xwd and xdotool, and their libraries (GLib, cairo, pango, gdk-pixbuf, GStreamer, Mesa, LLVM, ICU and theirs) | 242 MB |
| `fetch/wine-x11.txt` | The 3.24.4 minirootfs, Wine 11.0, and the X libraries, fontconfig and font its X11 driver loads | 85 MB |

## License

What the tests fetch keeps the licenses Alpine ships it under, recorded in
each package's metadata: crun GPL-2.0-or-later and LGPL-2.1-or-later;
libcap BSD-3-Clause or GPL-2.0-only; libseccomp LGPL-2.1-or-later; yajl MIT;
podman, conmon, netavark, containers-common, containerd, ctr, runc,
dockerd, the docker CLI, buildx, Compose and the registry Apache-2.0;
shadow, libbsd and linux-pam BSD-3-Clause; libmd BSD-3-Clause,
BSD-2-Clause, ISC, Beerware and public domain; skalibs and utmps ISC;
tini MIT; Wine LGPL-2.1-or-later; OpenJDK GPL-2.0 with the Classpath
exception; GCC, libgcc, libstdc++, libatomic and libgomp GPL-3.0-or-later
with the GCC Runtime Library Exception; binutils and make
GPL-3.0-or-later; mpc LGPL-3.0-or-later; isl and jansson MIT; clang and
LLVM Apache-2.0 with LLVM exceptions; libffi and libxml2 MIT; xz public
domain and BSD-0-Clause; fortify-headers 0BSD; iptables, libnftnl and
libxtables GPL-2.0-or-later; libmnl LGPL-2.1-or-later; Node.js and LuaJIT
MIT; simdutf and simdjson Apache-2.0 or MIT; ada (Apache-2.0 or MIT) and
MPL-2.0; ICU ICU; SBCL its own (public domain and BSD-style); Racket
Apache-2.0 or MIT; Guile LGPL-3.0-or-later and GPL-3.0-or-later; the
Boehm GC its own (Boehm-GC); lz4 BSD-2-Clause and GPL-2.0-or-later;
catatonit
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
LGPL-2.1-or-later; bzip2 bzip2-1.0.6; git GPL-2.0-only; libcurl curl;
nghttp2, c-ares, brotli and libpsl MIT; libidn2 and libunistring
GPL-2.0-or-later or LGPL-3.0-or-later; ca-certificates MPL-2.0 and MIT;
PostgreSQL and libpq the PostgreSQL License; postgresql-common MIT; tzdata
public domain; libldap OLDAP-2.8; Cyrus SASL BSD-3-Clause-Attribution and
BSD-4-Clause; liburing LGPL-2.1-or-later or MIT;
the display and toolkit packages (X11's and Wayland's, Weston, foot, Mesa,
Vulkan's loader and tools, Tcl/Tk, GTK, Qt, PyQt6 and their libraries) and
the minirootfs's (BusyBox GPL-2.0-only, musl MIT, and others) their own,
as each package's metadata records them.
