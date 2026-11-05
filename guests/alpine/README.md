# Alpine Linux test fixtures

The container tests use Alpine Linux, whose `aarch64` builds of the
container tools are position-independent, so they run in fwe's native
backend (Debian's podman, containerd and runc are not, and would need the
VM). Nothing is vendored here.

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

## License

What the tests fetch keeps the licenses Alpine ships it under, recorded in
each package's metadata: crun GPL-2.0-or-later and LGPL-2.1-or-later;
libcap BSD-3-Clause or GPL-2.0-only; libseccomp LGPL-2.1-or-later; yajl MIT;
the minirootfs's packages (BusyBox GPL-2.0-only, musl MIT, and others) their
own.
