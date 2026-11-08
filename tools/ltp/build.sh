#!/bin/sh
# Build the Linux Test Project's system-call tests for Linux arm64.
#
# Usage: tools/ltp/build.sh OUT
#
# Fetches the pinned LTP release (checked against its SHA-256), configures it
# for aarch64 musl with `zig cc`, and builds testcases/kernel/syscalls (and
# the tests elsewhere that runtest/syscalls runs) as
# stripped static PIE executables (PIE so they load above the 4 GiB macOS
# reserves, on the in-process backend). Installs them in /opt/ltp of a root
# filesystem in OUT/root (testcases/bin and runtest/syscalls, as LTP lays
# them out): the Alpine minirootfs, the root of the standard `alpine`
# image, which gives the tests a shell, the usual utilities and users.
# For tools/ltp/run.py. Needs zig and xz on the PATH.
set -eu

VERSION=20260930
SHA256=b9837481134fa6eabce91c2fba57d96695f81360468f83e11e6982584ad4d29d
URL="https://github.com/linux-test-project/ltp/releases/download/$VERSION/ltp-full-$VERSION.tar.xz"
# The root filesystem (as guests/alpine/fetch pins it).
ROOTFS=alpine-minirootfs-3.20.10-aarch64.tar.gz
ROOTFS_SHA256=61ac877fdbcee6914731bc22a4ed5668ea3470f201f97a7078931c48b71bbeec
ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/$ROOTFS"
# The compiler the build is pinned to (CI fetches it; see ci.yml).
ZIG_VERSION=0.17.0
# Not built: musl lacks fmtmsg's addseverity. timer_create's tests name
# glibc's sigevent member, built with musl's in its place (sigev.h below).
SKIP_DIRS="fmtmsg timer_create"
# The tests runtest/syscalls runs from outside testcases/kernel/syscalls.
OTHER_DIRS="testcases/kernel/ipc/pipeio testcases/kernel/ipc/msgstress \
    testcases/kernel/security/dirtyc0w testcases/kernel/security/dirtyc0w_shmem \
    testcases/kernel/security/dirtypipe testcases/kernel/security/prot_hsymlinks"

out=${1:?usage: build.sh OUT}
if [ "$(zig version 2>/dev/null)" != "$ZIG_VERSION" ]; then
    echo "build.sh: needs zig $ZIG_VERSION on the PATH" >&2
    exit 1
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
tarball="$out/ltp-full-$VERSION.tar.xz"
src="$out/src"
tools="$out/tools"

# fetch URL SHA256 FILE: FILE, downloaded once and checked.
fetch() {
    if [ ! -f "$3" ] || ! echo "$2  $3" | shasum -a 256 -c - >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$3.part" "$1"
        echo "$2  $3.part" | shasum -a 256 -c -
        mv "$3.part" "$3"
    fi
}
fetch "$URL" "$SHA256" "$tarball"
fetch "$ROOTFS_URL" "$ROOTFS_SHA256" "$out/$ROOTFS"

rm -rf "${src:?}" "${out:?}/root" "${tools:?}"
mkdir -p "$src" "$tools" "$out/root"
tar -xJf "$tarball" -C "$src" --strip-components=1
tar -xzf "$out/$ROOTFS" -C "$out/root"

# The cross toolchain: zig's clang with its bundled musl and Linux headers.
cat > "$tools/cc" <<'EOF'
#!/bin/sh
exec zig cc -target aarch64-linux-musl -fPIE "$@"
EOF
printf '#!/bin/sh\nexec zig ar "$@"\n' > "$tools/ar"
printf '#!/bin/sh\nexec zig ranlib "$@"\n' > "$tools/ranlib"
chmod +x "$tools/cc" "$tools/ar" "$tools/ranlib"
# glibc's name for the thread a SIGEV_THREAD_ID timer signals, as musl has
# it.
cat > "$tools/sigev.h" <<'EOF'
#include <signal.h>
#undef sigev_notify_thread_id
#define _sigev_un __sev_fields
#define _tid sigev_notify_thread_id
EOF

jobs=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
cd "$src"
./configure --host=aarch64-linux-musl --build="$(./config.guess)" \
    CC="$tools/cc" AR="$tools/ar" RANLIB="$tools/ranlib" \
    CFLAGS="-O2 -g0" LDFLAGS="-s" --prefix=/opt/ltp >"$out/configure.log" 2>&1 \
    || { tail -40 "$out/configure.log"; exit 1; }
{
    make -C lib -j"$jobs"
    make -C testcases/kernel/syscalls -j"$jobs" FILTER_OUT_DIRS="$SKIP_DIRS"
    make -C testcases/kernel/syscalls install FILTER_OUT_DIRS="$SKIP_DIRS" DESTDIR="$out/root"
    make -C testcases/kernel/syscalls/timer_create CFLAGS="-O2 -g0 -include $tools/sigev.h"
    make -C testcases/kernel/syscalls/timer_create install DESTDIR="$out/root"
    for d in $OTHER_DIRS; do
        make -C "$d" -j"$jobs"
        make -C "$d" install DESTDIR="$out/root"
    done
    make -C runtest install DESTDIR="$out/root"
} >"$out/build.log" 2>&1 || { grep -E "error|\*\*\*" "$out/build.log" | head -40; exit 1; }
rm -rf "${src:?}"
echo "LTP $VERSION: $(ls "$out/root/opt/ltp/testcases/bin" | wc -l | tr -d ' ') files in $out/root/opt/ltp"
