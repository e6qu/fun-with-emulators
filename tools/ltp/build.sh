#!/bin/sh
# Build the Linux Test Project's system-call tests for Linux arm64.
#
# Usage: tools/ltp/build.sh OUT
#
# Fetches the pinned LTP release (checked against its SHA-256), configures it
# for aarch64 musl with `zig cc`, and builds testcases/kernel/syscalls as
# stripped static PIE executables (PIE so they load above the 4 GiB macOS
# reserves, on the in-process backend). Installs them as a root filesystem's
# /opt/ltp, in OUT/root (testcases/bin and runtest/syscalls, as LTP lays
# them out), for tools/ltp/run.py. Needs zig and xz on the PATH.
set -eu

VERSION=20260930
SHA256=b9837481134fa6eabce91c2fba57d96695f81360468f83e11e6982584ad4d29d
URL="https://github.com/linux-test-project/ltp/releases/download/$VERSION/ltp-full-$VERSION.tar.xz"
# The compiler the build is pinned to (CI fetches it; see ci.yml).
ZIG_VERSION=0.17.0
# Not built: musl lacks fmtmsg's addseverity and the sigevent member
# timer_create's tests name.
SKIP_DIRS="fmtmsg timer_create"

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

if [ ! -f "$tarball" ] || ! echo "$SHA256  $tarball" | shasum -a 256 -c - >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$tarball.part" "$URL"
    echo "$SHA256  $tarball.part" | shasum -a 256 -c -
    mv "$tarball.part" "$tarball"
fi

rm -rf "${src:?}" "${out:?}/root" "${tools:?}"
mkdir -p "$src" "$tools"
tar -xJf "$tarball" -C "$src" --strip-components=1

# The cross toolchain: zig's clang with its bundled musl and Linux headers.
cat > "$tools/cc" <<'EOF'
#!/bin/sh
exec zig cc -target aarch64-linux-musl -fPIE "$@"
EOF
printf '#!/bin/sh\nexec zig ar "$@"\n' > "$tools/ar"
printf '#!/bin/sh\nexec zig ranlib "$@"\n' > "$tools/ranlib"
chmod +x "$tools/cc" "$tools/ar" "$tools/ranlib"

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
    make -C runtest install DESTDIR="$out/root"
} >"$out/build.log" 2>&1 || { grep -E "error|\*\*\*" "$out/build.log" | head -40; exit 1; }
rm -rf "${src:?}"
echo "LTP $VERSION: $(ls "$out/root/opt/ltp/testcases/bin" | wc -l | tr -d ' ') files in $out/root/opt/ltp"
