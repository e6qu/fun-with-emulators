#!/bin/sh
# fwe beside a Linux VM and native macOS, on this Mac: the benchmarks of
# run.py (`linux`) in a Linux VM (Lima, on Apple's Virtualization
# framework), then under fwe and natively (`macos`), in one table with
# fwe's ratio to each and fwe's share of the programs that compute.
#
# Needs Lima, Homebrew's builds the native side runs, the Mac's Vulkan
# driver and a password for sudo (DTrace, for fwe's share):
#     brew install lima llvm@22 python@3.14 sqlite git xz openjdk@25 node@24 \
#         luajit postgresql@18 xorg-server molten-vk vulkan-tools vulkan-headers
# Run from the repository: sh tools/bench/vm.sh. The VM (fwe-bench) is
# kept, stopped, for the next run; `limactl delete fwe-bench` removes it.
# A Linux VM is a hypervisor client: not while fwe's VM tests run.
#
# `--fwe-vm` adds a column of the same benchmarks under fwe's own VM
# backend (`fwe --vm`), signed with the hypervisor entitlement for it, run
# after the Linux VM has stopped. Misusing the hypervisor can bring a Mac
# down (docs/hypervisor.md): run it only on a Mac whose crash costs
# nothing, with no other hypervisor client (Lima, Podman's krunkit, UTM,
# Docker Desktop) running.
set -eu
fwe_vm=false
for arg in "$@"; do
    case "$arg" in
        --fwe-vm) fwe_vm=true ;;
        *) echo "vm.sh: unknown argument $arg" >&2; exit 2 ;;
    esac
done
repo=$(cd "$(dirname "$0")/../.." && pwd)
out=/tmp/lima/fwe-bench
vm=fwe-bench
cd "$repo"
command -v limactl >/dev/null || { echo "vm.sh: needs Lima (brew install lima)" >&2; exit 1; }
sudo -v
# sudo's ticket kept fresh through the run, which outlasts it.
(while sudo -n -v; do sleep 60; done) &
keep=$!
trap 'kill "$keep"' EXIT
mkdir -p "$out"

# The VM: Ubuntu, all of the Mac's cores, 8 GiB. Lima shares the home
# directory read-only (the repository) and /tmp/lima writable (the results).
if ! limactl list -q | grep -qx "$vm"; then
    limactl create --name="$vm" --cpus="$(sysctl -n hw.ncpu)" --memory=8 --tty=false template://default
fi
limactl start "$vm"
limactl shell --workdir "$repo" "$vm" sh -euc "
    command -v docker >/dev/null && command -v gcc >/dev/null && command -v Xvfb >/dev/null ||
        { sudo apt-get update -q && sudo apt-get install -qy docker.io gcc xvfb; }
    gcc -O2 -static-pie -o $out/bench guests/c/bench.c
    sudo docker run --rm -v $repo:/w:ro -v $out:/out -w /w alpine:3.24 sh -c \
        'apk add -q gcc musl-dev vulkan-headers && gcc -O2 -o /out/vkbench tools/bench/vkbench.c'
    sudo python3 tools/bench/run.py linux --bench $out/bench --cache $out/cache --xvfb /usr/bin/Xvfb --out $out/linux-vm.json
"
limactl stop "$vm"

# The same Linux build under fwe, its source natively.
cargo build --release -p fwe
clang -O2 -Wno-deprecated-declarations -o "$out/bench-mac" guests/c/bench.c
clang -O2 -I"$(brew --prefix)/include" -o "$out/vkbench-mac" tools/bench/vkbench.c
with_vm=""
if $fwe_vm; then
    # Every program in fwe's VM: fwe signed for the hypervisor, called
    # with `--vm` (its budgets against macOS are not this run's to keep).
    codesign --sign - --entitlements hypervisor.entitlements --force target/release/fwe
    printf '#!/bin/sh\nexec "%s" --vm "$@"\n' "$repo/target/release/fwe" > "$out/fwe-vm"
    chmod +x "$out/fwe-vm"
    python3 tools/bench/run.py macos --fwe "$out/fwe-vm" --bench "$out/bench" \
        --native "$out/bench-mac" --brew "$(brew --prefix)" --cache target/bench-cache \
        --xvfb "$(brew --prefix)/bin/Xvfb" --vkbench "$out/vkbench" \
        --vkbench-native "$out/vkbench-mac" --no-gpu --out "$out/macos-vm.json" || true
    with_vm="--fwe-vm $out/macos-vm.json"
fi
# shellcheck disable=SC2086 # `with_vm` is two words or none
python3 tools/bench/run.py macos --fwe target/release/fwe --bench "$out/bench" \
    --native "$out/bench-mac" --brew "$(brew --prefix)" --cache target/bench-cache \
    --xvfb "$(brew --prefix)/bin/Xvfb" --vkbench "$out/vkbench" --vkbench-native "$out/vkbench-mac" \
    --linux-vm "$out/linux-vm.json" $with_vm --out "$out/macos.json"
