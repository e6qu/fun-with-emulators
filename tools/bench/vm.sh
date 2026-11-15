#!/bin/sh
# fwe beside a Linux VM and native macOS, on this Mac: the benchmarks of
# run.py (`linux`) in a Linux VM (Lima, on Apple's Virtualization
# framework), then under fwe and natively (`macos`), in one table with
# fwe's ratio to each and fwe's share of the programs that compute.
#
# Needs Lima, Homebrew's builds the native side runs and a password for
# sudo (DTrace, for fwe's share):
#     brew install lima llvm@22 python@3.14 sqlite git xz
# Run from the repository: sh tools/bench/vm.sh. The VM (fwe-bench) is
# kept, stopped, for the next run; `limactl delete fwe-bench` removes it.
# A Linux VM is a hypervisor client: not while fwe's VM tests run.
set -eu
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
    command -v docker >/dev/null && command -v gcc >/dev/null ||
        { sudo apt-get update -q && sudo apt-get install -qy docker.io gcc; }
    gcc -O2 -static-pie -o $out/bench guests/c/bench.c
    sudo python3 tools/bench/run.py linux --bench $out/bench --cache $out/cache --out $out/linux-vm.json
"
limactl stop "$vm"

# The same Linux build under fwe, its source natively.
cargo build --release -p fwe
clang -O2 -Wno-deprecated-declarations -o "$out/bench-mac" guests/c/bench.c
python3 tools/bench/run.py macos --fwe target/release/fwe --bench "$out/bench" \
    --native "$out/bench-mac" --brew "$(brew --prefix)" --cache target/bench-cache \
    --linux-vm "$out/linux-vm.json" --out "$out/macos.json"
