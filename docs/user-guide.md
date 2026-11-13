# Using fwe

`fwe` runs Linux programs built for arm64 on a Mac with Apple Silicon,
without a Linux VM: the program's own code runs on the Mac's processor,
and `fwe` plays the Linux kernel for it. This guide covers installing
`fwe`, getting a Linux userland to run programs in, running containers
with podman, and what does not work.

The blocks marked as tested below are run by CI as they are written
(`user_guide_recipes` in `crates/fwe/tests/guests.rs`), each followed by
the output it gives.

## Installing

With Homebrew, from the project's repository as a tap:

```sh
brew tap e6qu/fwe https://github.com/e6qu/fun-with-emulators
brew install fwe          # the latest release
brew install --HEAD fwe   # or the main branch
```

Homebrew builds `fwe` from source and signs it for this Mac with the
entitlements it needs (the hypervisor, for programs that run in a VM; see
[Programs linked below 4 GiB](#programs-linked-below-4-gib)).

A release's archive on GitHub holds a signed `fwe`: unpack it and put
`fwe` on your `PATH`. A release signed without a Developer ID is not
notarized, and macOS refuses to run it until its quarantine mark is gone:

```sh
xattr -d com.apple.quarantine fwe
```

From source, with Rust installed:

```sh
cargo build --release -p fwe
codesign --sign - --force --options runtime \
  --entitlements hypervisor.entitlements target/release/fwe
```

## A Linux userland

Linux programs expect a Linux filesystem around them: their libraries,
`/etc`, `/usr/bin`. `fwe --pull` makes one from a container image,
fetching its linux/arm64 variant from the image's registry (Docker Hub
unless named otherwise) and unpacking it into a new directory; `--root`
then makes that directory the program's `/`.

A program inside the root is named by its path on the Mac. The
environment is passed on as it is, so give the program a Linux one with
`env -i`, as a login would (`fwe` found first, on your `PATH`). This
guide uses a shell function for it:

```sh
# linux ROOT PROGRAM [ARGS...]: run PROGRAM (a path in ROOT) with ROOT as /.
linux() {
  root=$1 prog=$2 fwe=$(command -v fwe); shift 2
  env -i HOME=/root TERM="${TERM:-dumb}" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$fwe" --root "$root" "$root$prog" "$@"
}
```

<!-- tested: debian -->
```sh
fwe --pull debian:trixie ~/debian 2>/dev/null
linux ~/debian /bin/bash -c 'apt-get update -qq && apt-get install -qq -y cowsay >/dev/null && /usr/games/cowsay -f tux hi | head -2'
```

```text
 ____
< hi >
```

<!-- tested: alpine -->
```sh
fwe --pull alpine:3.24 ~/alpine 2>/dev/null
linux ~/alpine /bin/sh -c 'apk add -q --no-progress git && git --version | cut -d" " -f1-2'
```

```text
git version
```

For an interactive shell: `linux ~/debian /bin/bash -l`.

What `--pull` does beyond unpacking:

- Files owned by users other than root, and set-ID programs (`su`,
  `passwd`), keep their owners and modes as Linux programs see them, in
  extended attributes `fwe` reads. The guest sees your own files as
  root's, and runs as root unless it changes user.
- `/etc/resolv.conf` is written with your Mac's name servers at the
  time, in place of the image's, and `/etc/hosts` where the image has
  none, as a container runtime does at a container's start.
- On a case-insensitive volume (macOS's default), a file whose name
  differs from another's only in case cannot be kept: `--pull` leaves the
  later one out and lists it. Debian's image has one such file, a manual
  page. On a case-sensitive APFS volume nothing is left out:

  ```sh
  hdiutil create -size 20g -fs 'Case-sensitive APFS' -volname linux -type SPARSE linux.sparseimage
  hdiutil attach linux.sparseimage    # then pull into /Volumes/linux/...
  ```

Any image with a linux/arm64 variant can be pulled the same way
(`ubuntu:24.04`, `ghcr.io/owner/name:tag`), and any root filesystem
unpacked into a directory serves.

## Running programs

- **A program built for Linux on arm64** (an ELF file) runs directly:
  `fwe ./program`. A statically linked one needs nothing more; a
  dynamically linked one needs its dynamic linker and libraries, so run it
  in a root of the distribution it was built for, copied into the root.
- **Threads, processes, signals, pipes, sockets, terminals and job
  control** behave as on Linux; `fork`, `exec` and `wait` make real Mac
  processes, one `fwe` for each Linux process.
- **Networking** uses the Mac's: a server listening on a port is
  reachable from the Mac on that port, and outgoing connections go out as
  the Mac's do.
- **Files** outside the root are out of the program's reach; without
  `--root`, the program sees the Mac's filesystem as its own.

### Programs linked below 4 GiB

macOS keeps the lowest 4 GiB of a process's address space for itself, so
a program linked to load there (a non-PIE executable: Debian's Python,
GCC, clang and Go are) runs in a small VM instead, through
Hypervisor.framework. `fwe` picks the VM for it by itself. This needs
`fwe` signed with the hypervisor entitlement (Homebrew's and the
releases' are) on a Mac that offers the hypervisor
(`sysctl kern.hv_support` prints `1`); otherwise `fwe` says the program
needs the VM and exits with status 126. `fwe --vm` runs every program in
the VM, for programs that need 4 KiB pages, such as Wine.

The VM backend is tested on a software stand-in for Hypervisor.framework
(CI's machines offer no hypervisor); its run on real hardware is still
to come ([roadmap](../ROADMAP.md)).

### Windows programs

Windows programs built for ARM64 run through Alpine's Wine, in the VM:

```sh
linux ~/alpine /bin/sh -c 'apk add -q wine'
cp winprog.exe ~/alpine/tmp/
env -i HOME=/root PATH=/usr/bin:/bin "$(command -v fwe)" --vm --root ~/alpine ~/alpine/bin/sh \
  -c 'wine wineboot --init && wine /tmp/winprog.exe'
```

CI's `wine` job runs `guests/windows/winprog.c` (built with
`zig cc -target aarch64-windows-gnu`) this way: files, threads,
exceptions and a child process.

## Containers

podman runs in a userland that has it, as root, with containers made by
crun and `overlay` storage. In an Alpine root:

<!-- tested: podman -->
```sh
linux ~/alpine /bin/sh -c 'apk add -q --no-progress podman'
cat > ~/alpine/etc/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
EOF
cat > ~/alpine/etc/containers/containers.conf <<'EOF'
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
EOF
linux ~/alpine /usr/bin/podman run --rm --network=none docker.io/library/alpine:3.24 \
  sh -c 'echo hello from a container; cat /etc/alpine-release | cut -d. -f1-2'
```

```text
hello from a container
3.24
```

- `cgroup_manager = "cgroupfs"`: there is no systemd to ask.
- `--network=none`: a container gets loopback only; a new network
  namespace has nothing else (see below).
- podman also builds images, pushes and pulls them, and runs rootless as
  another user, and Docker Engine (`dockerd` with `--bridge=none
  --iptables=false --storage-driver=overlay2`) runs, builds and composes
  containers; CI's `podman` and `docker` jobs run them.

## Seeing what a program does

```sh
fwe --strace ./program                         # each system call, to standard error
fwe --strace=failures ./program                # only the calls that fail
fwe --strace --strace-file=trace.log ./program # every process of the run, to a file
```

A call `fwe` does not implement fails with `ENOSYS`, as on a Linux kernel
that lacks it, and `--strace` names it.

## What does not work

- **Network namespaces beyond loopback**: a new one has loopback only;
  virtual Ethernet pairs, bridges and firewall rules (`iptables`,
  `nftables`) are refused, so a container on a bridged network does not
  start (`--network=none` or the host's network does).
- **io_uring** and **fanotify**: refused, and programs fall back to
  ordinary calls and inotify.
- **Linux's devices and drivers**: no `/dev/kvm`, GPU, FUSE or kernel
  modules; files live on the Mac's filesystem, so disk filesystems
  (ext4, btrfs) and block devices are not there.
- **Resource limits of cgroups** but the process count: accepted, not
  enforced.
- **A sandbox**: namespaces, seccomp and the rest keep well-behaved
  programs apart, as containers expect, but a program run natively
  shares the `fwe` process and acts as your user; run untrusted code in a
  Linux VM ([isolation and security](linux-on-macos.md#isolation-and-security),
  [comparisons](comparisons.md)).
- **Programs for other processors** (x86-64): `fwe` runs arm64 code only.
- **Chosen process ids**: pids are the Mac's.
- The full list is in the [roadmap](../ROADMAP.md#not-planned-for-10),
  and where `fwe` differs from Linux in detail in the
  [architecture's known limitations](architecture.md#known-limitations).

## Troubleshooting

- **`fwe: ...: No such file or directory` for a program in a root**: name
  it by its path on the Mac (`~/debian/bin/bash`), with `--root`.
- **"needs the hypervisor backend"**: the program is linked below 4 GiB;
  see [Programs linked below 4 GiB](#programs-linked-below-4-gib).
- **A program says a call is not implemented**: run it with
  `--strace=failures` and look for `ENOSYS`; please report it with the
  trace.
- **Name lookups fail in a root**: check its `/etc/resolv.conf`; `--pull`
  writes the name servers your Mac had at the time.
