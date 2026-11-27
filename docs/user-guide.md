# Using fwe

`fwe` runs Linux programs built for arm64 on a Mac with Apple Silicon,
without a Linux VM: the program's own code runs on the Mac's processor,
and `fwe` plays the Linux kernel for it. This guide covers installing
`fwe`, a Linux userland, running programs (Windows programs and programs
with windows among them) and containers, and what does not work. How
`fwe` maps each Linux feature onto macOS is in
[linux-on-macos.md](linux-on-macos.md). CI runs the recipes marked as
tested exactly as written and checks the output shown after each
(`user_guide_recipes` in `crates/fwe/tests/guests.rs`).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
when, and only when, they appear in all capitals, as shown here.

## Installing

### With Homebrew

From the project's repository as a tap:

```sh
brew tap e6qu/fwe https://github.com/e6qu/fun-with-emulators
brew install --HEAD fwe   # the main branch
```

Homebrew builds `fwe` from source and signs it for this Mac with the
entitlements it needs (the hypervisor's, for programs that run in a VM;
see [Programs linked below 4 GiB](#programs-linked-below-4-gib)). Once a
release is published, `brew install fwe` installs that instead.

### From a release

A release's archive on GitHub holds a signed `fwe`: unpack it and put
`fwe` on your `PATH`. A release signed without a Developer ID is not
notarized, and macOS refuses to run it while it carries its quarantine
mark, so the mark MUST be removed first:

```sh
xattr -d com.apple.quarantine fwe
```

### From source

Building REQUIRES Rust 1.95 or later and the Xcode command line tools'
`clang`, which builds fwe's Linux Vulkan driver. The Rust toolchain's
`rust-lld` links the driver (rustup's toolchains have it); with a
toolchain that lacks it, `FWE_LLD` MUST name an `ld.lld`, such as
Homebrew's `lld`. Then build and sign `fwe` with the entitlements:

```sh
cargo build --release -p fwe
codesign --sign - --force --options runtime \
  --entitlements hypervisor.entitlements target/release/fwe
```

## A Linux userland

Linux programs expect a Linux filesystem around them: their libraries,
`/etc`, `/usr/bin`. `fwe --pull IMAGE DIR` makes one from a container
image: it fetches the image's linux/arm64 variant from its registry
(Docker Hub unless named otherwise) and unpacks it into `DIR`, a new or
empty directory. `--root DIR` makes that directory the program's `/`.

A program inside the root MUST be named by its path on the Mac. `fwe`
passes its environment on as it is, so the program SHOULD be given a
Linux one with `env -i`, as a login would. This guide uses a shell
function for both:

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

Beyond unpacking, `--pull`:

- keeps the owners and modes of files owned by users other than root,
  and of set-ID programs (`su`, `passwd`), as Linux programs see them, in
  extended attributes `fwe` reads. The guest sees your own files as
  root's, and runs as root unless it changes user;
- writes `/etc/resolv.conf` with your Mac's current name servers, and
  `/etc/hosts` where the image has none, as a container runtime does at a
  container's start;
- on a case-insensitive volume (macOS's default), leaves out and lists a
  file whose name differs from another's only in case, which cannot be
  kept there. Debian's image has one such file, a manual page. On a
  case-sensitive APFS volume nothing is left out:

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
  dynamically linked one needs its dynamic linker and libraries, so it
  MUST run in a root of the distribution it was built for, copied into
  it.
- **Threads, processes, signals, pipes, sockets, terminals and job
  control** behave as on Linux; `fork`, `exec` and `wait` make real Mac
  processes, one `fwe` for each Linux process.
- **Programs that make code as they run** (the JIT compilers of Node.js,
  Java, LuaJIT, Racket, Guile) run natively too ([jit.md](jit.md)).
- **Daemons:** one that detaches outlives the `fwe` command that started
  it, as on Linux. No Linux init or service manager runs; to keep a Linux
  daemon running as a macOS service, a `launchd` job runs `fwe` with the
  daemon in the foreground
  ([init, orphans and daemons](linux-on-macos.md#init-orphans-and-daemons)).
- **Networking** uses the Mac's: a server listening on a port is
  reachable from the Mac on that port, and outgoing connections go out as
  the Mac's do.
- **Files** outside the root are out of the program's reach. Without
  `--root`, the program sees the Mac's filesystem as its own.

### Programs linked below 4 GiB

macOS keeps the lowest 4 GiB of a process's address space for itself. A
program linked to load there (a non-PIE executable, such as Debian's
Python, GCC, clang and Go, or Alpine's SBCL) runs in a small VM instead,
through Hypervisor.framework. `fwe` chooses the VM by itself, and
`fwe --strace` says why. A static program linked there with its
relocations kept (`-Wl,--emit-relocs`) runs natively, moved above 4 GiB.

For the VM, `fwe` MUST be signed with the hypervisor entitlement
(Homebrew's and the releases' are) and run on a Mac that offers the
hypervisor (`sysctl kern.hv_support` prints `1`). Otherwise `fwe` says
the program needs the hypervisor backend and exits with status 126.
`fwe --vm` runs every program in the VM, for programs that need 4 KiB
pages, such as Wine. CI's machines offer no hypervisor, so CI tests the
VM backend only on a software stand-in for Hypervisor.framework
([roadmap](../ROADMAP.md)).

### Windows programs

Windows programs built for ARM64 run through Alpine's Wine, in the VM.
Wine's own Notepad, on the display ([below](#programs-with-windows)):

```sh
linux ~/alpine /bin/sh -c 'apk add -q wine font-dejavu'
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
  "$(command -v fwe)" --vm --root ~/alpine ~/alpine/bin/sh -c 'wine notepad'
```

A program of your own runs as `wine /path/in/the/root/program.exe`; the
[README's examples](../README.md#examples) run PuTTY and OpenTTD so.
`zig cc -target aarch64-windows-gnu` builds such a program from C (CI's
`wine` job runs `guests/windows/winprog.c` this way). Windows programs
draw through Wine's X11 driver and play sound through its PulseAudio
driver, as Linux programs do ([Sound](#sound)).

### Programs with windows

Linux programs draw their windows through an X server on the Mac:
XQuartz (`brew install --cask xquartz`), or any X server listening on a
Unix socket. `fwe` gives a program the display its own `DISPLAY` names,
which XQuartz sets for every program you start once it is installed; the
program sees it as Linux's display `:0` (`:N` for the Mac's `:N`).
XQuartz lets in only clients with its cookie: a program that brings none
is sent with yours, from `~/.Xauthority` (or the file `XAUTHORITY`
names in fwe's environment), as `ssh -X` sends a forwarded program's:

```sh
linux ~/alpine /bin/sh -c 'apk add -q xeyes xterm font-dejavu'
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
  "$(command -v fwe)" --root ~/alpine ~/alpine/usr/bin/xterm -fa monospace
```

X11 clients, Tk (tkinter), GTK 3 and 4 and Qt draw this way. Images go
to the server through shared memory (MIT-SHM) where the server takes it
by descriptor (MIT-SHM 1.2, as Xvfb's does). Wayland programs run in a
Weston started in the userland with its X11 back end
(`weston --backend=x11`), which draws in a window on the X server;
`--xwayland` adds Xwayland for X11 programs inside it.

OpenGL on the CPU, through Mesa's software renderer
(`LIBGL_ALWAYS_SOFTWARE=1`), needs a server with GLX that Mesa can use.
Homebrew's Xvfb has no GLX, and Mesa finds none of XQuartz's GLX
configurations usable; the userland's own X servers have it, run by fwe:
Xephyr, which shows its screen in a window on XQuartz, or Xvfb. Start
one, and give its programs its display inside, as the
[README's games](../README.md#extreme-tux-racer) do:

```sh
linux ~/alpine /bin/sh -c 'apk add -q xorg-server-xephyr mesa-dri-gallium mesa-demos'
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY="$DISPLAY" "$(command -v fwe)" --root ~/alpine ~/alpine/bin/sh -c \
  'Xephyr :1 -screen 800x600 & until [ -S /tmp/.X11-unix/X1 ]; do sleep 0.1; done
   DISPLAY=:1 LIBGL_ALWAYS_SOFTWARE=1 glxgears; kill $!'
```

### The GPU

Vulkan programs run natively draw on the Mac's GPU through fwe's own
Linux Vulkan driver, which passes each Vulkan command to the Mac's
Vulkan driver. Once the Mac has one, fwe puts its driver where a Linux
Vulkan loader looks (`/etc/vulkan/icd.d`). The Mac's driver is
KosmicKrisp (Homebrew's `mesa`, on macOS 26 with an Apple GPU) if
installed, else MoltenVK (`brew install molten-vk`); `FWE_VULKAN_DRIVER`,
in fwe's environment, names another driver's manifest.
`VK_DRIVER_FILES` makes fwe's driver the only one a program sees (a
userland's Mesa drivers draw on the CPU):

```sh
brew install molten-vk
linux ~/alpine /bin/sh -c 'apk add -q vulkan-tools'
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
  VK_DRIVER_FILES=/etc/vulkan/icd.d/fwe_icd.aarch64.json \
  "$(command -v fwe)" --root ~/alpine ~/alpine/usr/bin/vkcube --wsi xcb
```

OpenGL programs use the GPU through Mesa's Zink:
`MESA_LOADER_DRIVER_OVERRIDE=zink` selects it, with
`LIBGL_KOPPER_DRI2=1` on a server without DRI3, as Xvfb is.

### Sound

Programs play sound through PulseAudio on the Mac, which plays it on
CoreAudio:

```sh
brew install pulseaudio
brew services start pulseaudio
```

`fwe` hands its programs the server your own PulseAudio programs find
(its socket in `~/.config/pulse`), or the Unix socket `PULSE_SERVER`
names in fwe's environment, with your cookie (`~/.config/pulse/cookie`,
or `PULSE_COOKIE`). A program finds it as Linux's system-wide server,
with no setting in the userland. PulseAudio's programs play on it
directly, ALSA's through ALSA's PulseAudio plugin, and PipeWire's
through a PipeWire daemon in the userland with its PulseAudio tunnel:

```sh
linux ~/debian /bin/sh -c 'apt-get install -qq -y pulseaudio-utils alsa-utils libasound2-plugins'
env -i HOME=/root PATH=/usr/bin:/bin "$(command -v fwe)" --root ~/debian ~/debian/usr/bin/paplay \
  /usr/share/sounds/alsa/Front_Center.wav
env -i HOME=/root PATH=/usr/bin:/bin "$(command -v fwe)" --root ~/debian ~/debian/usr/bin/aplay \
  -D pulse /usr/share/sounds/alsa/Front_Center.wav
```

PipeWire's tunnel to the Mac's server is a module in PipeWire's
configuration, in the userland's `~/.config/pipewire/pipewire.conf.d/mac.conf`:

```
context.modules = [
  { name = libpipewire-module-pulse-tunnel
    args = { tunnel.mode = sink, pulse.server.address = "unix:/run/pulse/native",
             pulse.latency = 1000, node.name = mac } }
]
```

The tunnel keeps half its `pulse.latency` at the Mac's server and as much
of its own, and fills with silence what the server asks for before it has
it. Its default, 200 ms, leaves gaps when the Mac is busy; a second does
not. A sound's last `pulse.latency` is not played once its program has
stopped.

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
  namespace has nothing else ([below](#what-does-not-work)).

podman also builds images, pushes and pulls them, and runs rootless as
another user. Docker Engine (`dockerd --bridge=none --iptables=false
--ip6tables=false --storage-driver=overlay2`) runs, builds and composes
containers. CI's `podman` and `docker` jobs run both.

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
- **Linux's devices and drivers**: no `/dev/kvm`, FUSE or kernel
  modules. The only GPU is fwe's (Vulkan through fwe's driver, its
  windows X11's). Files live on the Mac's filesystem, so disk filesystems
  (ext4, btrfs) and block devices are not there.
- **Resource limits of cgroups** but the process count: accepted, not
  enforced.
- **A sandbox**: namespaces, seccomp and the rest keep well-behaved
  programs apart, as containers expect, but a program run natively
  shares the `fwe` process and acts as your user; untrusted code SHOULD
  run in a Linux VM ([isolation and security](linux-on-macos.md#isolation-and-security),
  [comparisons](comparisons.md)).
- **OpenGL 3 and WebGL on the GPU, with MoltenVK**: Zink gives OpenGL
  2.1 and OpenGL ES 2.0 there, so browsers draw WebGL in software (Mesa's
  llvmpipe, without `MESA_LOADER_DRIVER_OVERRIDE=zink`).
- **Zed on the GPU, with MoltenVK**: MoltenVK cannot compile Zed's
  shaders; Zed draws by software through Mesa's lavapipe
  (`VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.aarch64.json` and
  `ZED_ALLOW_EMULATED_GPU=1`).
- **ALSA's devices** (`/dev/snd`): ALSA's programs play only through
  ALSA's PulseAudio plugin ([Sound](#sound)).
- **The GPU in the VM, or after `fork`**: a program in the VM has no
  GPU, nor does a child forked from a process that used it (its Vulkan
  calls fail) until it runs a program with `execve`.
- **Programs for other processors** (x86-64, x86 Windows programs): `fwe`
  runs arm64 code only.
- **Chosen process ids** outside a pid namespace of fwe's: there pids are
  the Mac's.
- **More than 16384 open descriptors** in one process.

The full list is in the [roadmap](../ROADMAP.md#not-planned-for-10);
where `fwe` differs from Linux in detail is in the
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
  wrote the name servers your Mac had when it ran.
