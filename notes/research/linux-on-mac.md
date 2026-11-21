# Running Linux programs on macOS and Apple Silicon: a survey

Research notes, gathered 2026-11-20 from public sources (web pages, papers,
release notes, and the source code of Noah). Nothing here was run on this
machine. Every fact has its source beside it; a date is given where the
source has one. "Not found" means it was looked for and no source settled it.
Numbers are as the source states them, on its hardware, and are not
comparable across rows unless the row says so.

This file adds to [docs/comparisons.md](../../docs/comparisons.md), which
already places fwe beside Wine, VMs, WSL, gVisor, QEMU, DynamoRIO, FEX, Box64,
Rosetta 2 and the Linuxulator. Here the focus is on mechanisms and measured
numbers, and on projects that file does not cover.

Contents:

1. [The landscape in one table](#1-the-landscape-in-one-table)
2. [Apple's own stack](#2-apples-own-stack)
3. [Linux VMs on the Mac](#3-linux-vms-on-the-mac)
4. [Without a Linux kernel: in-process and kernel-less](#4-without-a-linux-kernel-in-process-and-kernel-less)
5. [Asahi Linux: Linux on the bare metal](#5-asahi-linux-linux-on-the-bare-metal)
6. [x86 on arm64: FEX and Box64](#6-x86-on-arm64-fex-and-box64)
7. [4 KiB programs on a 16 KiB system](#7-4-kib-programs-on-a-16-kib-system)
8. [Cross-cutting numbers](#8-cross-cutting-numbers)
9. [What fwe can take from these](#9-what-fwe-can-take-from-these)

---

## 1. The landscape in one table

| Approach | Example | Who answers system calls | Files | Memory returned to macOS | Start-up (as published) |
|---|---|---|---|---|---|
| One shared Linux VM | OrbStack, Docker Desktop, Lima, Colima, Podman machine | a real Linux kernel | shared into the VM (virtiofs, 9p, sshfs, custom) | mostly not under Virtualization.framework; partly with custom VMMs | seconds |
| A VM per container | Apple `container` | a real Linux kernel per container | ext4 block device per image; directories shared | not returned (Apple says so) | "sub-second" |
| A VM inside the process (library VMM) | libkrun, krunkit, muvm | a real Linux kernel (libkrunfw) | virtio-fs served in-process | free-page reporting balloon | not found |
| A VM per process, no kernel | Noah, Carrick, elfuse, hl, alvm, fwe's VM backend | a userspace kernel, on VM exits | the host's own, directly | the host's own memory management | Carrick ~90 ms |
| In-process, instructions rewritten | fwe native, Line (x86, Intel Mac), ASC-Hook (Linux) | a userspace kernel in the same process | directly | the host's own | milliseconds |
| Emulator with its own system-call layer | Blink, iSH | the emulator, translating to host calls | directly (Blink), or a SQLite metadata store (iSH) | the host's own | not found |
| Kernel personality | WSL1, Linuxulator, NetBSD compat_linux, illumos lx | the host kernel's second table | directly | the host's own | — |
| Bare metal Linux | Asahi | Linux | Linux's own | — | — |

---

## 2. Apple's own stack

### 2.1 Rosetta for Linux

**What it is.** Apple's x86-64 translator, offered to Linux guests of
Virtualization.framework (VZ) since macOS 13. It runs x86-64 programs inside an
arm64 Linux distribution; VZ cannot boot an x86 Linux distribution.
[Apple, "Running Intel Binaries in Linux VMs"](https://developer.apple.com/tutorials/data/documentation/virtualization/running-intel-binaries-in-linux-vms.md)

**How the guest gets it** (same Apple page):

- The host app creates `VZLinuxRosettaDirectoryShare()` and attaches it to a
  `VZVirtioFileSystemDeviceConfiguration(tag:)`. Rosetta reaches the guest as a
  **virtiofs share** holding a `rosetta` binary.
- In the guest a person mounts it (`mount -t virtiofs <TAG> /mnt`) and registers
  it with `binfmt_misc` for x86-64 ELF headers (`update-binfmts --install rosetta
  /mnt/rosetta` with the ELF machine `0x3e` magic, `--credentials yes --preserve
  yes --fix-binary yes`; `preserve` must be `no` on macOS 13). Apple says the app
  cannot script the guest-side steps.
- Static x86-64 binaries need nothing else; dynamic ones need x86-64 libraries
  installed in the guest.
- On the host, the files live in `/Library/Apple/usr/libexec/oah/RosettaLinux/`
  (`rosetta`, `rosettad`). Rosetta makes up a `/proc/cpuinfo` reading
  "VirtualApple @ 2.50GHz", family 6, model 142.
  [Inoki, 2026-02-28](https://blog.inoki.cc/2026/02/28/Apple-Rosetta-Linux-VM-Secret-en/index.html)
- Rosetta refuses to run outside VZ: it checks, by an ioctl through virtiofs to
  the host, a 0x45-byte key, and needs FEAT_FlagM and a 24 MHz or 1 GHz counter.
  [threedots.ovh, 2022-06-07](https://threedots.ovh/blog/2022/06/quick-look-at-rosetta-on-linux/)
  A feasibility report for libkrun found no equivalent of the VZ share under
  Hypervisor.framework. [tnk4on](https://tnk4on.github.io/libkrun-rosetta/)

**Ahead of time vs as it runs.** In 2022 Rosetta for Linux translated only as code ran
(JIT). [threedots.ovh, 2022](https://threedots.ovh/blog/2022/06/quick-look-at-rosetta-on-linux/)
macOS 14 added an ahead-of-time cache, set with
`VZLinuxRosettaDirectoryShare.setCachingOptions`. The cache is shared between
the Rosetta runtime and a daemon, `rosettad`, through a Unix socket
(`.unixSocket(path)`) or an abstract socket name (`.abstractSocket(name)`).
[Apple](https://developer.apple.com/tutorials/data/documentation/virtualization/running-intel-binaries-in-linux-vms.md)
Lima runs `rosettad` (Lima 2.0+, macOS 14+): containers ask for the CDI device
`lima-vm.io/rosetta=cached`, and the cache files are
`/var/cache/rosettad/*.aotcache`.
[Lima, multi-arch](https://lima-vm.io/docs/config/multi-arch)

**TSO (x86's stronger memory ordering).**

- Apple cores switch to x86-like total store order with bit 1 (`EnTSO`) of
  `ACTLR_EL1`, writable only by privileged code.
  [Khayet & Morrison, ASPLOS '26](https://www.cs.tau.ac.il/~mad/publications/asplos2026-TSO.pdf)
  The same paper measures TSO mode at about 1.9% harmonic-mean slowdown across
  49 applications once code fixes are applied (4.2% before), worst non-outlier
  11.5%.
- `AIDR_EL1` bit 9 says whether a core has it.
  [Hector Martin's patch, 2024-04-10](https://lkml.indiana.edu/2404.1/04830.html)
- An Apple engineer's Linux patch series lets a VZ Linux guest set the bit
  through a `prctl` (`PR_SET_MEM_MODEL`). It "must be done on Apple Silicon MacOS
  Sonoma version 14.4 or later, since earlier versions do not support
  modification of the TSOEN bit".
  [Zayd Qumsieh, 2024-04-10](https://lkml.iu.edu/hypermail/linux/kernel/2404.1/04656.html)
  He also wrote that `ACTLR_EL1.TSO` "is not exposed for writing on Virtual
  Machines on all versions of MacOS", and that reading `AIDR_EL1` traps to
  Hypervisor.framework.
  [2024-04-15](https://lists.infradead.org/pipermail/linux-arm-kernel/2024-April/920866.html)
- Upstream Linux maintainers refused the `prctl`. Will Deacon said it "is going
  to lead to subtle fragmentation of arm64 Linux userspace".
  [2024-04-11](https://lore.kernel.org/lkml/20240411132853.GA26481@willie-the-truck/)
  No merge was found.
- How Rosetta for Linux itself gets TSO today: not found in Apple documents. In
  2022, with the Rosetta share mapped, "the VM runs in TSO mode".
  [threedots.ovh](https://threedots.ovh/blog/2022/06/quick-look-at-rosetta-on-linux/)

**AVX.** Rosetta translates AVX and AVX2, not AVX-512, for macOS programs.
[Apple](https://developer.apple.com/tutorials/data/documentation/apple-silicon/about-the-rosetta-translation-environment.md)
For Linux guests, AVX2 was not exposed as of April 2025 (FB17421013).
[Apple forums](https://developer.apple.com/forums/thread/769486)
Linux-guest AVX on macOS 26 or 27: not found.

**Its future.**

- Rosetta for macOS programs "will be available through macOS 27"; after that,
  only "a subset of Rosetta functionality aimed at supporting older unmaintained
  gaming titles" stays.
  [Apple](https://developer.apple.com/tutorials/data/documentation/apple-silicon/about-the-rosetta-translation-environment.md)
- Linux translation stays and moves into the OS: "macOS 27 directly integrates
  support for Intel binary translation, without needing to install Rosetta".
  From macOS 27, `VZLinuxRosettaDirectoryShare.availability` always returns
  `.installed`.
  [Apple](https://developer.apple.com/tutorials/data/documentation/virtualization/running-intel-binaries-in-linux-vms.md)
- An Apple engineer: "No, Rosetta for Linux is not planned for deprecation."
  [Apple forums, June 2026](https://developer.apple.com/forums/thread/830176)

**Speed.**

- Geekbench 5 under Rosetta for Linux, hacked onto Graviton3 (not an Apple chip,
  no TSO): about 70% of native.
  [threedots.ovh, 2022](https://threedots.ovh/blog/2022/06/quick-look-at-rosetta-on-linux/)
- Rosetta for macOS, Geekbench: about 78–79% of native.
  [MacRumors, 2020-11-15](https://www.macrumors.com/2020/11/15/m1-chip-emulating-x86-benchmark/)
- 7-Zip on an M1: Rosetta 2 about 71% of native.
  [box86.org, 2022-03-24](https://box86.org/2022/03/box86-box64-vs-qemu-vs-fex-vs-rosetta2/)
- A careful Rosetta-in-Linux vs QEMU or vs native benchmark: not found. One
  anecdote: an amd64 Python image started in 4.2 s on OrbStack (Rosetta) and in
  12.8 s on Docker Desktop (QEMU).
  [dev.to](https://dev.to/pickuma/orbstack-deep-review-the-macos-native-container-runtime-that-replaces-docker-desktop-25p8)

### 2.2 Containerization and the `container` command

Announced at WWDC in June 2025.
[WWDC25 session 346](https://developer.apple.com/videos/play/wwdc2025/346/),
[apple/containerization](https://github.com/apple/containerization),
[apple/container](https://github.com/apple/container)

**Design.**

- Each Linux container runs "inside of its own lightweight virtual machine",
  and each can have its own IP address, so ports need no forwarding.
- Inside the VM, `vminitd` is the first process. It offers a gRPC API over vsock
  and relays I/O, signals and events.
  - It is written in Swift and built as a static musl executable.
  - The VM's root file system "has no core utilities… no dynamic libraries and no
    libc" (WWDC25 346).
- Start-up is "sub-second", thanks to "an optimized Linux kernel configuration"
  and a minimal root file system. The WWDC demo reached a shell "within a few
  hundred milliseconds".
- Images become block devices: the image's layers are written into an ext4 file
  system by a Swift package (ContainerizationEXT4) that formats and fills ext4
  directly. Host directories are "first shared with the virtual machine, before
  being provided to the specific container".
- "if no containers are running, no resources will be allocated" (WWDC25 346).
- Kernel:
  - Tested "starting with kernel version 6.14.9".
  - VIRTIO drivers must be built in, not loaded as modules.
  - Kata Containers' kernel is suggested; `container` 1.3.0 made Kata 3.32.0 the
    default.
  - Its page size: not found.

  [kernel/](https://github.com/apple/containerization/tree/main/kernel)
- A Linux host backend also exists (cloud-hypervisor over KVM).
- Needs Apple silicon and macOS 26; "Older versions of macOS are not supported".

**The `container` tool's parts** ([technical overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)):

- `container-apiserver`, a launch agent, starts XPC helpers for images, networks
  (`container-network-vmnet`) and machines.
- Each container gets one `container-runtime-linux` helper.

**Memory.** "The Virtualization framework has only partial memory ballooning
support." A VM uses only what it touches (`--memory 16g` may show about 2 GiB in
use), but "memory pages freed inside the container's VM are not returned to the
host"; the workaround is restarting the container.
[technical overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)

**Networking.**

- On macOS 15, containers cannot reach one another, all sit on 192.168.64.1/24,
  and `container network` is unavailable.
- macOS 26 adds custom vmnet networks (`vmnet_network_create`,
  `VZVmnetNetworkDeviceAttachment`).
  [WWDC26 session 224](https://developer.apple.com/videos/play/wwdc2026/224/)

**Releases** ([releases](https://github.com/apple/container/releases)):

| Version | Date | What it added |
|---|---|---|
| 0.1.0 | 2025-06-09 | first release |
| 0.3.0 | 2025-07-30 | localhost port publishing; nested virtualization |
| 0.4.1 | 2025-08-28 | named volumes, systemd |
| 0.7.0 | 2025-12-03 | Rosetta for image builds |
| 0.8.0 | 2026-01-22 | IPv6 |
| 1.0.0 | 2026-06-09 | `container machine`: long-lived Linux environments, one VM each ([WWDC26 session 389](https://developer.apple.com/videos/play/wwdc2026/389)) |
| 1.6.x | 2026-10 | `container commit`, `container cluster` |
| 1.7.1 | 2026-11-06 | current |

**Measured.** A third-party RepoFlow benchmark, as reported by byteiota (May
2026), gives container start at 0.21 s for Docker Desktop and 0.92 s for Apple
`container`. The methodology was not seen.
[byteiota](https://byteiota.com/apple-container-cli-linux-macos/)

### 2.3 Virtualization.framework (VZ): limits that matter

- **Number of VMs:** VZ "enforces this cap for Mac VMs… But has no fixed cap for
  Linux VMs". [Apple DTS, Sep 2026](https://developer.apple.com/forums/thread/845455)
- **Nested virtualization:** `VZGenericPlatformConfiguration.isNestedVirtualizationEnabled`,
  macOS 15+. [Apple](https://developer.apple.com/documentation/virtualization/vzgenericplatformconfiguration/isnestedvirtualizationenabled.md)
  The M3-or-later requirement is stated by third parties (UTM, Parallels), not by
  Apple.
- **Memory balloon:** `VZVirtioTraditionalMemoryBalloonDevice` takes a target
  size; there is no free-page reporting.
  [Apple](https://developer.apple.com/documentation/virtualization/vzvirtiotraditionalmemoryballoondevice.md)
  A measurement (macOS 26.4) found the balloon does not return memory at all:
  - Guest memory lives in the XPC helper `com.apple.Virtualization.VirtualMachine`.
  - Its footprint went from 718 MB idle to 3,717 MB after the guest filled and
    freed 3 GB, and stayed there.
  - Inflating the balloon by 15.35 GB left the footprint "byte-identical"; the
    ballooned pages were only compressed under pressure.

  [ArcBox, 2026](https://arcbox.dev/blog/macos-vm-memory-ratchet)
- **Graphics:** `VZVirtioGraphicsDeviceConfiguration` (macOS 13) offers scanouts
  only. An Apple statement on 3D for Linux guests: not found.
- **Clipboard:** a SPICE agent port (`sharesClipboard`), macOS 13.
- **USB:** emulated mass storage hot-plug on macOS 15; on macOS 27, an "Accessory
  Access" framework passes USB devices through to macOS and Linux VMs.
  [WWDC26 224](https://developer.apple.com/videos/play/wwdc2026/224/)
- **macOS 27 additions:** custom Virtio devices for Linux guests, stackable ASIF
  disk layers (DiskImageKit), EFI Secure Boot for Linux (WWDC26 224).
- **Snapshots:** `saveMachineStateToURL` failed with `VZErrorInternal` for a
  third party, likely because it needs the private
  `com.apple.private.virtualization` entitlement.
  [Encore, 2026-08-18](https://encore.dev/blog/firecracker-apple-silicon)
- **Guest page size:** not stated by Apple. Linux guests with 4 KiB pages run (the
  guest picks its own stage-1 granule); the host's pages are 16 KiB.

### 2.4 Hypervisor.framework (HVF): what the APIs allow

- **One VM per process.** `hv_vm_create` "Creates a VM instance for the current
  process". [Apple](https://developer.apple.com/documentation/hypervisor/hv_vm_create(_:).md)
- **IPA size:** `hv_vm_config_set_ipa_size` and the
  `hv_vm_config_get_max_ipa_size`/`get_default_ipa_size` getters, macOS 13. A
  QEMU reviewer reports about 4 TB at 16K and 1 TB at 4K on an M4 Max, and that
  the public getter seems to give the smaller value.
  [patchew, 2025-12-19](https://patchew.org/QEMU/20251219183716.4379-1-j@getutm.app)
- **4 KiB stage 2 (IPA granule):** `hv_vm_config_set_ipa_granule` with
  `HV_IPA_GRANULE_4KB` or `16KB`, macOS 26. Before that, `hv_vm_map` needed
  16 KiB alignment.
  [Apple](https://developer.apple.com/documentation/hypervisor/hv_vm_config_set_ipa_granule(_:_:).md)
  QEMU patches add `ipa-granule=4k` (March 2026; merge not found).
  [patchew](https://patchew.org/QEMU/20260309214906.92578-1-lucaaamaral@gmail.com)
- **GIC:** `hv_gic_create`, macOS 15: a GICv3 with distributor, redistributors and
  MSIs. [Apple](https://developer.apple.com/documentation/hypervisor/hv_gic_create(_:).md)
- **EL2 (nested):** `hv_vm_config_set_el2_enabled`, macOS 15. HVF "doesn't provide
  a reset state for the vCPUs".
  [Apple forums, Mar 2025](https://developer.apple.com/forums/thread/775546)
- **Maximum vCPUs:** `hv_vm_get_max_vcpu_count` exists; per-chip values were not
  found.
- **Guest TSO:** there is no public API. Guest writes to `ACTLR_EL1.TSOEN` work from
  macOS 14.4 per Apple's own Linux patch, "not on all versions" (2.1 above).
- **Returning memory under HVF.** `MADV_DONTNEED` does nothing to the footprint.
  `MADV_FREE` makes pages discardable only under pressure. `MADV_FREE_REUSABLE`
  drops the footprint at once. For pages the guest has dirtied through stage 2,
  `madvise` is "a silent no-op" unless the range is first `hv_vm_unmap`ped and
  then `hv_vm_map`ped again; done so, 3,073 MiB were freed from a live VM.
  [ArcBox](https://arcbox.dev/blog/macos-vm-memory-ratchet)
- **`hvc #0`:** HVF silently takes some `hvc #0` calls as SMCCC when `x0` matches
  a function ID; Carrick switched to `hvc #2`.
  [Carrick, 2026-06-05](https://carrick-website.pages.dev/blog/introducing-carrick)

---

## 3. Linux VMs on the Mac

### 3.1 OrbStack

**Hypervisor.**

- Version 1.6.0 (2024-05-22) brought a "New virtualization engine".
  [release notes](https://docs.orbstack.dev/release-notes)
- Its developer said (on Hacker News, about mid-2026): "Instead of
  Virtualization.framework, we have a custom Rust virtualization stack with
  custom devices and protocols for things like filesystem sharing".
  [HN](https://news.ycombinator.com/item?id=48470145)
- Whether that stack sits directly on Hypervisor.framework: not stated.

**Kernel.**

- One custom kernel shared by all of OrbStack's Linux "machines", which "are not
  independent VMs" (as in WSL2). [architecture](https://docs.orbstack.dev/architecture)
- Linux 7.2.12 in v2.2.5 (2026-10-23).
- On Apple Silicon, KASLR is "augmented" so the kernel avoids KPTI overhead,
  which they say makes system calls faster.
- No nested KVM. [machines](https://docs.orbstack.dev/machines/)

**Files.**

- VirtioFS plus "custom dynamic caching"; Mac files at `/mnt/mac`, Linux files at
  `~/OrbStack`. [architecture](https://docs.orbstack.dev/architecture)
- 1.6 claims per-call overhead cut "by up to 10x", "2–10x faster, reaching 75–95%
  of native". It waits for data to reach the SSD before reporting it written.
  [OrbStack blog, 2024-05-22](https://orbstack.dev/blog/fast-filesystem)

| Workload (1614 Node packages, 807 MiB) | OrbStack vs native macOS | % of native |
|---|---|---|
| `pnpm install` | 12.2 s vs 10.9 s | 88% |
| `yarn install` | 9.8 s vs 7.9 s | 77% |
| `rm -rf node_modules` | 4.0 s vs 3.6 s | 87% |
| Postgres `pgbench` | 8998 vs 11785 TPS | 76% |

**Memory.**

- "Dynamic memory" in v1.7.0 (2024-08-22) builds on a "giant array" that tracks
  which parts of guest RAM are in use, and gives unused memory back to macOS.
  [blog](https://orbstack.dev/blog/dynamic-memory)
- The exact mechanism (balloon, free-page reporting, madvise): not found.
- In 2023, under VZ, freed memory "can't be released without restarting".
  [quoted by ArcBox](https://arcbox.dev/blog/macos-vm-memory-ratchet)
- Idle CPU about 0.1%. [efficiency](https://docs.orbstack.dev/efficiency)

**Networking.**

- A "custom virtual network stack": IPv4 and IPv6 NAT, a DNS server that forwards
  to macOS's (so it follows VPNs), and event-based port forwarding to localhost.
- Up to 45 Gbps between macOS and containers.
- Container IPs are reachable from macOS, under `<name>.orb.local` names; macOS
  proxy settings and keychain certificate authorities are carried in.
  [architecture](https://docs.orbstack.dev/architecture),
  [network](https://docs.orbstack.dev/docker/network)

**Other.**

- `binfmt_misc` runs Mac programs from inside Linux; a `mac` command prefix
  does the same.
- x86 through Rosetta, "much faster than QEMU". How Rosetta is used under a
  custom VMM: not found.
- GPU: none found.
- Start-up: "Starts in seconds"; a precise official figure was not found. One
  third-party post measured 1.8 s cold start, but its stated versions do not add
  up, so it is weak evidence.
  [dev.to](https://dev.to/michael_sun_18a5c4c96768d/utm-vs-orbstack-vs-lima-macos-vm-real-cold-start-disk-io-and-memory-numbers-on-m3-macbook-pro-4j6d)

**What is clever:** owning the whole stack (VMM, devices, file protocol,
network) to tune each crossing; a kernel tuned for syscall cost (no KPTI);
memory tracking to return RAM, which VZ cannot do.

### 3.2 Docker Desktop for Mac

**Hypervisors.**

- VZ is the stable default.
- "Docker VMM" was a beta from 4.35 (November 2024), built on libkrun up to 4.85.
  From 4.86 it is Docker's own closed VMM.
  [Docker docs](https://docs.docker.com/desktop/features/vmm/)
- Docker VMM went to public beta on 2026-08-12, with GA targeted for the end of
  October 2026 as the default for new installs.
  [Docker blog](https://www.docker.com/blog/docker-vmm-public-beta/)
- It claims faster start-up, faster file I/O and memory returned when idle; no
  numbers or mechanism were published.
- It has no Rosetta, and needs at least 4 GB of VM memory.

**Files.**

- VirtioFS arrived in 4.6 (2022-03-16).
  [Docker blog](https://www.docker.com/blog/speed-boost-achievement-unlocked-on-docker-desktop-4-6-for-mac/)

  | Workload | Before → with VirtioFS |
  |---|---|
  | MySQL import of 284 MB | 3m16s → 18s |
  | `composer install` | 1m27s → 11s |
  | A TypeScript app's boot | 1m30s → 18s |

  Docker sums this up as "up to 98%" less time.
- Later releases tuned caches: 4.31 longer attribute-cache timeouts; 4.33 a
  longer directory-cache timeout and no `security.capability` FUSE requests.
- Synchronized file shares (4.27, 2024-02-06), on paid plans: Mutagen keeps an
  ext4 copy of host directories inside the VM and syncs both ways, so container
  file calls never cross the VM boundary. The cost is that files are stored
  twice. [Docker blog](https://www.docker.com/blog/announcing-synchronized-file-shares/)
- libkrun-era Docker VMM (2024-11-21, read from charts): `git status` cold about
  27 s on VZ vs just under 10 s.
  [Docker blog](https://www.docker.com/blog/what-are-the-latest-docker-desktop-enterprise-grade-performance-optimizations/)

**Networking.**

- vpnkit (OCaml) ended the guest's TCP connections and re-made them as host
  `connect()` calls, so a VPN sees ordinary host traffic.
  [Docker blog, 2022-01-25](https://www.docker.com/blog/how-docker-desktop-networking-works-under-the-hood/)
- 4.19 (2023) moved to gVisor's TCP/IP stack, said to be "5x faster"
  (secondhand). [Collabnix](https://collabnix.com/docker-desktop-for-mac-is-no-longer-slow-and-how-docker-team-fixed-it/)

**Memory.** Resource Saver stops the VM when no container runs; waking takes
about 3–10 s. [docs](https://docs.docker.com/desktop/use-desktop/resource-saver)

**GPU.** None. Docker Model Runner runs llama.cpp and vllm-metal as native macOS
processes because "there is no GPU passthrough for Metal in containers".
[Docker blog](https://www.docker.com/blog/docker-model-runner-vllm-metal-macos/)

### 3.3 Lima and Colima

**VM types.**

- VZ is the default from Lima 1.0 (macOS ≥ 13.5); QEMU otherwise.
  [vmtype](https://lima-vm.io/docs/config/vmtype/)
- krunkit (experimental, Lima 2.0, macOS 14) gives a GPU through Mesa Venus.
  [krunkit](https://lima-vm.io/docs/config/vmtype/krunkit/)
- Lima 2.0 (November 2025) added plugins and an MCP server for sandboxing AI
  agents. [FOSDEM 2026 slides](https://archive.fosdem.org/2026/events/attachments/RGCTDY-lima/slides/266976/lima_yjbsxrd.pdf)

**Mounts.**

- reverse-sshfs before 0.17; virtiofs for VZ since 0.17; 9p for QEMU since 1.0
  (msize 128 KiB).
- Lima publishes no file-speed numbers. [mount](https://lima-vm.io/docs/config/mount/)

**Ports.**

- A guest agent watches sockets (eBPF on `NETLINK_SOCK_DIAG`) and forwards them.
  [port](https://lima-vm.io/docs/config/port/)
- Measured throughput, M4 Max:

| Path | Throughput |
|---|---|
| SSH over vsock | 6.32 Gbit/s |
| gRPC | 5.37 Gbit/s |
| SSH without vsock | 4.06 Gbit/s |
| vzNAT (guest by IP) | 59.2 Gbit/s |
| socket_vmnet | 3.46 Gbit/s |

**Networking.** By default, user-mode (slirp) networking: the guest is
192.168.5.15 and the host 192.168.5.2.
[network](https://lima-vm.io/docs/config/network/user/)

**x86.** Rosetta on VZ, with the AOT cache. A patched QEMU "hybrid" with HVF is
about 9x faster than TCG for compiling C.
[multi-arch](https://lima-vm.io/docs/config/multi-arch/)

**Colima** puts Docker, containerd or Incus on Lima; `--vm-type krunkit` gives
GPU containers. [colima](https://github.com/abiosoft/colima)

### 3.4 Podman machine

- Two providers: applehv (vfkit on VZ) and libkrun (krunkit). krunkit has been
  in the installer since Podman 5.2.
  [Podman blog](https://blog.podman.io/2024/07/podman-and-libkrun/)
- libkrun is the default in Podman 6.
  [Podman blog, 2025-10-31](https://blog.podman.io/2025/10/podman-6-machine-usability-improvements/)
- Networking through gvproxy (gvisor-tap-vsock); files through virtiofs.
  [Red Hat](https://www.redhat.com/en/blog/podman-mac-machine-architecture)
- `--device /dev/dri` gives a container a Venus GPU.

### 3.5 libkrun, krunkit and muvm: a VMM as a library

**libkrun** ([repo](https://github.com/containers/libkrun)):

- A dynamic library that embeds a Rust VMM in the calling process: KVM on Linux,
  HVF on macOS.
- Devices: console, blk, fs, gpu (Venus and native context), net, vsock, balloon
  (free-page reporting only), rng, rtc.

**libkrunfw.** The guest kernel is shipped inside a shared library: the dynamic
linker maps its sections and libkrun places them in guest memory with no further
work. [libkrunfw](https://github.com/containers/libkrunfw)

**TSI (Transparent Socket Impersonation).**

- The patched guest kernel hands socket calls over vsock to the VMM, which opens
  real host sockets (TCP, UDP and absolute-path Unix sockets) for connections and
  listeners.
- The guest has no network card and lives in "the host's network context".
- Limits: no listening on datagram sockets; it excludes virtio-net. Muvm moved
  from TSI to virtio-net plus passt because TSI did not work well with Steam.
  [sinrega, 2023-10-06](https://sinrega.org/2023-10-06-using-microvms-for-gaming-on-fedora-asahi)

**virtio-fs served inside the VMM process.** An experimental synchronous mode
(`VIRTIO_FS_F_SYNC`) gives each vCPU its own queue. When the guest kicks it, the
VM exit takes the vCPU thread straight into the file-system code, which does the
host call, writes the reply and resumes the guest: no worker thread, no
completion interrupt.
[Sergio López, 2026-10-16](https://sinrega.org/2026-10-16-synchronous-queues-virtio-fs/)
Measured on an M3 Pro with 8 vCPUs:

| Test | Asynchronous → synchronous |
|---|---|
| kernel build (`make -j8`) | 463.8 s → 334.3 s; system CPU 25m02s → 11m03s |
| fio 4 KiB random read/write, 1 job | 41.7 → 55.2 MiB/s |
| fio, 4 jobs | 120 → 149 MiB/s |
| `unlinkat`, mean | 161 µs → 103 µs |

**GPU.**

- How it works: Mesa's Venus driver in the guest → virtio-gpu shared memory →
  virglrenderer → MoltenVK → Metal on the host.
- llama.cpp with Llama 3.1 8B on an M4 Pro: CPU 0.52 tok/s; Vulkan 20.84 tok/s.
  Containers reach 74–80% of native Metal.
  [Red Hat, 2025-06-05](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers)
- "API remoting" forwards ggml calls to the host's ggml-metal instead of Vulkan
  commands, and reaches native speed (worst case about 95%). It "isn't
  multitenant safe".
  [Red Hat, 2025-09-18](https://developers.redhat.com/articles/2025/09/18/reach-native-speed-macos-llamacpp-container-inference)

**krunkit** is libkrun-efi (a full VM with EDK2 firmware) behind vfkit's
command line, macOS 14+.
[sinrega, 2024-03-06](https://sinrega.org/2024-03-06-enabling-containers-gpu-macos/)

**muvm** is libkrun with a 4 KiB-page kernel on Asahi's 16 KiB hosts; see
[5](#5-asahi-linux-linux-on-the-bare-metal).

Start-up times for libkrun: not found.

### 3.6 UTM, Tart, vfkit

- **UTM:**
  - Backends: QEMU (TCG for x86, the default) and VZ. Rosetta works only on VZ.
  - Its QEMU backend offers a GPU: VirGL for OpenGL and Venus for Vulkan 1.3,
    through ANGLE/Metal; it is experimental and "may crash".
  - [display](https://docs.getutm.app/settings-qemu/devices/display/)
- **Tart:**
  - VZ VMs whose images are stored in OCI registries.
  - Its maker, Cirrus Labs, joined OpenAI (announced 2026-04-07), and the
    repository moved to github.com/openai/tart.
  - [tart.run](https://tart.run/),
    [MacStadium](https://macstadium.com/blog/cirrus-labs-is-joining-openai)
- **vfkit:**
  - A VZ command-line tool used by Podman, minikube and crc.
  - It has a REST API, and Linux kernels must be uncompressed.
  - [usage](https://github.com/crc-org/vfkit/blob/main/doc/usage.md)

### 3.7 Comparisons across VM tools

**`npm install`, M4 Pro, mean of 3** ([Paolo Mainardi, 2025-01-04](https://www.paolomainardi.com/posts/docker-performance-macos-2025/)):

| Tool | Bind mount | Bind mount + volume |
|---|---|---|
| Lima 1.0.3 (VZ, virtiofs) | 8.99 s | 3.96 s |
| Docker Desktop 4.37.1 (VZ) | 9.53 s | 3.61 s |
| Docker VMM (libkrun) | 8.47 s | 3.42 s |
| Docker synchronized file shares | 3.88 s | not given |
| OrbStack 1.9.2 | 4.22 s | 3.19 s |
| native macOS | about 3.4 s | — |

The author's summary: bind mounts run about 3x native, down from 5–6x in 2022.

**Playwright suite, M2 Max** ([DDEV, Dec 2023](https://github.com/ddev/ddev/discussions/5599)):

| Tool | virtiofs | Mutagen |
|---|---|---|
| Colima | 138.3 s | 62.1 s |
| OrbStack | 99.0 s | 61.8 s |

**What is slow in all of them, and why.** Each file call from Linux crosses the
VM boundary into a host process that repeats it on APFS. Caching attributes and
directory entries in the guest is what speeds it up (OrbStack, Docker's timeout
changes), and the sync mode in libkrun shows the crossing itself (a worker
thread plus an interrupt) is a large share. Avoiding the crossing altogether
(Mutagen's copy inside the VM) gets closest to native.

---

## 4. Without a Linux kernel: in-process and kernel-less

### 4.1 Noah (2016–2020): the nearest prior art

Sources:

- [repository](https://github.com/linux-noah/noah) (archived 2020-06-09; last commit
  2020-06-09)
- the source read for these notes: `src/main.c`, `lib/vmm.c`,
  `src/mm/*.c`, `src/proc/fork.c`, `src/ipc/*.c`, `include/syscall.h`
- [Open Source Summit slides](https://events.static.linuxfound.org/sites/events/files/slides/Noah%20Hypervisor-Based%20Darwin%20Subsystem%20for%20Linux.pdf)
- the VEE 2020 paper, Saeki, Nishiwaki, Shinagawa, Honiden, "A Robust and Flexible
  Operating System Compatibility Architecture", DOI 10.1145/3381052.3381327 (full
  text not reachable; numbers below are from its talk slides:
  [Speaker Deck](https://speakerdeck.com/nullpo_head/noah-a-robust-and-flexible-operating-system-compatibility-architecture),
  [SlideShare](https://www.slideshare.net/TakayaSaeki/noah-robust-and-flexible-operating-system-compatibility-architecture-container-runtime-meetup-2))

**Target.** x86-64 Linux programs on Intel Macs (Hypervisor.framework's VT-x
interface), macOS Sierra and later. A Windows prototype, NoahW, used Intel HAXM.

**Shape.**

- One macOS process plus one VM per Linux process.
- The VM holds no kernel. Noah's ELF loader puts the program in the VM, and the
  program runs in guest user mode.
- Every exception exits the VM (`VMCS_CTRL_EXC_BITMAP = 0xffffffff`).

**How a system call reaches Noah** (`src/main.c`).

- Noah leaves `syscall` disabled in the guest, so the instruction raises an
  invalid-opcode exception (#UD), which exits the VM.
- Noah checks that the two bytes at `rip` are `0f 05`, reads the six argument
  registers, calls `sc_handler_table[rax]`, writes `rax` and steps `rip` past the
  instruction.
- AVX instructions are also caught by #UD the first time, and Noah then turns on
  the AVX state in `XCR0`.
- `CPUID` exits and is answered from the host's.

**Memory** (`src/mm/mm.c`, `src/mm/mmap.c`).

- The guest page tables are fixed: a "straight mapping" in which guest virtual
  equals guest physical, built once from 1 GiB entries (`pdp.h`). The user range
  ends at `0x7fc0000000` (just under 512 GiB, 39 bits), and there is no kernel
  half.
- All per-page work is done in the second stage (EPT) through `hv_vm_map` and
  `hv_vm_unmap`.
- A Linux `mmap` becomes a host `mmap` of the same kind, recorded in a red-black
  tree of regions and mapped into the VM at the guest address with the requested
  protection. `mprotect` and `munmap` change the EPT mapping.
- Guest faults arrive as EPT violations; if the address is not in a region,
  Noah raises `SIGSEGV`.
- Pages are 4 KiB (Intel).
- The slides' point: a single address translation (only the EPT), not two.

**Threads** (`src/proc/fork.c`).

- One vCPU per Linux thread, each on its own pthread.
- A new thread copies the creating vCPU's registers and VMCS fields, sets `rsp`
  and `rax = 0`, and joins the process's task list.

**fork.**

- Hypervisor.framework allowed one VM per process and could not fork one. Noah
  therefore snapshots the vCPU (registers, VMCS fields, FPU state), **destroys
  the VM**, calls the host `fork()`, and in both processes creates a new VM,
  re-maps every region (`restore_ept`) and restores the vCPU.
- Memory is shared copy-on-write by the host's own `fork`.
- A multi-threaded process cannot fork ("multi-threaded fork is not implemented
  yet").
- `vfork` is a plain `fork`.

**exec** reloads the ELF in the same VM.

**Signals** (`src/ipc/signal.c`).

- Linux handlers are installed as host handlers that only set a pending bit.
- Pending signals are checked before each VM entry (`task_run`). Noah builds
  Linux's `rt_sigframe` on the guest stack and points `rip` at the handler.
- Nothing forces a running vCPU out of the VM, so a thread spinning without
  exits does not see its signal until its next exit.
- Real-time signals are not sent ("RT signal is raised" warning).

**futex** is a per-process hash table of pthread condition variables, so shared
futexes between processes are not supported.

**Files.**

- A VFS with mount points maps `/Users`, `/dev` and `/tmp` to the host's and
  `/usr`, `/etc` and the rest to `~/.noah/tree`.
- Paths are resolved component by component, with symlinks and mounts handled
  by Noah (`resolve_path`).
- Sockets are file descriptors of the VFS.
- `select`, `pselect6` and `poll` are passed through; there is no `epoll` at all.

**Coverage.**

- 329 x86-64 system calls in the table, 172 implemented.
- `ptrace` is unimplemented, so `strace` cannot run inside. Noah has a
  "meta-strace" (`--strace FILE`) that logs calls from outside the VM.
- Ran apt-get, pacman (some subcommands), vim, gcc, make, Ruby, X clients (xeyes,
  doom 3) and a Linux kernel build.

**Measured** (talk slides, VEE 2020; hardware not stated; the speaker notes
imply the baseline is native macOS on the same machine):

- `dup()` breakdown: a VM entry and a VM exit each cost "around three hundred
  cycles"; the host system call about 2,000 cycles. Simple calls pay most; the
  authors say the entry/exit path could be optimized.
- lmbench overheads, in slide order (mapping of values to labels inferred from
  text order):

  | Test | Overhead |
  |---|---|
  | null call | 410% |
  | null I/O | 310% |
  | stat | 175% |
  | open/close | 172% |
  | signal install | 329% |
  | signal handle | 239% |
  | fork | 256% |
  | exec | −24% (faster) |
  | 0K file create | 42% |
  | protection fault | −45% |
  | page fault | −92% |

- Phoronix: Linux kernel build 16% slower.
- NoahW against Cygwin and WSL1:

  | Test | NoahW | Cygwin | WSL1 |
  |---|---|---|---|
  | `dup2`, calls per second | 36,723 | 556,453 | 693,309 |
  | `fork` with a 0 MiB array | 106.4 ms | 219.4 ms | 2.06 ms |
  | `fork` with a 1 GiB array | 458.4 ms | 1531.8 ms | 62.66 ms |

**Lessons.**

- Robust: "Bugs in Noah never cause kernel panic".
- Cheap where the host does the work (exec, page faults).
- Slow per call: two VM transitions plus the host call. fork, which tears the
  whole VM down and rebuilds it, scales with the mappings.
- The model fixes one translation (the EPT) and makes every `mmap`/`mprotect` a
  stage-2 change, the opposite of the newer projects below.

### 4.2 The newer Hypervisor.framework projects on Apple Silicon

All run arm64 Linux programs at EL0 in a VM with no kernel, and trap `svc` to a
host-side handler.

**Carrick** ([site](https://carrick-website.pages.dev/), [blog, 2026-06-05](https://carrick-website.pages.dev/blog/introducing-carrick)):

- **System calls:** the guest's `svc #0` goes to a tiny EL1 vector, which exits
  with `hvc #2` (not `#0`, see [2.4](#24-hypervisorframework-hvf-what-the-apis-allow)).
- **Memory:** stage-1 identity page tables with the MMU on, "so exclusive loads
  and stores (`ldaxr`/`stlxr`) work".
- **Threads:** one pthread and one vCPU per guest thread. Locks are per subsystem
  (fs, creds, proc, signal, mem); a single big lock lasted two days.
- **fork:** pause sibling vCPUs at a lock-safe point, then call the real macOS
  `fork()`. The child inherits the host's copy-on-write memory, re-registers it
  with `hv_vm_map`, and both processes build a fresh vCPU. (fwe's rule is never
  to fork with a VM alive; see [AGENTS.md](../../AGENTS.md).)
- **Measured with DTrace** (`/bin/true`):

  | Step | Cost |
  |---|---|
  | first boot | ~90 ms |
  | fork | ~5.7 ms |
  | fork + exec | ~7.8 ms (native Linux ~1 ms) |
  | child teardown | ~7 µs |
  | process teardown | ~175 ms, "as the kernel reclaims the large VM mapping" |

- **Coverage:**
  - About 216 of 338 arm64 system calls.
  - LTP 671/893 (75%).
  - Go about 876/880 standard-library test binaries.
  - Node.js 5301/5304 tests.
  - No ptrace.

**elfuse** ([repo](https://github.com/sysprog21/elfuse), Apache-2.0):

- **Design:** an EL1 shim and an HVC protocol; guest memory is one mmap'd slab;
  threads map 1:1 to vCPUs, at most 64.
- **fork:** `posix_spawn`s a new elfuse process and transfers the state.
- **Other features:** synthetic `/proc` and `/dev`; FUSE inside the guest without
  macFUSE; x86-64 through Rosetta in the same VM.
- **Speed:** claims "millisecond-scale" start-up and per-call overhead in
  microseconds; no figures given.
- **Byte-exact Linux file names on case-insensitive APFS**
  ([docs/filenames.md](https://raw.githubusercontent.com/sysprog21/elfuse/main/docs/filenames.md)):
  - A name is stored as itself only if it is "fold-stable": lowercase ASCII, no
    byte above `0x7f`, and not shaped like an escape.
  - Every other name is stored under a reversible escape: `.ef=` plus the bytes
    in lowercase hex (`README` → `.ef=524541444d45`), or 12 bits per CJK ideograph
    for names over 125 bytes.
  - The stored name is a pure function of the Linux name, with no side table, so
    `openat`, `renameat` and `unlinkat` stay single host calls.
  - Lookup tries the literal spelling first, so files staged from outside (a
    `Makefile`) keep working. `getdents64` and inotify decode on the way out.
  - Costs: names about twice as long (host `PATH_MAX` is 1024); each path
    component is probed. It applies only inside the sysroot, and only on a
    case-folding volume.

**hl / hyper-linux** ([repo](https://github.com/zw3rk/hyper-linux); from the team's
reading of `src/guest.c`, `src/fork_ipc.c`, `src/shim.S`, 2026-11-04):

- Guest memory is one host slab, `hv_vm_map`ped once. `munmap` and `mprotect`
  edit the guest's stage-1 tables and flush the TLB, never stage 2.
- fork is `posix_spawn` of a new runtime plus socketpair IPC, with memory sent as
  a file-backed slab.
- `CLONE_VM` without `CLONE_THREAD` (vfork) runs in the same process and VM.

**alvm** ([repo](https://github.com/mathetake/alvm)) is a one-commit experiment
with the same shape, in Rust.

**What the newer ones agree on, against Noah:** permissions in stage 1, one
stage-2 mapping made once. Noah did the opposite, because Intel's EPT made it
the cheap path.

### 4.3 In-process system-call rewriting (fwe's native approach)

**Line** ([geekprojects/line](https://github.com/geekprojects/line), GPL-3.0):

- An experiment running x86-64 Linux ELF programs inside a macOS process on
  Intel Macs, with its own dynamic linker.
- It finds `syscall` instructions and `%fs` accesses ahead of time (with
  libdisasm) and replaces them with breakpoints; far jumps and calls are patched
  too.
- "Bare minimum" of system calls; no performance figures; date not shown.

**ASC-Hook** ([arXiv 2412.05784v4, 2025-06-21](https://arxiv.org/html/2412.05784v4)), arm64 Linux:

- **How it rewrites:**
  - The instruction that sets `x8` (the call number) becomes `mov x8, #tramp`,
    and the `svc` becomes `br x8`.
  - The first-level trampolines start at address 4096, so page 0 stays unmapped;
    a 16-bit immediate allows 3,840 sites, with an `adrp` fallback beyond that.
  - Each site gets a second-level trampoline that redoes the original `x8` set.
- **What it skips:** static analysis drops sites with no visible `x8` set, or
  with a jump target between the two instructions; those use `brk` and a signal.
- **Learning from faults:** a jump straight to the `br x8` sets the PC to the
  call number, which faults as misaligned. The handler records the site in a
  file, so the next run avoids it.
- **Measured** on a 2.8 GHz Neoverse-N1:

  | getpid through | ns per call |
  |---|---|
  | LD_PRELOAD | 6.79 |
  | ASC-Hook | 33.5 |
  | a signal | 986.7 |
  | ptrace | 2059.6 |

  Applications heavy in system calls run 3.7% slower on average.
- **Note:** Linux's Syscall User Dispatch is not available on arm64.

**zpoline** ([USENIX ATC 2023](https://www.usenix.org/conference/atc23/presentation/yasukata)),
x86-64:

- `syscall` → `callq *%rax`, with a trampoline at address 0 (the call number is
  the jump target).

**lazypoline** ([DSN 2024](https://adriaanjacobs.github.io/files/dsn24lazypoline.pdf)):

- Finds each site the first time it runs, through a slow kernel path, then
  rewrites it.

**LFI** ([README](https://android.googlesource.com/platform/external/lfi/lfi-runtime/+/5030ec6653f3a0b0514d79c929d6d082d75050d1/README.md),
[poster](https://www.scs.stanford.edu/~zyedidia/docs/lfi/lfi-poster.pdf)),
arm64 software fault isolation:

- A Linux emulation layer over a sandbox runtime.
- Poster figures:
  - a system call in 22 ns, against 129 ns on Linux
  - about 6–7% overhead on SPEC
  - 4 GiB sandboxes
- macOS support is "experimental and lacks futex support".

**gVisor systrap** ([blog, 2023-04-28](https://gvisor.dev/blog/2023/04/28/systrap-release/)):

- On x86-64 it patches `mov sysno,%eax; syscall` into `jmp *%gs:offset`.
- "ARM has no such patching."
- Older getpid figures (Xeon, 2021):

  | Configuration | getpid |
  |---|---|
  | native | 62 ns |
  | runsc-KVM | 830 ns |
  | runsc-ptrace | 6249 ns |

  [Ant Group](https://gvisor.dev/blog/2021/12/02/running-gvisor-in-production-at-scale-in-ant/)

**PRoot** ([proot-me](https://proot-me.github.io/)), for scale:

- ptrace-based path translation.
- A seccomp filter costs about 10 ns per call; a seccomp-to-ptrace round trip
  about 6 µs. [LKML 2020](https://lkml.indiana.edu/2005.3/09385.html)

### 4.4 WSL1: pico processes

- **Pico processes**
  ([Nick Judge, 2016-05-23](https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview)):
  - A pico process is an empty user address space (no ntdll, no PEB) attached to
    a "pico provider" driver (lxss.sys, lxcore.sys). The NT kernel passes it
    every system call and user-mode exception.
  - Kernel changes made for WSL: a better fork; user address space managed in
    single 4 KiB pages instead of 64 KiB; case sensitivity a thread can opt into.
- **System calls**
  ([Stephen Hufnagel, 2016-06-08](https://learn.microsoft.com/en-us/archive/blogs/wsl/wsl-system-calls)):
  - Decoded from `rax` with the Linux ABI.
  - About 235 implemented in June 2016.
  - Pipes were written from scratch because NT's differ.
- **Files**
  ([Sven Groot, 2016-06-15](https://learn.microsoft.com/en-us/archive/blogs/wsl/wsl-file-system-support)):
  - lxcore has a Linux-like VFS with a dentry cache.
  - **VolFs** (the Linux root):
    - Each inode holds a metadata-only NT handle, which an open reopens with the
      requested access.
    - mode, uid, gid, device numbers and timestamps live in NTFS extended
      attributes, chosen "to avoid opening extra handles".
    - Unlink of an open file renames it into a hidden directory first.
  - **DrvFs** (`/mnt/c`) **disables the dentry cache** so Windows' changes are
    always seen. Later it got `$LXUID`/`$LXGID`/`$LXMOD`/`$LXDEV` attributes,
    plus a reparse point on special files, "much faster to determine the kind of
    file … without having to query its extended attributes".
    [file permissions](https://learn.microsoft.com/en-us/windows/wsl/file-permissions)
- **Case sensitivity:** a per-directory NTFS flag, set on directories WSL creates.
  [2018-02-28](https://devblogs.microsoft.com/commandline/per-directory-case-sensitivity-and-wsl/)
- **Why it was slow,** in Sven Groot's words
  ([WSL #873, 2018-09-27](https://api.github.com/repos/microsoft/WSL/issues/comments/425272829)):
  - Linux answers many `stat` calls from its dentry cache; NT has none.
  - Every operation passes through Windows filter drivers (antivirus and others).
  - NT must open a handle before most operations.
  - Emulating Linux path parsing adds requests to the file-system stack.
  - "No single cause."
- **WSL2's gain**
  ([2019-05-06](https://devblogs.microsoft.com/commandline/announcing-wsl-2/)):
  - "up to 20x faster" unpacking a tarball, "around 2-5x faster" for git clone,
    npm install and cmake.
  - Also: full system-call compatibility, and kernel improvements for free.
- **fork:** about 30 µs on Linux, 2–5 ms under WSL1, in one project's measurement
  (WSL version and date not shown).
  [BuildStream #1217](https://gitlab.com/BuildStream/buildstream/-/issues/1217)
  The Noah slides above give 2.06 ms for WSL1's fork with no array.

### 4.5 Darling: macOS programs on Linux (the inverse)

- **System calls**
  ([docs](https://docs.darlinghq.org/internals/basics/system-call-emulation.html)):
  - A modified `libsystem_kernel.dylib` sends BSD calls to Linux ones, with
    errno translation and path prefixing (`vchroot_expand`).
  - Mach traps become RPCs to `darlingserver`.
  - Programs that make raw `syscall`s (some UPX-packed ones) fail.
- **darlingserver**
  ([docs](https://docs.darlinghq.org/internals/darlingserver/index.html)):
  - A userspace "kernel server, much like wineserver" that reuses XNU's own
    source.
  - It replaced a Linux kernel module in 2022. The module was "typically faster"
    but "too unstable"; the switch ended random kernel panics and freezes.
    [Q2 2023 report](https://blog.darlinghq.org/2023/08/21/progress-report-q2-2023)
- **RPC**
  ([docs](https://docs.darlinghq.org/internals/darlingserver/rpc.html)):
  - One Unix datagram socket per thread; descriptors pass with SCM_RIGHTS.
  - For the server to act on a client, it sends a reply or a real-time signal
    whose handler asks what to do; ptrace was rejected for having no
    asynchronous API.
- **Signals**
  ([docs](https://docs.darlinghq.org/internals/darlingserver/interrupts.html)):
  - The protocol is `interrupt_enter` (the server aborts the in-flight call and
    keeps its reply), then `sigprocess`, then `interrupt_exit`.
  - A reserved real-time signal emulates SIGSTOP, so a stopped process can still
    answer the debugger.
  - "Signal handling and kernel-side sleeping" were the trickiest parts.
- **Threads:** XNU's threads run as cooperative microthreads on one worker
  thread, because of "bugs in the multithreaded implementation".
  [docs](https://docs.darlinghq.org/internals/darlingserver/threads-and-friends.html)
- **arm64 on arm64:** "not there yet" (August 2023).

### 4.6 Blink: an x86-64 Linux emulator that runs on macOS

[jart/blink](https://github.com/jart/blink)

- **Size and coverage:** 500+ instructions, 150+ Linux system calls including
  fork and clone; about 220 KB static.
- **JIT:**
  - Copies micro-op functions into a 22 MB buffer, sized to arm64's branch range.
    When the buffer runs low, it drops everything and starts again.
  - Hooks are kept in a lock-free hash table; a mutex would cost more than 33%.
  - Self-modifying code is caught by write-protecting pages and trapping SIGSEGV.
- **Memory:** "linear" by default (host address = guest address + a fixed
  offset). Programs always see 4096-byte pages; on 16 KiB hosts, misaligned
  mappings may get relaxed protections.
- **Speed:** "2x faster than qemu-x86_64 on some benchmarks".
- **Files:** overlays (`BLINK_OVERLAYS`) apply to absolute paths only;
  `--enable-vfs` adds an in-process /proc and devfs.
- **Tests:** passes 350 LTP suites and 108 musl libc-test tests.

### 4.7 iSH: Linux on iOS

[ish-app/ish](https://github.com/ish-app/ish)

- **Execution:** i386 Alpine under emulation. "Asbestos" is threaded code
  (assembly "gadgets" that tail-call each other), not a JIT; the README claims
  3–5x over a switch-based interpreter.
- **fakefs:**
  - Keeps mode, uid, gid, rdev and its own inode numbers in a SQLite database
    beside a directory of real files.
  - Symlinks and device nodes are plain files whose meaning is in the database.
  - Each operation is a database transaction.
  - [fs/fake.c](https://raw.githubusercontent.com/ish-app/ish/master/fs/fake.c)

### 4.8 Kernel personalities: Linuxulator, NetBSD, illumos lx

- **FreeBSD Linuxulator on arm64:**
  - From 2021: auxv, TLS, core dumps; "ongoing work to make Linuxulator on arm64
    on par with amd64".
    [2021 report](https://www.freebsd.org/status/report-2021-04-2021-06/linuxulator/)
  - In 2023 the ABI root (`/compat/ubuntu`) was set once at exec instead of per
    call, because per-call translation mishandled absolute symlinks; fewer than
    70 glibc-2.37 tests fail.
    [2023 report](https://www.freebsd.org/status/report-2023-04-2023-06/linuxulator/)
  - FreeBSD 15.0 (December 2025) has native inotify, and the Linuxulator's
    inotify calls use it.
    [commit list](https://lists.freebsd.org/archives/dev-commits-doc-all/2025-November/004791.html)
  - Performance figures: not found.
- **epoll on kqueue in FreeBSD**
  ([linux_event.c](https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/compat/linux/linux_event.c)):
  - `epoll_create` is a kqueue.
  - Mapping: `EPOLLIN` → `EVFILT_READ`, `EPOLLOUT` → `EVFILT_WRITE`,
    `EPOLLONESHOT` → `EV_DISPATCH`, `EPOLLET` → `EV_CLEAR`, `EPOLLRDHUP` → `EV_EOF`.
    The 64-bit `epoll_data` is kept in `kevent.ext[0]`.
  - A source comment marks `EPOLLPRI`/`EPOLLHUP` as not mapped.
- **NetBSD:**
  - `compat_linux` for aarch64 since 2021-09-23 (NetBSD 10).
  - Its epoll and inotify date from 2023, and its epoll "does not survive a fork".
  - arm64 Linux has only the generic system-call table, so `epoll_create1` and
    `epoll_pwait` only.
  - [history](https://nxr.netbsd.org/history/src/sys/compat/linux/arch/aarch64),
    [commit](https://mail-index.netbsd.org/source-changes-hg/2023/07/28/msg368575.html)
- **illumos lx brand**
  ([Bryan Cantrill, 2014-09-27](https://speakerdeck.com/bcantrill/the-dream-is-alive-running-linux-containers-on-an-illumos-kernel)):
  - The hard parts were "Signals, device pathing, /proc, TTY ioctls, ptrace".
  - Native epoll was added for it.

### 4.9 gVisor's file and memory fixes

- **directfs**
  ([2023-06-27](https://gvisor.dev/blog/2023/06/27/directfs/)):
  - Before, every file operation was an RPC to a separate gofer process. Now the
    gofer only hands over mount-point descriptors, and the Sentry makes
    descriptor-relative `openat`/`fstatat`/`mkdirat` calls itself
    (`O_NOFOLLOW` forced).
  - `stat` more than 2x faster; real workloads 12% faster.
- **Root file system overlay**
  ([2023-05-08](https://gvisor.dev/blog/2023/05/08/rootfs-overlay/)):
  - The container's writable layer is a tmpfs inside the sandbox, its data in
    one host file the sandbox maps.
  - fsstress went from 262.79 s to 3.18 s; a bazel build's overhead halved.
- **netstack** is "optimized for security over performance". Buffer pooling cut
  its allocation and garbage-collection time (20–30% of the total) and raised
  throughput by more than 30%.
  [2022-10-24](https://gvisor.dev/blog/2022/10/24/buffer-pooling/)

### 4.10 Looked for, not found

- **QEMU user mode on macOS:** none. The old `darwin-user` target ran Darwin
  programs and was removed about 2012.
  [qemu-devel](https://lists.gnu.org/archive/html/qemu-devel/2013-07/msg04781.html)
- **LKL (the Linux kernel as a library) on macOS:** only work-in-progress
  patches as of 2020. [LWN](https://lwn.net/Articles/816276)
- **Box64 on macOS:** Linux hosts only.
- **UserLAnd:** its README does not say how it works.

---

## 5. Asahi Linux: Linux on the bare metal

**Why the kernel uses 16 KiB pages.**

- Apple's IOMMU (DART) has a fixed 16 KiB page. On a 4 KiB kernel, Linux's IOVA
  code hits a BUG_ON.
  [Sven Peter, 2021](https://lore.kernel.org/linux-arm-kernel/e0d9af36-fc6c-4470-a87c-61b9161bdf8f@www.fastmail.com/)
- Asahi: a 4K kernel "requires some very hacky patches"; 16K "performs better"
  (no number given). [broken software](https://asahilinux.org/docs/sw/broken-software/)
- macOS also runs 16 KiB, with a layer for 4 KiB processes (used by Rosetta);
  Linux has none. [marcan on LWN](https://lwn.net/Articles/872089/)

**What broke on 16 KiB, and the first version that works**
([broken software](https://asahilinux.org/docs/sw/broken-software/)):

| Package | Fixed in |
|---|---|
| Chromium and Electron | 102 |
| jemalloc | 5.3.1 |
| Emacs | 28.0 |
| Wine | 10.5 |
| box64 | 0.2.8 |
| Rust (Arch Linux ARM) | 1.62.1 |
| Zig | 0.14.0 |
| libunwind | 1.7.0 |
| rr | 5.6.0 |
| WebKitGTK | 2.34.6 |
| QEMU | 7.2.6 / 8.0.5 / 8.1.1 |

- Still broken: hardened_malloc (16K support incomplete), Waydroid,
  qt5-webengine (patched downstream).
- x86-64 software is supported only "via a 4k page size microVM running FEX".

**TSO.**

- Hector Martin's "arm64: Support the TSO memory model" adds a generic
  `PR_SET_MEM_MODEL` `prctl` and, on Apple cores, flips the TSO bit in
  `ACTLR_EL1`, saved and restored on context switch. Shipped downstream to
  "thousands of users" through FEX.
  [2024-04-11](https://lists.infradead.org/pipermail/linux-arm-kernel/2024-April/919152.html)
- Not merged upstream: Will Deacon and Marc Zyngier objected (see
  [2.1](#21-rosetta-for-linux)).
- Sergio López noted that guests under macOS Hypervisor.framework need TSO too.
  [2024-05-06](https://lkml.iu.edu/2405.0/05577.html)
- Whether muvm guests get hardware TSO: not found.

**muvm** ([repo](https://github.com/AsahiLinux/muvm)):

- A libkrun microVM with a 4 KiB-page kernel, so 4 KiB programs (x86 through FEX
  or Box64, registered with binfmt) run on 16 KiB hosts. `muvm-guest` runs a
  server, so several apps share one VM.
- GPU through DRM native context; X11 forwarded; networking through passt.
- Memory is not reserved up front, and unused pages go back to the host.
  `--mem` defaults to 80% of RAM.
- X11 bridging ([Asahi Lina, 2024-12-12](https://asahilinux.org/2024/12/muvm-x11-bridging/)):
  - X11's futex-based fences need truly shared memory. `/dev/shm` is mounted over
    virtiofs with DAX, so atomics and futexes work across host and guest, and a
    watcher thread forwards futex wakes.
  - `libxshmfence`'s memfd use had to be turned off.
  - Apps that wait on the GPU are slower than those that do not.
- Cost: "about 20% depending on the workload". muvm cannot do Wayland, has slow
  I/O and struggles with some input devices.
  [progress report, 2026-11-07](https://asahilinux.org/2026/11/progress-report-7-3/)

**Leaving muvm (2026).** Games now run outside muvm with FEX plus Wine's ARM64EC
(which is "mature and reliable", so FEX translates only the game's own code).
4 KiB processes come from Google's **P3S (Per Process Page Size)** Android
kernel patches. Earlier "ugly hacks inside FEX" for this "have since been
removed". [progress report, 2026-11-07](https://asahilinux.org/2026/11/progress-report-7-3/)

**AAA games** ([Alyssa Rosenzweig, 2024-10-10](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/)):

- The stack: muvm + FEX + Wine + DXVK/vkd3d-proton + Honeykrisp.
- Geometry and tessellation shaders are emulated with compute shaders.

**GPU drivers.**

- Conformant OpenGL 4.6 (February 2024).
  [Asahi](https://asahilinux.org/2024/02/conformant-gl46-on-the-m1/)
- Vulkan 1.4 conformant on the day the spec came out (2024-12-02).
  [Alyssa Rosenzweig](https://alyssarosenzweig.ca/blog/vulkan-14-sur-asahi-linux.html)
- OpenCL 3.0 through rusticl.
- The drivers are upstream in Mesa, and DRM native context is in upstream
  virglrenderer and Mesa 25.2.
  [6.16 report, 2025-08-07](https://asahilinux.org/2025/08/progress-report-6-16/)

**Project state.**

- Hector Martin resigned on 2025-02-13, and seven leads replaced him.
  [Asahi](https://asahilinux.org/2025/02/passing-the-torch/)
- Downstream went from 1232 to 858 patches by February 2026.
  [6.19 report](https://asahilinux.org/2026/02/progress-report-6-19/)
- M3 is generally available without the EXPERT flag; its GPU draws a first
  triangle. M4 Pro/Max and M5 boot to a text console only.
  [7.3 report](https://asahilinux.org/2026/11/progress-report-7-3/)

---

## 6. x86 on arm64: FEX and Box64

### 6.1 FEX-Emu

- **Page size:** "FEX only supports AArch64 host systems running a 4k page-size
  kernel". [Fedora change](https://www.fedoraproject.org/wiki/Changes/FEX)
- **TSO:**
  - Memory-model emulation is "the number one thing that slows down FEX". Its
    software fallback (atomics or LRCPC) "absolutely demolishes performance";
    FEX asks the Asahi kernel for hardware TSO when it can.
    [FEX-2306](https://fex-emu.com/FEX-2306/)
  - Its defaults: TSO emulation on, vector TSO off, `memcpy`/`memset` TSO off,
    "half-barrier" atomics for unaligned accesses (backpatched), and PE "volatile
    metadata" used to drop TSO where the compiler said it is safe.
    [Config.json.in](https://raw.githubusercontent.com/FEX-Emu/FEX/main/FEXCore/Source/Interface/Config/Config.json.in)
  - FEX 2207 kept TSO off until a program's second thread started; FEX 2510
    dropped that and added user-marked ranges that skip TSO.
    [FEX-2510](https://fex-emu.com/FEX-2510/)
- **Self-modifying code:** `SMCChecks` defaults to `mtrack` (page-tracking
  invalidation); `full` is the other mode.
- **Disk cache:** FEX 2609 (2026-09-07) adds `FEX_DISKCACHE=1`, a FOZ database
  in `$HOME/.cache/fex-emu/`, with faster full SMC detection.
  [FEX-2609](https://fex-emu.com/FEX-2609/)
  Current options: `DiskCacheMaxFileSize` (1 GiB), `DiskCachePruneStaleEntries`,
  `DiskCacheAnonCaching`.
- **Thunks:** calls into OpenGL, Vulkan and others go to the host's arm64
  library through generated glue (`thunkgen`, Clang-based). Vulkan `pNext` chains
  and pointers crossing guest and host are the hard parts.
  [FEX-2208](https://fex-emu.com/FEX-2208/)
- **TPIDRRO_EL0:** FEX and arm64 Wine want Linux to store the CPU number there,
  as Windows on Arm and macOS do; an Igalia kernel patch (August 2026) has an
  unknown merge status.
  [Phoronix, 2026-11-06](https://phoronix.com/news/FEX-2611-Released)

### 6.2 Box64

- **Approach:** a dynarec, "5-10x faster than the interpreter alone", and
  **wrapped native libraries** (libc, libm, SDL, OpenGL, GTK, Vulkan) for
  "surprising performance".
  [README](https://raw.githubusercontent.com/ptitSeb/box64/main/README.md)
- **Memory model:** `BOX64_DYNAREC_STRONGMEM` defaults to 0 (no TSO emulation);
  levels 1–3 add barriers, and 4 mimics QEMU's TSO. It turns on automatically
  for Mono and the JVM.
  [USAGE.md](https://raw.githubusercontent.com/ptitSeb/box64/main/docs/USAGE.md)
- **Page size:**
  - Since v0.2.8, 16K or 4K is chosen at run time.
  - The v0.4.6 preview (2026-08-07) fakes a 4K system on 16K kernels: the ELF
    loader maps as if on 4K, and memory is adjusted when Wine loads a PE. Steam,
    Wine and Proton run on Asahi without a microVM, but "No 100% of things are
    supported in 16k configuration".
  - Changing protections on ranges not aligned to 16K is the core problem.
  - [box86.org](https://box86.org/2026/08/preview-of-next-box64-improved-non-4k-pagesize-handling/)
- **DynaCache** (v0.3.8, 2025-10-13) keeps generated code on disk per binary in
  `~/.cache/box64`: Factorio launches in 29 s instead of 39 s.
  [box86.org](https://box86.org/2025/10/new-box64-v0-3-8-released/)
  Since v0.4.4 (2026-08-02) it is on by default, zlib-compressed and capped at
  2 GB. [box86.org](https://box86.org/2026/08/new-box64-v0-4-4-release/)
- **Benchmarks** ([box86.org, 2022-03-24](https://box86.org/2022/03/box86-box64-vs-qemu-vs-fex-vs-rosetta2/)):

  | Benchmark | QEMU | FEX | Box64 | native |
  |---|---|---|---|---|
  | 7-Zip, Raspberry Pi 400 | 931 | 1486 | 3084 | 5787 |

  On an M1, Box64 on Asahi reached about 57% of native and Rosetta 2 about 71%.
  Fedora (2024): "Performance is similar between box64 and FEX". A 2025–26
  head-to-head: not found.

---

## 7. 4 KiB programs on a 16 KiB system

| Who | How | Status |
|---|---|---|
| macOS | a 4K-process layer in the kernel, used by Rosetta | private |
| Google P3S | per-process 4 KiB mode on a 16 KiB Linux kernel: tracks each process's granule and sets `TCR` on context switch | Android patches; used by Asahi experiments; not shipped by Asahi yet ([LPC 2026](https://lpc.events/event/20/contributions/2630/)) |
| Arm proposal | each `mm` gets a 4K/16K/64K ABI fixed at `execve`, inherited by children, with an adapter at the system-call boundary that enforces alignment | LSF/MM/BPF 2026 topic ([LKML](https://lkml.iu.edu/2602.2/01906.html)) |
| Box64 | fakes 4K in its ELF loader and memory calls | preview, "not 100%" |
| Blink | relaxes protections on misaligned mappings | shipped |
| muvm | a 4 KiB-page kernel in a VM | shipped; about 20% cost |
| HVF | `HV_IPA_GRANULE_4KB` stage 2 (macOS 26); a guest picks its own stage-1 granule | public API |
| QEMU user mode | 4K guests on 16K hosts still fail (`mremap` returns `EFAULT`) | [issue 3410](https://gitlab.com/qemu-project/qemu/-/work_items/3410) |

---

## 8. Cross-cutting numbers

**System-call cost, one call, as published** (different machines; for order of
magnitude only):

| Path | Cost | Source |
|---|---|---|
| native Linux getpid (Xeon) | 62 ns | Ant/gVisor 2021 |
| in-process rewrite (ASC-Hook, Neoverse-N1) | 33.5 ns added | ASC-Hook |
| LFI sandbox call | 22 ns | LFI poster |
| VM exit + entry (Noah, Intel) | ~600 cycles + host call ~2,000 cycles | Noah VEE slides |
| gVisor KVM platform | 830 ns | Ant 2021 |
| signal-based interception | 987 ns | ASC-Hook |
| ptrace | 2,060–6,249 ns | ASC-Hook; Ant 2021 |
| virtio-fs `unlinkat` through a VM (libkrun) | 103–161 µs | sinrega 2026 |

**fork:**

| System | fork |
|---|---|
| native Linux | ~30 µs (BuildStream) |
| WSL1 | 2.06 ms (Noah slides); 2–5 ms (BuildStream) |
| Carrick | 5.7 ms; fork + exec 7.8 ms |
| NoahW | 106 ms |

**Start-up:**

| System | Start-up |
|---|---|
| Carrick | 90 ms first boot |
| Apple `container` | "a few hundred milliseconds" (Apple); 0.92 s (third party) |
| OrbStack | seconds |
| Docker Resource Saver | 3–10 s to wake |

**File I/O through a VM:** OrbStack 75–95% of native; bind mounts about 3x native
on Lima and Docker Desktop (VZ) for `npm install`, and about 1.25x on OrbStack
(4.22 s against 3.4 s).

---

## 9. What fwe can take from these

Each idea names its source and says whether it keeps the program in-process
(fwe's native backend) or needs fwe's VM backend. fwe treats the VM as a last
resort, never as a speed fix, so the VM ideas are for programs that already
need it.

### Keeps the program in-process

1. **Byte-exact, case-sensitive names on the default case-insensitive APFS**
   (elfuse, [4.2](#42-the-newer-hypervisorframework-projects-on-apple-silicon)).
   - fwe's known limitation: one file for names differing only in case
     (architecture.md, Known limitations).
   - elfuse's scheme stores every name that is not lowercase ASCII under a
     reversible escape (`.ef=` + hex), decided by the name alone. Each create,
     rename and unlink therefore stays one host call, and `getdents64` decodes
     on the way out.
   - For fwe it would apply under `--root` on a case-folding volume. The cost is
     longer host names (`PATH_MAX` 1024), and files made by macOS tools must
     still be found by their literal spelling.
2. **Directory cache with host-driven coherence** (WSL1, gVisor directfs,
   [4.4](#44-wsl1-pico-processes), [4.9](#49-gvisors-file-and-memory-fixes)).
   - WSL1's DrvFs threw away its dentry cache for coherence and paid on every
     call. Sven Groot names the missing cache as the first reason `stat` was
     slow.
   - gVisor made `stat` more than 2x faster with descriptor-relative calls from
     held directory descriptors.
   - This supports ROADMAP M6 PR 3 as planned: kqueue-checked directory caches,
     plus `openat`/`fstatat` relative to held directory descriptors rather than
     re-walking full paths.
3. **One cheap marker for a file's kind** (WSL1 reparse points on special files).
   - When fwe keeps Linux metadata in extended attributes (`org.fwe.mode`,
     `org.fwe.owner`), let the common case (a regular file with no fwe
     attributes) be decided without reading any attribute. For example, a
     marker only on files that have one, as WSL1 did "without having to query
     its extended attributes".
4. **Container writable layers in memory** (gVisor rootfs overlay: fsstress
   262.79 s → 3.18 s).
   - Keep an overlay's upper layer for short-lived containers in a host file
     fwe maps, not as individual APFS files, when the container does not need it
     to persist.
   - In-process, and a large win for image builds and test containers.
   - It must be measured against fwe's overlay before adopting.
5. **Rewrite pitfalls to test for** (ASC-Hook, [4.3](#43-in-process-system-call-rewriting-fwes-native-approach)).
   - ASC-Hook rewrites the `x8` set and the `svc` as a pair, and lists the
     hazards: a jump target between the two, a site with no visible `x8` set,
     and a jump straight to the second instruction.
   - It records a site that faulted to a file, so the next run avoids it. That
     is the same idea as fwe's kept preparation, and a check that fwe's kept
     records also capture sites learned at run time.
   - Its 33.5 ns per call on a Neoverse-N1 is a published bar for fwe's gate
     (the team's notes record 316 ns for a whole getpid under fwe after the
     gate work of PR #82, which includes fwe's kernel work, so compare like
     with like).
6. **Code-cache housekeeping** (FEX disk cache: 1 GiB per file, prune stale
   entries; Box64 DynaCache: 2 GB cap, zlib).
   - fwe keeps prepared images and translations by file identity. Both
     translators cap and prune their caches; fwe's docs do not describe a size
     limit or pruning.
   - Box64's measured gain from its cache (Factorio 39 s → 29 s) is a model for
     the macro benchmark such a change brings.
7. **4 KiB pages on 16 KiB hosts** (Box64 v0.4.6, Blink, the Arm per-mm
   proposal, P3S, [7](#7-4-kib-programs-on-a-16-kib-system)).
   - ROADMAP M6 PR 5 plans the Box64-style approach.
   - Box64 reports that protection changes on ranges not aligned to 16 KiB are
     the core problem, and that Wine's PE loader needed its own adjustment,
     which matters for M6 PR 6.
   - Box64 still says "not 100%"; Blink relaxes protections on misaligned parts
     where Linux would not.
   - The Arm proposal's design fits fwe: a per-process page-size ABI fixed at
     `execve`, inherited by children, enforced at the system-call boundary.
8. **Signals into a busy thread** (Noah, Darling, illumos lx).
   - Noah delivered a signal only at the thread's next VM exit, so a spinning
     thread never saw it.
   - Darling and lx call signals arriving mid-call their hardest part. Darling's
     explicit `interrupt_enter`/`interrupt_exit` protocol keeps an interrupted
     call's reply until the handler returns.
   - A test of a signal to a thread in a tight loop with no system calls, in
     both backends, guards against Noah's flaw.
9. **epoll on kqueue edge cases** (FreeBSD `linux_event.c`, NetBSD).
   - FreeBSD keeps `epoll_data` in `kevent.ext[0]` and leaves `EPOLLPRI` and
     `EPOLLHUP` unmapped.
   - NetBSD's epoll does not survive fork; fwe rebuilds its epoll kqueues in a
     fork child.
   - Useful as a checklist against fwe's mapping.
10. **x86-64 programs under fwe, in-process, later** (Box64, FEX).
    - Box64 is an arm64 Linux program that already runs on 16 KiB kernels, needs
      no TSO by default (`STRONGMEM=0`), and wraps native libraries.
    - Run on fwe, its generated code would go through fwe's JIT translation path,
      so it measures that path's cost on a heavy JIT.
    - FEX needs 4 KiB pages and benefits from hardware TSO. A user process
      cannot set `ACTLR_EL1.TSOEN` on macOS (see the VM list), so FEX would pay
      for software TSO in-process.
    - Not planned for 1.0; noted as a use for M6 PR 5's 4 KiB pages.
11. **GPU: forward at the highest level that is safe** (libkrun, muvm).
    - Venus through virglrenderer and MoltenVK reached 74–80% of native Metal for
      llama.cpp. API remoting (forwarding ggml calls) reached about 95–100%.
    - muvm needed DAX-mapped `/dev/shm` and a futex-forwarding thread to share
      X11 fences across the VM; fwe in-process has real shared memory and host
      futexes, so `MIT-SHM` and `xshmfence` should work without that machinery.
    - For M7 PR 2, Venus in-process as planned. Library thunking at the Vulkan
      or ggml level (FEX's thunks, Box64's wrapped libraries) is the faster, less
      general option, to be judged by the same benchmarks.
12. **Network namespaces with a userspace TCP/IP stack** (Docker Desktop's move
    from vpnkit to gVisor's netstack, OrbStack's custom stack, libkrun's TSI and
    passt).
    - For M8: per-namespace addresses can be served in-process by a userspace
      stack (gVisor netstack in Go, or a Rust stack), with host sockets made the
      way TSI and vpnkit make them, so VPNs and firewalls see ordinary macOS
      traffic.
    - TSI's limits (no listening on UDP; Steam broke) are a warning on
      impersonating sockets rather than routing packets.
13. **Memory footprint** (ArcBox measurement).
    - macOS counts a page in a process's footprint until it is freed with
      `MADV_FREE_REUSABLE`; `MADV_DONTNEED` and `MADV_FREE` do not drop it.
    - Where Linux's `MADV_FREE` or `MADV_DONTNEED` lets the kernel take anonymous
      pages, fwe could pass `MADV_FREE_REUSABLE` to the host (keeping Linux's
      zero-fill rule for `MADV_DONTNEED`), so Activity Monitor and memory
      pressure see the memory as free.
    - Small, in-process; check with `phys_footprint` before and after.
14. **What not to copy.** Each of these is a VM tool's answer to a problem fwe
    avoids by being in-process:
    - Docker's synchronized file shares (a second copy of the files).
    - OrbStack's and Apple's shared directories.
    - Restarting VMs to return memory (Apple `container`).

### Needs fwe's VM backend (only for programs that already need it)

1. **Stage-1 permissions, one stage-2 mapping** (hl, elfuse, Carrick, against
   Noah).
   - All three newer projects map guest memory once and do `mprotect`/`munmap`
     in the guest's own page tables plus a TLB flush.
   - Noah's stage-2 approach made each `mmap` and `mprotect` an HVF call and fork
     a full VM rebuild (NoahW fork 106–458 ms).
   - This agrees with the team's earlier notes (hvf-prior-art), and is the
     published consensus.
2. **fork by spawning, not by forking a live VM** (elfuse, hl; Noah destroyed
   the VM before fork; Carrick forks with the VM alive).
   - Carrick's costs (fork 5.7 ms, process teardown 175 ms "as the kernel
     reclaims the large VM mapping") give a bar to measure against.
   - Its practice of calling `fork()` with a VM alive is what fwe's rules forbid.
3. **4 KiB stage 2** (`hv_vm_config_set_ipa_granule(HV_IPA_GRANULE_4KB)`, macOS
   26).
   - Lets the VM backend map guest memory at 4 KiB granularity where the host
     allows.
   - Useful if fwe's VM backend ever needs 4 KiB stage-2 mappings (for example,
     file pages at 4 KiB offsets) rather than doing it all in stage 1.
4. **TSO for x86 translators in the VM** (Apple's Linux patch).
   - A guest at EL1 can set `ACTLR_EL1.TSOEN` from macOS 14.4 on some versions.
     fwe's VM backend owns EL1, so it could give a translator (FEX) hardware TSO
     per process, which the native backend cannot.
   - Must be verified on real hardware under fwe's VM safety rules; Apple says
     it is "not exposed for writing on Virtual Machines on all versions of
     MacOS".
5. **`hvc` immediate** (Carrick).
   - HVF can consume `hvc #0` as an SMCCC call when `x0` matches a function ID.
     Carrick moved to `hvc #2`; fwe's VM backend should check its own vector.
6. **Returning VM memory** (ArcBox).
   - Under HVF, guest-dirtied memory is returned only by `hv_vm_unmap` →
     `madvise(MADV_FREE_REUSABLE)` → `hv_vm_map`.
   - This conflicts with "one stage-2 mapping, made once" and with fwe's caution
     about stage-2 churn. If ever needed, do it rarely, in large ranges, on a
     machine whose crash costs nothing.

### Not for fwe, and why

- **Rosetta for Linux.** It refuses to run outside a Virtualization.framework
  VM with its share attached, and no Hypervisor.framework equivalent exists.
  fwe cannot use it in either backend.
- **A VM per container** (Apple `container`) or **one Linux kernel VM**
  (OrbStack, Docker, Lima). These trade fwe's in-process model for a real
  kernel. Their published file numbers (75–95% of native at best, about 3x
  native for bind mounts) are what fwe's direct APFS access is measured against.
