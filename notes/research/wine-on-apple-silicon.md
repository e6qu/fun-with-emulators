# Wine and its relatives on Apple Silicon and on ARM

A survey, made on 2026-11-20, of how Windows programs run on Apple Silicon
Macs and on ARM64 Linux through Wine and the projects around it
(CrossOver, Apple's Game Porting Toolkit, Whisky, Proton, Hangover, FEX),
how they synchronise threads, how they draw, what they measured, and what
fwe can take from them. Each fact has its source beside it. "Not found"
means the search turned up nothing reliable; nothing here is guessed.
Where a statement is a reading of source code or of a package rather than
a quote, it says so, with the date of the reading. Several primary pages
(codeweavers.com, phoronix.com, winehq.org news) refused automated fetches;
for those the fact is taken from a second source that quotes them, named
beside it.

Terms used throughout:

- **PE** and **ELF**: Windows' and Linux's executable formats. Wine's
  Windows-facing DLLs are PE files; the part of each that talks to the
  host (Wine calls it the *Unix side*, `ntdll.so`, `winemac.so` and so on)
  is an ELF (Linux) or Mach-O (macOS) library.
- **wineserver**: a separate process every Wine process talks to over a
  Unix socket. It keeps what processes share: handles, synchronisation
  objects, the registry, window state.
- **TEB**: the Windows *thread environment block*, one per thread
  (`NtCurrentTeb()`), holding the thread's last error, its TLS slots and
  much else. On x86-64 Windows code reaches it through `gs`, on ARM64
  through register `x18`.
- **wow64** ("Windows 32-bit on Windows 64-bit"): running 32-bit x86 code
  inside a 64-bit process. Wine's *new wow64* (from Wine 9) does it the
  Windows way: 32-bit PE code calls into 64-bit Unix code through thunks,
  so no 32-bit host process or library is needed.
- **ARM64EC** ("emulation compatible"): a Windows ABI for ARM64 code that
  shares a process with x86-64 code run by an emulator; **ARM64X** is one
  binary holding both ARM64 and ARM64EC code
  ([Microsoft](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)).
- **DXVK**, **VKD3D-Proton**, **vkd3d**: Direct3D 8–11, Direct3D 12 (two
  implementations) on Vulkan. **MoltenVK** and **KosmicKrisp**: Vulkan on
  Apple's Metal. **D3DMetal** and **DXMT**: Direct3D straight on Metal.
- **Venus**: Mesa's Vulkan driver that forwards Vulkan calls over
  virtio-gpu to a host, where virglrenderer replays them on a real Vulkan
  driver.

## 1. The short version

1. **Native ARM64 Wine on macOS became possible in 2026.** Apple added, in
   macOS 26.4/26.5 and Xcode 26.4, a per-thread "custom x18 ABI", spawning
   a process with 4 KiB pages, a resizable and remappable `__PAGEZERO`,
   and per-thread TSO, all behind restricted entitlements
   ([wine-devel, Brendan Shanks, 2026-08-07](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/)).
   CodeWeavers shipped a CrossOver Preview with ARM64 Wine and FEX on
   2026-07-31; the upstream Wine patches are announced but not merged
   (Section 2).
2. **x18 has four known answers on macOS**: link against an old SDK so the
   kernel keeps preserving `x18`; switch threads into the custom x18 ABI
   (`os_set_custom_x18_abi_enabled`); keep the TEB elsewhere for Wine's own
   code; or rewrite every `x18` use, as fwe does (Section 2.8).
3. **Rosetta 2 is ending**: macOS 27 is the last release with full
   Rosetta; macOS 28 keeps only a subset for older games
   ([Apple](https://developer.apple.com/news/?id=w5ngl9k2)). This is what
   pushes CrossOver to ARM64 Wine with FEX for x86 code.
4. **Wine's ARM64 support is complete upstream**: ARM64EC and ARM64X since
   Wine 10.0 (2025-01-21), the new wow64 fully supported and NTSync used in
   Wine 11.0 (2026-01-13), x86 emulators (FEX, Box64) plugged in as Windows
   DLLs (Section 3).
5. **Proton 11 (2026-07-07) prefers NTSync, then fsync, then the server**;
   esync is obsolete there. It ships ARM64 builds with FEX for the Steam
   Frame (Section 4).
6. **Alpine's Wine 11.0, the one fwe runs, opens `/dev/ntsync`** when it
   exists (its `wineserver` contains the path; read 2026-11-20). fwe has
   `futex_waitv` and shared futexes already; `/dev/ntsync` it does not
   have (Section 5).
7. **Synchronisation through wineserver is very slow on macOS**: msync's
   author measured 10 million contended waits at over 170 s server-side
   against 3.8 s with Mach semaphores and `__ulock_wait2`
   ([wine-msync](https://github.com/marzent/wine-msync)). NTSync gained
   21 % to 678 % over upstream Wine's server-side waits in games
   ([GamingOnLinux, 2024-01-24](https://gamingonlinux.com/2024/01/proposed-windows-nt-sync-driver-brings-big-wine-proton-performance-improvements/)).
8. **Upstream DXVK 3 cannot run on upstream MoltenVK**: DXVK 3 requires
   Vulkan 1.4 and `VK_EXT_transform_feedback`, which MoltenVK does not
   offer; MoltenVK also has no geometry shaders. KosmicKrisp (LunarG, Mesa,
   macOS 26+) is Vulkan 1.4 conformant but still lacked geometry shaders
   and transform feedback in October 2026 (Section 6).
9. **DXMT (Direct3D 11 on Metal) beat DXVK on fill rate but not on draw
   calls** in the one published comparison (117 against 41 fps on a title
   screen, 100 against 44–50 on fill rate, 115 against 133–139 on draw
   calls, in a VM), and its host side is a small library that a VM, or
   fwe, can serve (Section 6.5).

## 2. Wine on macOS Apple Silicon

### 2.1 Upstream Wine on macOS

- Upstream Wine supports macOS 10.15 and later; Wine 11.19 and 11.21
  removed pre-10.15 workarounds and macOS i386 code ("winemac: Remove
  pre-macOS 10.15 workarounds", "ntdll: Remove macOS i386-specific code",
  "preloader: Remove i386 macOS support") (release notes read from
  [wine-11.19 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.19/ANNOUNCE.md)
  and [wine-11.21 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.21/ANNOUNCE.md)).
- Wine 10.0: "Syscall emulation for applications doing direct NT syscalls
  is supported on macOS Sonoma and later"
  ([wine-10.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.0/ANNOUNCE.md)).
  How it is done is not stated there.
- Wine 11.0: "On macOS, the `%gs` register is swapped in the syscall
  dispatcher. This avoids conflicts between the Windows TEB and the macOS
  thread descriptor"
  ([wine-11.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md)).
  This is x86-64 Wine; macOS on x86-64 keeps its own thread pointer in
  `gs`, which Windows code also wants.
- ARM64 macOS pieces are arriving upstream: the ARM64 signal code has
  `__APPLE__` branches for reading registers from the macOS signal context
  (read from
  [dlls/ntdll/unix/signal_arm64.c](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/signal_arm64.c),
  2026-11-20), and Wine 11.16 has "ntdll: Populate the CPU name and vendor
  on ARM64 macOS"
  ([wine-11.16 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.16/ANNOUNCE.md)).
  The x18 custom ABI, 4 KiB-page spawning and PAGEZERO changes of Section
  2.9 were **not found** in upstream Wine by GitHub code search on
  2026-11-20 (`4k_page_size_np`, `x86_64_compat`, `custom-x18`: zero hits
  in `wine-mirror/wine`). A third-party tracker found no evidence of a
  merge as of Wine 11.18
  ([macgameport issue](https://github.com/macgameport/cities-skylines-2-macos/issues/16)).
- Brendan Shanks (CodeWeavers) wrote on 2026-08-07 that "macOS now has
  all the pieces needed to run ARM64 Wine natively" and that he would send
  merge requests upstream soon
  ([wine-devel](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/)).

### 2.2 How x86 Windows code runs on Apple Silicon today

- **Rosetta 2 runs an x86-64 build of Wine.** A 2026 CrossOver review:
  "Stable CrossOver 26 still relies on Rosetta 2 on Apple Silicon, but
  CrossOver 27 will use native ARM64 Wine components and FEX"
  ([machow2](https://machow2.com/crossover-mac-review/)).
  Whisky and the GPTK evaluation environment packaged D3DMetal in x86-64
  Wine, as every D3DMetal packaging found does (Section 2.4).
- **32-bit Windows programs** run through Wine's new wow64 inside the
  64-bit process: Wine 9.0's new wow64 "finally allows 32-bit applications
  to run on recent macOS versions" that dropped 32-bit Unix processes
  ([wine-9.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-9.0/ANNOUNCE.md));
  Wine 11.0 made new wow64 fully supported, 16-bit included, with
  `WINEARCH=win32` prefixes deprecated
  ([wine-11.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md)).
- **Rosetta 2 and x86 segments**: "Rosetta 2 doesn't support x86
  segmentation (beyond having one segment that covers the entirety of the
  32-bit address space)"; a Win16 program's `i386_set_ldt()` makes Rosetta
  print "LDT ... not supported" and spin
  ([Wine bug 59042](https://list.winehq.org/archives/list/wine-bugs@list.winehq.org/thread/UX45Z5ALWA2O6K5REJHNINUAFIZKY7PP)).
- **AVX**: Rosetta on macOS 15 translates AVX and AVX2, but CPUID does not
  report them; `ROSETTA_ADVERTISE_AVX=1` makes it do so
  ([Go runtime source](https://go.googlesource.com/go/+/master/src/internal/cpu/cpu_x86_darwin.go),
  [RPCS3 forum](https://forums.rpcs3.net/showthread.php?tid=208033)). The
  first macOS 15.x release with it is disputed (15.0 beta or 15.4) in the
  sources found.
- **Rosetta's end**: "macOS 27: Final release to support Rosetta —
  Intel-only apps will no longer run on Mac computers with Apple silicon
  after this update"; from macOS 28 a limited subset stays for older games
  that rely on Intel-based frameworks
  ([Apple developer news](https://developer.apple.com/news/?id=w5ngl9k2),
  [MacRumors 2025-06-10](https://www.macrumors.com/2025/06/10/apple-to-phase-out-rosetta-2/),
  [MacRumors 2026-06-10](https://www.macrumors.com/2026/06/10/macos-golden-gate-last-to-support-intel-apps/)).
  macOS 26.4 already warns when a Rosetta app starts
  ([MacRumors 2026-02-16](https://www.macrumors.com/2026/02/16/macos-tahoe-26-4-rosetta-2-warnings)).
  Apple's words for the subset: "we will keep a subset of Rosetta
  functionality aimed at supporting older unmaintained gaming titles, that
  rely on Intel-based frameworks" (quoted by both MacRumors articles).
  Whether Windows games under CrossOver, or Rosetta inside Linux VMs, fall
  in that subset was **not found** in Apple's words.

### 2.3 CrossOver (CodeWeavers)

CrossOver is CodeWeavers' commercial Wine; CodeWeavers employs many of
Wine's developers.

| Release | Date | What it brought | Source |
|---|---|---|---|
| CrossOver 23.7–24 | 2023–2024 | "MSync" advanced setting: Mach-semaphore synchronisation; "some applications run with better performance ... some are broken by MSync" | [CodeWeavers support](https://support.codeweavers.com/advanced-settings-in-crossover-235) |
| CrossOver 25 | 2025-03-11 | Wine 10.0; DXMT (D3D11 on Metal) as a toggle, "especially good performance benefits for lower spec Macs"; D3DMetal 2.1, MoltenVK 1.2.10, vkd3d 1.14 | [CodeWeavers blog](https://codeweavers.com/blog/mjohnson/2025/3/11/experience-next-level-gaming-on-mac-with-crossover-25) (fetch refused; quoted by [It's FOSS](https://itsfoss.com/news/crossover-25-release/)) |
| CrossOver 25.1 | 2025-08 | fixes | [OMG! Ubuntu](https://www.omgubuntu.co.uk/2025/08/crossover-25-1-0-released-office-gaming-fixes/amp) |
| CrossOver 26 | 2026-02-10 | Wine 11.0; D3DMetal 3.0; DXMT 0.72; vkd3d 1.18; NTSync on Linux; DLSS through MetalFX with D3DMetal or DXMT | [Phoronix](https://phoronix.com/news/crossover-26), [AlternativeTo](https://alternativeto.net/news/2026/2/crossover-26-released-with-wine-11-ntsync-on-linux-and-support-for-many-new-games-on-mac) |
| CrossOver Preview (ARM64) | 2026-07-31 | ARM64 Wine with FEX for x86 code (ARM64EC); universal builds that fall back to Intel Wine and Rosetta on older macOS; "not expected to be useful for anything beyond testing" | [CodeWeavers blog title](https://www.codeweavers.com/blog/mjohnson/2026/7/31/crossover-preview-the-right-to-bear-arm64-on-mac) (fetch refused; quoted in search summary), [wine-devel](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/) |
| CrossOver 27 | planned early 2027 | ARM64 Wine; drops Intel Macs (Intel users keep CrossOver 26) | [TUAW 2026-08-02](https://www.tuaw.com/2026/08/02/crossover-goes-native-on-apple-silicon/) |

What the ARM64 Preview lacks, as reported: no D3DMetal, so no Direct3D 12;
many launchers fail; old bottles cannot be converted
([TUAW](https://www.tuaw.com/2026/08/02/crossover-goes-native-on-apple-silicon/));
its Direct3D 11 path is DXMT
([Blendlogic, 2026-08](https://blendlogic.com/posts/crossover-arm64-fex-mac-gaming.html)).
The minimum macOS for its ARM64 path was **not found** from CodeWeavers;
one third-party integration requires macOS 27 for "arm64 Wine with FEX"
([OfflineDAoC-macOS PR](https://github.com/trozzelle/OfflineDAoC-macOS/pull/10)),
and the Mach9 engine (below) requires 26.5.

### 2.4 Apple's Game Porting Toolkit and D3DMetal

- The toolkit (GPTK) is a porting aid. Its *evaluation environment for
  Windows games* runs an unmodified Windows executable on Apple Silicon to
  estimate performance and check shader conversion; it also holds the
  Metal shader converter (DXIL to Metal), metal-cpp and remote Windows
  tools. The current version is **Game Porting Toolkit 4**
  ([Apple](https://developer.apple.com/games/game-porting-toolkit/)).
- GPTK 3 came with Metal 4 at WWDC 2025 (sparse buffers and textures,
  performance insights, MetalFX)
  ([AppleInsider 2025-06-09](https://appleinsider.com/articles/25/06/09/metal-4-game-porting-toolkit-3-boost-frame-rate-ray-tracing-performance));
  GPTK 4 at WWDC 2026 adds Metal 4 to the evaluation environment and
  "agent skills" for coding agents
  ([WWDC26 session 357](https://developer.apple.com/videos/play/wwdc2026/357/),
  [What's new in Games](https://developer.apple.com/wwdc26/guides/games/)).
- **D3DMetal** is the part that translates Direct3D 11 and 12 to Metal;
  it does not do Direct3D 9
  ([carette.xyz, 2025-12-20](https://www.carette.xyz/posts/deep_dive_into_crossover/)).
  Apple's page does not say which CPU architecture it is built for. Every
  packaging found ships it inside x86-64 Wine under Rosetta: MetalSharp's
  x86-64 build "runs under Rosetta 2 ... plus Apple's D3DMetal", its ARM64
  build has none
  ([MetalSharp-Wine 6.0](https://github.com/metalsharp/MetalSharp-Wine/releases/tag/v6.0));
  CrossOver's ARM64 Preview has none (above). An ARM64 or ARM64EC
  D3DMetal was **not found**.
- Measured: GTA V went from about 106 to about 176 fps (+66 %) and Red Dead
  Redemption 2 from about 60 to about 75 fps between GPTK 3 and the GPTK 4
  beta, on an M4 Pro MacBook Pro, one reviewer's tests
  ([Macworld, 2026-07-16](https://www.macworld.com/article/3189951/apples-latest-game-porting-toolkit-beta-changed-how-i-think-about-mac-gaming.html)).

### 2.5 Whisky and its end

Whisky was a free macOS front end to Wine with GPTK's D3DMetal. Its
developer, Isaac Marovitz, stopped development in April 2025, saying
Whisky competed with CrossOver, whose sales fund Wine, while giving little
back to Wine; only fixes for macOS breakage were promised, and he
recommended CrossOver
([MacRumors 2025-04-23](https://www.macrumors.com/2025/04/23/whisky-ends-mac-gaming-tool-crossover/),
[heise](https://heise.de/-10355657)). Community forks continue (for example
a KosmicKrisp DXVK backend:
[niltonperimneto/Whisky PR 5](https://github.com/niltonperimneto/Whisky/pull/5)).

### 2.6 Other native ARM64 Wine efforts on macOS (2026)

| Project | What it is | x18 | Source |
|---|---|---|---|
| wine-macos-native | patches over a macOS ARM64 port branch of Wine 11.10 with FEX-2609; ARM64 programs (`cmd`, `notepad`) and x86-64 through FEX run; 32-bit x86 not yet; tested on macOS 26.6.2, M2 | TEB kept in pthread TSD slot 700, read through `TPIDRRO_EL0` | [GitHub](https://github.com/Irz-Z/wine-macos-native) |
| MetalSharp-Wine | Wine 11.20 native ARM64 with FEX; ARM64, x86-64 and 32-bit x86 (32-bit needs macOS 26.4+); D3D9–12 and OpenGL 4.6 on Metal ("Mullion" default; DXVK or VKD3D-Proton optional) | not stated on its page | [GitHub](https://github.com/metalsharp/MetalSharp-Wine) |
| Mach9 engine (gw2-on-mac) | Wine fork; "Opt threads into the custom x18 ABI on arm64 macOS ... (macOS 26.4+)"; loader needs `com.apple.security.custom-x18-abi-toggle`; needs `posix_spawnattr_set_4k_page_size_np`, so macOS 26.5 | custom x18 ABI | [jdrly/wine PR 51](https://github.com/jdrly/wine/pull/51), [gw2-on-mac issue 337](https://github.com/jdrly/gw2-on-mac/issues/337) |
| FX Steam Launcher (steamac) | Valve's ARM64 SteamOS (the Steam Frame image) in a libkrun VM on Hypervisor.framework; Proton 11 ARM64 + FEX inside; graphics by Venus to MoltenVK or KosmicKrisp on the host, or DXMT through a host executor | the guest is Linux, which keeps `x18` | [xenospectrum 2026-11-03](https://xenospectrum.com/en/fx-steam-launcher-steamos-mac-silicon-graphics-pipeline/), [wiki](https://github.com/fxgl/steamac/wiki) |

### 2.7 Does anyone run ARM64 Windows code natively on macOS?

Yes, since mid-2026, and only with the macOS 26.4/26.5 changes: the
CrossOver ARM64 Preview, wine-macos-native, MetalSharp and Mach9 above run
ARM64 PE code natively and x86 code through FEX as ARM64EC. Before 2026
no product did; released CrossOver and Whisky ran x86-64 Wine under
Rosetta. fwe already runs ARM64 Windows console programs through Linux
Wine in its VM backend (its `x18` the guest's own there)
([ROADMAP.md](../../ROADMAP.md)).

### 2.8 The x18 problem

Windows' ARM64 ABI: `x18` is a reserved platform register; "in user mode,
points to TEB"
([Microsoft](https://learn.microsoft.com/cpp/build/arm64-windows-abi-conventions)).
ARM64EC code also reads the TEB from `x18`
([Microsoft](https://learn.microsoft.com/en-us/cpp/build/arm64ec-windows-abi-conventions)).
Apple's ARM64 ABI reserves `x18` for the platform, and "on recent macOS
versions it can be cleared at any time"
([wine-devel](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/));
fwe documents it as cleared on every exception return, preemption included
([docs/linux-on-macos.md](../../docs/linux-on-macos.md)). Linux leaves
`x18` to user code, so Wine on ARM64 Linux simply keeps the TEB there;
Wine's own Unix-side ELF code relies on it too: the ARM64 syscall
dispatcher begins `ldr x10, [x18, #0x378]` (the TEB's syscall frame) and
saves and restores `x18` itself (read from
[signal_arm64.c](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/signal_arm64.c),
2026-11-20).

| Answer | How | Limits | Who | Source |
|---|---|---|---|---|
| Old SDK link | macOS 11 and 12 did not clear `x18`, and current macOS keeps that behaviour for binaries built against those SDKs: link with `-Wl,-platform_version,macos,11.0,11.0` | a compatibility behaviour, "a workaround ... until Wine is using the x18 custom ABI"; wine-macos-native puts the cut at SDK 12.0 | Wine's macOS work in 2026 | [wine-devel](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/), [wine-macos-native](https://github.com/Irz-Z/wine-macos-native) |
| Custom x18 ABI | a per-thread mode in which `x18` is saved and restored like any register: `void os_set_custom_x18_abi_enabled(bool)`, `bool os_custom_x18_abi_enabled(void)`, declared in `<os/arch/arm64.h>`; switched on before Windows code, off before calling system frameworks | macOS 26.4 (fwe's probe, Mach9) or 26.5 (wine-devel); an entitlement, `com.apple.security.custom-x18-abi-toggle` per the Mach9 fork (not found in Apple's documentation); fwe found each switch costs two host calls and saw the mode dropped by the host, and its test notes the mode "could not cover" preemption on CI VMs | Mach9, Wine patches in progress | [crates/native/src/lib.rs](../../crates/native/src/lib.rs) (`lookup_x18_abi`), [crates/fwe/tests/guests.rs](../../crates/fwe/tests/guests.rs) (`asm_x18_survives_preemption`), [docs/architecture.md](../../docs/architecture.md), [jdrly/wine PR 51](https://github.com/jdrly/wine/pull/51) |
| TEB elsewhere for Wine's own code | Wine's `NtCurrentTeb()` reads a TSD slot through `TPIDRRO_EL0` | PE code compiled for Windows still reads `x18`; needs one of the other answers for that | wine-macos-native | [GitHub](https://github.com/Irz-Z/wine-macos-native) |
| Rewrite each use | every instruction naming `x18` becomes a branch to a stub that uses a TSD slot instead | a stub per use; code made at run time is translated | fwe | [docs/linux-on-macos.md "x18: a stub per use"](../../docs/linux-on-macos.md) |

The macOS 26.1 SDK on the development Mac has no `os/arch/arm64.h`
(checked 2026-11-20), so the header itself was not read.

### 2.9 Other macOS additions for Wine (26.4, 26.5, Xcode 26.4)

All from the
[wine-devel post of 2026-08-07](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/)
unless marked:

- **4 KiB pages**: macOS 26.5 adds `posix_spawnattr_set_4k_page_size_np()`
  to spawn a process with 4 KiB pages. The symbol is absent from 26.4.1's
  libSystem
  ([gw2-on-mac issue 337](https://github.com/jdrly/gw2-on-mac/issues/337)).
- **PAGEZERO**: arm64 macOS enforces a `__PAGEZERO` of at least 4 GiB,
  which stops Wine mapping `USER_SHARED_DATA` at `0x7ffe0000`. Xcode 26.4's
  new linker flag `-Wl,-x86_64_layout_emulation` lets the PAGEZERO size be
  changed and the region remapped; Wine's plan is to grow it to about
  `0x170000000` to reserve the whole low range for itself. The flag's only
  documentation found is this post.
- **TSO**: macOS 26.5 lets a thread switch to the x86 (TSO) memory model
  with `thread_set_x86_64_compat()`; new threads do not inherit it.
- **Entitlements**: these features need restricted entitlements,
  `com.apple.developer.cross-architecture-support` (paid developer
  accounts) or `...-unmanaged` (free accounts), in a provisioning profile
  inside a `.app` bundle with the loader. The post does not say which
  feature needs which entitlement.

## 3. Wine's ARM64 and ARM64EC support

### 3.1 By release

| Release | ARM64 and emulation | Source |
|---|---|---|
| Wine 9.0 (2024-01) | PE/Unix separation complete, "possible to run existing Windows binaries on ARM64"; initial ARM64EC build with an experimental LLVM toolchain; new wow64 experimental (configure option); the 32-bit x86 emulation interface implemented, no emulator shipped | [ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-9.0/ANNOUNCE.md) |
| Wine 10.0 (2025-01-21) | "The ARM64EC architecture is fully supported, with feature parity with the ARM64 support"; "Hybrid ARM64X modules are fully supported"; the 64-bit x86 emulation interface implemented, the emulator found through `HKLM\Software\Microsoft\Wow64\amd64`, "The FEX emulator implements this interface when built as ARM64EC"; "ARM64 support requires the system page size to be 4K, since that is what the Windows ABI specifies" | [ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.0/ANNOUNCE.md) |
| Wine 11.0 (2026-01-13) | new wow64 fully supported (16-bit too); "On ARM64, there is support for simulating a 4K page size on top of larger host pages. This works for simple applications", a 4K-page kernel strongly recommended; GitLab CI builds ARM64; NTSync used when present | [ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md) |
| Wine 11.x (2026) | ARM64EC build in MinGW mode (11.15); ".net applications run as ARM64EC on ARM64" (11.15); Mono with ARM64 support (11.16); `CONTEXT_ARM64_X18` fix (11.16); relay debugging for ARM64EC (11.20) | ANNOUNCE files of [11.15](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.15/ANNOUNCE.md), [11.16](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.16/ANNOUNCE.md), [11.20](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.20/ANNOUNCE.md) |

### 3.2 How x86 code joins an ARM64 Wine process

- **x86-64 programs**: Wine on ARM64 loads the program as x86-64 code in an
  ARM64EC process; the emulator is a Windows DLL (FEX's
  `libarm64ecfex.dll`) named under `HKLM\Software\Microsoft\Wow64\amd64`.
  Wine's own DLLs are ARM64EC (or ARM64X), so a call from emulated code
  into Wine leaves the emulator at the function boundary and runs natively
  ([wine-10.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.0/ANNOUNCE.md),
  [Hangover README](https://github.com/AndreRH/hangover)).
- **32-bit x86 programs**: through new wow64 with an emulator DLL for
  i386: FEX's `libwow64fex.dll` or Box64's `WowBox64.dll`
  ([Hangover README](https://github.com/AndreRH/hangover),
  [box64 v0.3.6](https://newreleases.io/project/github/ptitSeb/box64/release/v0.3.6)).
- **ARM64EC in short**: ARM64 code that uses the x64 `CONTEXT` layout, so
  it may not use `x13`, `x14`, `x23`, `x24`, `x28` or `v16`–`v31`; calls
  go through *call checkers* that decide at run time whether the target is
  ARM64EC or x64 and route x64 targets through signature-specific *exit
  thunks* into the emulator; x64 callers enter through *entry thunks*.
  Code a JIT makes at run time counts as x64 unless allocated with
  `MEM_EXTENDED_PARAMETER_EC_CODE`
  ([Microsoft, 2025-11-06](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)).

### 3.3 Hangover, FEX and Box64

- **Hangover** pairs Wine with FEX or Box64 for x86 Windows programs on
  ARM64 Linux. 11.0 (2026-01-13) follows Wine 11.0, drops QEMU, and is
  "down to around ten patches atop upstream Wine"
  ([Phoronix](https://phoronix.com/news/hangover-11.0-released)). It
  "break[s] out of emulation at the win32 syscall or wine unix call level"
  ([README](https://github.com/AndreRH/hangover)).
- **FEX** (x86 on ARM64 Linux): FEX-2508 (2025-08) added "hardware TSO"
  use, letting Wine's wow64/ARM64EC libraries use Apple Silicon's TSO mode
  ([linuxcompatible](https://www.linuxcompatible.org/story/fex2508-released));
  FEX-2509 added Mono-specific speedups for ARM64EC/wow64
  ([fex-emu.com](https://fex-emu.com/FEX-2509/)). Valve has funded FEX
  since its first commit (2018-11-28)
  ([GamingOnLinux 2025-12-03](https://www.gamingonlinux.com/2025/12/valve-have-been-funding-fex-to-get-x86-games-on-arm-linux/)).
- **TSO on Linux**: Asahi's `PR_SET_MEM_MODEL` prctl (2024) met objections
  ([Will Deacon](https://lore.kernel.org/lkml/20240411132853.GA26481@willie-the-truck/));
  mainline `include/uapi/linux/prctl.h` has no memory-model option (read
  through the GitHub API, 2026-11-20).

## 4. Proton (Valve)

### 4.1 What it is and what it changes

Proton is Valve's Wine for Steam on Linux: a patched Wine plus DXVK,
VKD3D-Proton, vkd3d, dxvk-nvapi, Wine Mono and Steam integration, rebased on
each Wine stable release
([Proton releases](https://github.com/ValveSoftware/Proton/releases)).

| Release | Date | Base and components | Source |
|---|---|---|---|
| Proton 10.0-1 (b–f) | 2025-04/05 | Wine 10.0; DXVK 2.6.1; VKD3D-Proton 2.14.1+; vkd3d-shader 1.15+ | [proton-10.0-1b](https://github.com/ValveSoftware/Proton/releases/tag/proton-10.0-1b) |
| Proton 11.0-1-beta1 | 2026-04-16 | Wine 11.0; "Added FEX-2604 for ARM64EC builds" | [beta1](https://github.com/ValveSoftware/Proton/releases/tag/proton-11.0-1-beta1) |
| Proton 11.0-1 | 2026-07-07 | Wine 11.0; FEX-2605; DXVK 2.7.1-467; vkd3d 1.19; VKD3D-Proton proton-20260410 | [11.0-1](https://github.com/ValveSoftware/Proton/releases/tag/proton-11.0-1) |
| Proton 11.0-2 | 2026-08-21 | FEX-2607; vkd3d 2.0; DXVK 2.7.1-498 | [11.0-2](https://github.com/ValveSoftware/Proton/releases/tag/proton-11.0-2) |

ARM64 builds: `configure.sh --target-arch=arm64` on an ARM64 machine; "It's
not possible to use the resulting builds in x86 Steam running via FEX"
([Proton README, proton_11.0](https://github.com/ValveSoftware/Proton/blob/proton_11.0/README.md)).

### 4.2 Synchronisation in Proton 11

Read from source on 2026-11-20:
- `server/inproc_sync.c` (proton_11.0): open `/dev/ntsync` unless
  `PROTON_NO_NTSYNC=1`; if it opens, fsync is turned off ("ntsync: up and
  running."); otherwise fsync if enabled; otherwise "wineserver: using
  server-side synchronization"
  ([source](https://github.com/ValveSoftware/wine/blob/proton_11.0/server/inproc_sync.c)).
- The `proton` launcher sets `WINEFSYNC=1` unless `PROTON_NO_FSYNC`
  ([source](https://github.com/ValveSoftware/Proton/blob/proton_11.0/proton)).
- esync: "Obsoleted in Proton 11.0"
  ([README](https://github.com/ValveSoftware/Proton/blob/proton_11.0/README.md)).
- Before Proton 11, NTSync was in GE-Proton from 10-9 (2025-07) with
  `PROTON_USE_NTSYNC=1`
  ([GamingOnLinux](https://www.gamingonlinux.com/2025/07/ge-proton-10-9-released-with-ntsync-and-fsr4-upgrade-support)).

### 4.3 DXVK and VKD3D-Proton

- **DXVK 3.x requires Vulkan 1.4** and `VK_EXT_depth_clip_enable`,
  `VK_KHR_maintenance5`, `VK_KHR_maintenance6`, `VK_KHR_load_store_op_none`,
  `VK_EXT_robustness2`, `VK_EXT_transform_feedback`, 256 bytes of push
  constants, descriptor indexing, 8/16/64-bit integers and
  `scalarBlockLayout`; the legacy 1.10.3 needed Vulkan 1.1
  ([DXVK wiki](https://github.com/doitsujin/dxvk/wiki/Driver-support)).
  DXVK 3.0 moved shader compilation to `dxbc-spirv` with an on-disk cache
  and uses `VK_EXT_descriptor_heap` where offered
  ([v3.0 notes](https://github.com/doitsujin/dxvk/releases/tag/v3.0));
  latest v3.1.1, 2026-09-15
  ([releases](https://github.com/doitsujin/dxvk/releases)).
  A fork reports DXVK 3 also refuses an adapter without `fillModeNonSolid`
  ([winecx-gptk PR 15](https://github.com/dappermint/winecx-gptk/pull/15)).
- **VKD3D-Proton requires** Vulkan 1.3, descriptor indexing with at least
  1,000,000 update-after-bind descriptors per type (bar uniform buffers),
  `samplerMirrorClampToEdge`, `shaderDrawParameters`, `VK_EXT_robustness2`,
  `VK_KHR_push_descriptor`; recommends `VK_EXT_mutable_descriptor_type` and
  `VK_EXT_descriptor_buffer`
  ([README](https://github.com/HansKristian-Work/vkd3d-proton)).

### 4.4 Steam Linux Runtime and pressure-vessel

Steam runs Proton inside a container of its own runtime ("sniper", Steam
Linux Runtime 3.0, app 1628350), set up by pressure-vessel with a bundled
bubblewrap, which needs unprivileged user namespaces
([steam-runtime-tools docs](https://gitlab.steamos.cloud/steamrt/steam-runtime-tools/-/blob/b2a2a20e8dc45ceb335780af6e186085a2943c2c/docs/slr-for-game-developers.md)).
A June 2026 report shows SteamRT 4 (`4.0.20260507`) with a
`pressure-vessel-arm64` package
([steam-runtime issue 830](https://github.com/ValveSoftware/steam-runtime/issues/830)).
A 2026 Steam beta runs the 64-bit Linux client itself in a container
([It's FOSS](https://itsfoss.com/news/steam-linux-64-bit-client/)).

### 4.5 Valve and ARM

- **Steam Frame**: a standalone VR headset on a Snapdragon SoC running
  SteamOS, announced 2025-11-12 with the Steam Machine and Steam
  Controller ([Game Informer](https://www.gameinformer.com/2025/11/12/valve-announces-console-like-steam-machine-steam-frame-vr-headset-and-new-steam)),
  launched 2026-09-14 at $1,059
  ([GeekWire](https://geekwire.com/2026/monday-morning-surprise-valve-software-suddenly-launches-its-wireless-vr-headset-steam-frame-for-1059/)).
  Windows x86 games run through Proton and FEX, Linux x86 through FEX,
  Android apps through "Lepton"
  ([PCWorld](https://www.pcworld.com/article/3266419/valve-escaped-windows-now-steam-is-breaking-free-from-the-pc-itself.html)).
  The chip model (Snapdragon 8 Gen 3) is stated only by secondary sources.
- FEX's code cache was enabled in Proton Experimental for ARM in September
  2026, to improve 1 % lows on later runs
  ([GamingOnLinux](https://www.gamingonlinux.com/2026/09/fex-code-cache-enabled-for-proton-experimental-arm-to-improve-frame-timings/)).

## 5. Synchronisation primitives

### 5.1 Why Wine needs them

Windows programs wait on events, mutexes and semaphores, often several at
once ("wait for any" or "wait for all", `WaitForMultipleObjects`), with
semantics Linux's futex does not have: an atomic wait-all that takes
nothing until it can take everything, `PulseEvent` (wake waiters, leave the
event unset), mutexes owned by a thread and *abandoned* when it dies
([LWN 2024-02-16](https://lwn.net/Articles/961884/)). Upstream Wine without
help keeps these objects in wineserver, so every wait and signal is a round
trip over the socket to another process (same source).

### 5.2 The mechanisms

| | Where | Mechanics | Needs from the kernel | Source |
|---|---|---|---|---|
| server-side | upstream Wine (default) | wineserver holds the objects; clients send requests and wait for replies on their socket | Unix sockets, `SCM_RIGHTS` | [LWN](https://lwn.net/Articles/961884/) |
| esync | wine-staging, Proton ≤ 10 (`WINEESYNC=1`) | one eventfd per object (`EFD_SEMAPHORE` for semaphores), all `O_NONBLOCK`; wait-any is `poll` on the eventfds; wait-all polls then grabs in a loop and undoes on failure (not truly atomic); semaphore and mutex state in POSIX shared memory `/wine-esync`; server objects (processes, threads, queues) get an eventfd the server signals; `PulseEvent` cannot be exact; one fd per object, so `RLIMIT_NOFILE` of 1,048,576 is recommended | `eventfd`, `poll`, `shm_open`, `SCM_RIGHTS`, a high fd limit | [README.esync](https://raw.githubusercontent.com/zfigura/wine/esync/README.esync) |
| fsync | Proton (`WINEFSYNC=1`) | objects are 16-byte records (count, max or signaled or owner tid, refcount, last pid) in a shared-memory file `/wine-<ino>-fsync` the server creates; waits use `futex_waitv` (syscall 449) with `FUTEX_32` and no private flag, up to `MAXIMUM_WAIT_OBJECTS + 1` futexes; wakes are `FUTEX_WAKE`; a process exits if `futex_waitv` gives `ENOSYS` or `EPERM` | `futex_waitv` on shared memory, `futex`, `shm_open` | read from [Proton's fsync.c](https://github.com/ValveSoftware/wine/blob/bleeding-edge/dlls/ntdll/unix/fsync.c), 2026-11-20; [Collabora](https://collabora.com/news-and-blog/blog/2023/02/17/the-futex-waitv-syscall-gaming-on-linux) |
| NTSync | Linux 6.14+, Wine 11.0, Proton 11 | a char device `/dev/ntsync`; each open is one instance; objects (semaphore, mutex, event) are fds made by ioctls on it; waits are ioctls that take an array of object fds | `/dev/ntsync` | [kernel docs](https://docs.kernel.org/userspace-api/ntsync.html) |
| msync | CrossOver's "MSync" setting (23.7+); the open patch set wine-msync, whose mechanics these are (whether CrossOver's is the same code was not found) | a client-side pool of Mach semaphores (creation is expensive); a waiter registers its objects with wineserver over a Mach port, which signals the semaphore; single-object waits use `__ulock_wait2` in user space when available; shared memory code from fsync; `WINEMSYNC=1` | Mach semaphores, Mach ports, `__ulock_wait2` (macOS) | [wine-msync](https://github.com/marzent/wine-msync) |

**NTSync in detail** (from the
[kernel documentation](https://docs.kernel.org/userspace-api/ntsync.html)
and [`include/uapi/linux/ntsync.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ntsync.h),
read 2026-11-20):
- Device `/dev/ntsync`, a misc device with mode `0666`
  ([driver source](https://github.com/torvalds/linux/blob/master/drivers/misc/ntsync.c)).
- Create ioctls on the device fd return a new object fd:
  `NTSYNC_IOC_CREATE_SEM` (`count`, `max`; `EINVAL` if count > max),
  `NTSYNC_IOC_CREATE_MUTEX` (`owner`, `count`; `EINVAL` if only one is
  zero), `NTSYNC_IOC_CREATE_EVENT` (`manual`, `signaled`). Closing the last
  fd deletes the object.
- Object ioctls: `SEM_RELEASE` (returns the previous count, `EOVERFLOW`
  past max), `MUTEX_UNLOCK` (`EPERM` if not owner), `MUTEX_KILL` (mark
  abandoned; later acquirers get `EOWNERDEAD` but still acquire),
  `EVENT_SET`, `EVENT_RESET`, `EVENT_PULSE`, and `SEM_READ`, `MUTEX_READ`,
  `EVENT_READ`.
- `NTSYNC_IOC_WAIT_ANY` and `NTSYNC_IOC_WAIT_ALL` take
  `struct ntsync_wait_args { u64 timeout; u64 objs; u32 count, index,
  flags, owner, alert, pad; }`: at most `NTSYNC_MAX_WAIT_COUNT` = 64
  objects; the timeout is absolute nanoseconds on `CLOCK_MONOTONIC` (or
  `CLOCK_REALTIME` with `NTSYNC_WAIT_REALTIME`), `U64_MAX` for none; an
  optional `alert` event ends the wait with `index == count`; `EINTR` on a
  signal; wait-all takes every object atomically or none.
- Every operation on an object is atomic and totally ordered with respect
  to others on that object.
- **How Wine uses it** (read from upstream source 2026-11-20): wineserver
  opens `/dev/ntsync` and creates the objects
  ([server/inproc_sync.c](https://github.com/wine-mirror/wine/blob/master/server/inproc_sync.c));
  each client receives the device fd at start-up
  (`inproc_device_fd = wine_server_receive_fd(...)` in
  [server.c](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/server.c))
  and an object's fd the first time it uses a handle, then caches it and
  calls the ioctls itself
  ([sync.c](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/sync.c)).
  Objects therefore cross processes as fds sent with `SCM_RIGHTS`. Without
  the device, Wine falls back to server-side waits.
- A kernel selftest exists:
  [tools/testing/selftests/drivers/ntsync/ntsync.c](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/drivers/ntsync).

**Alpine's Wine 11.0 uses NTSync when present**: the `wineserver` of
Alpine 3.24's `wine-11.0-r0` (aarch64, the package fwe's Wine test fetches,
SHA-256 `b9a2ae11...`) contains the string `/dev/ntsync` and the
`inproc_sync` code, and its `ntdll.so` the client side (`strings`, read
2026-11-20). It has no esync or fsync, which are not in upstream Wine.

### 5.3 Measured performance

| Measurement | Numbers | Conditions | Source |
|---|---|---|---|
| NTSync against upstream Wine (server-side) | Anger Foot 69→99 fps (+43 %), Call of Juarez 99.8→224.1 (+125 %), Dirt 3 110.6→860.7 (+678 %), Forza Horizon 5 108→160 (+48 %), Lara Croft: Temple of Osiris 141→326 (+131 %), Metro 2033 164.4→199.2 (+21 %), Resident Evil 2 26→77 (+196 %), The Crew 26→51 (+96 %), Tiny Tina's Wonderlands 130→360 (+177 %), Total War Saga: Troy 109→146 (+34 %) | Figura's RFC table, several users, hardware not given; baseline server-side, not fsync | [GamingOnLinux 2024-01-24](https://gamingonlinux.com/2024/01/proposed-windows-nt-sync-driver-brings-big-wine-proton-performance-improvements/) |
| NTSync against esync/fsync | "similar" speed, but correct wait-all and `PulseEvent` | forum reports of the LPC 2023 talk; no measurement found | [GamingOnLinux comments](https://gamingonlinux.com/2024/01/proposed-windows-nt-sync-driver-brings-big-wine-proton-performance-improvements/page=2) |
| fsync (futex_waitv) against esync | spin-lock calls down over 80 % in some programs; mixed per game (ACO equal; Ori, BioShock favour esync; DOOM Eternal, Witcher 3 favour fsync) | Collabora | [Collabora 2023-02-17](https://collabora.com/news-and-blog/blog/2023/02/17/the-futex-waitv-syscall-gaming-on-linux) |
| msync on macOS | 10M contended waits, 2 threads: msync+ulock 3.79 s, msync 5.89 s, esync 7.42 s, server-side > 170 s; "zigzag" 2 s: 401,605 / 270,545 / 222,675 / 60,309 iterations; FFXIV indoors CPU-bound: 219 / 170 / 145 / 93 fps | M2 Max, CrossOver 23-based Wine | [wine-msync](https://github.com/marzent/wine-msync) |

### 5.4 What a Linux-ABI layer must provide for each

| Mechanism | Linux interfaces used | fwe today (read 2026-11-20) |
|---|---|---|
| server-side | Unix sockets, `SCM_RIGHTS`, shared memory files | present; this is what Wine uses on fwe now |
| esync | `eventfd` (`EFD_SEMAPHORE`, `O_NONBLOCK`), `poll`/`epoll`, `shm_open` (`/dev/shm`), `SCM_RIGHTS` of eventfds, thousands of fds | `eventfd` emulated as a pipe plus a mapped counter file, passed across processes in a "bundle" ([specialfd.rs](../../crates/kernel/src/specialfd.rs), [scm.rs](../../crates/kernel/src/scm.rs)); each eventfd costs several host objects, which esync multiplies by object count |
| fsync | `futex_waitv` on shared (non-private) 32-bit futexes in a `shm_open` file, `FUTEX_WAKE` | `futex_waitv` (up to 128) present; shared futexes through a table every fwe process maps, sleeping on `__ulock_wait2` with `UL_COMPARE_AND_WAIT_SHARED` ([futex.rs](../../crates/kernel/src/futex.rs), [sharedfutex.rs](../../crates/kernel/src/sharedfutex.rs)) |
| NTSync | `/dev/ntsync` and its 14 ioctls, object fds passed with `SCM_RIGHTS`, `EOWNERDEAD`, absolute timeouts on two clocks, `EINTR` | absent (no match for `ntsync` in `crates/`) |

## 6. Graphics

### 6.1 The paths from Direct3D to an Apple GPU

| Path | Direct3D | Through | Status on Apple Silicon | Source |
|---|---|---|---|---|
| D3DMetal | 11, 12 | Metal | x86-64 Wine under Rosetta only (Section 2.4) | [MetalSharp 6.0](https://github.com/metalsharp/MetalSharp-Wine/releases/tag/v6.0) |
| DXMT | 10, 11 | Metal | in CrossOver 25+ (and its ARM64 Preview); no stream output | [CrossOver 25](https://itsfoss.com/news/crossover-25-release/), [xenospectrum](https://xenospectrum.com/en/fx-steam-launcher-steamos-mac-silicon-graphics-pipeline/) |
| DXVK on MoltenVK | 9–11 | Vulkan → Metal | upstream DXVK 3 needs transform feedback MoltenVK lacks; CrossOver ships DXVK with its own MoltenVK build (MoltenVK 1.2.10 in CrossOver 25; its DXVK version not found) | Sections 4.3, 6.2 |
| VKD3D-Proton / vkd3d on MoltenVK | 12 | Vulkan → Metal | FX launcher reports D3D12 feature level 11_0, SM 6.0 on MoltenVK, typically 12_0 on KosmicKrisp | [xenospectrum](https://xenospectrum.com/en/fx-steam-launcher-steamos-mac-silicon-graphics-pipeline/) |
| Wine's wined3d | 1–11 | OpenGL (or Vulkan, not yet default) | Wine's built-in path; "The Vulkan renderer is not yet at parity with the GL renderer" | [wine-11.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md) |
| Venus | any of the Vulkan paths above, in a Linux VM | virtio-gpu → virglrenderer → host Vulkan driver | libkrun/krunkit; FX launcher | Section 6.6 |

### 6.2 MoltenVK

- 1.4.0 (2025-08-20) added Vulkan 1.4; 1.4.1 (2025-11-30) a new descriptor
  implementation; 1.4.2 (2026-07-24) minimum macOS 12, native sampler
  min/max filtering
  ([releases](https://github.com/KhronosGroup/MoltenVK/releases)).
- What DXVK needs that it lacks (read from MoltenVK `main`, 2026-11-20):
  `MVKExtensions.def` lists `EXT_robustness2`, `EXT_depth_clip_enable`,
  `KHR_maintenance5`, `KHR_maintenance6`, `KHR_load_store_op_none`, but no
  `EXT_transform_feedback`; `MVKDevice.mm` never sets `geometryShader`
  ([MVKExtensions.def](https://github.com/KhronosGroup/MoltenVK/blob/main/MoltenVK/MoltenVK/Layers/MVKExtensions.def),
  [MVKDevice.mm](https://github.com/KhronosGroup/MoltenVK/blob/main/MoltenVK/MoltenVK/GPUObjects/MVKDevice.mm)).
  Its documented limits also include no pipeline-statistics queries
  ([user guide](https://github.com/KhronosGroup/MoltenVK/blob/main/Docs/MoltenVK_Runtime_UserGuide.md)).
  Metal has no transform-feedback API
  ([MoltenVK issue 1588](https://github.com/KhronosGroup/MoltenVK/issues/1588)),
  and Apple's GPUs have no geometry-shader hardware
  ([Asahi](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/)), so
  both must be emulated, as Asahi's Linux driver does with compute shaders.
- UTM's MoltenVK fork adds geometry shaders, robustness2 and
  `VK_EXT_depth_clip_enable` (PR 2712); tessellation together with a
  geometry shader fails with `VK_ERROR_FEATURE_NOT_PRESENT`
  ([steamac wiki](https://github.com/fxgl/steamac/wiki)).
- Native Vulkan (MoltenVK) against native Metal for llama.cpp: 75–77 %
  ([Red Hat 2025-06-05](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers)).

### 6.3 KosmicKrisp (LunarG, Mesa)

- A Mesa Vulkan driver on Metal, built from a blank slate in about ten
  months, with Mesa's NIR and its own NIR-to-MSL compiler; sponsored by
  Google; Vulkan 1.3 conformant in September 2025
  ([LunarG XDC 2025](https://www.lunarg.com/lunarg-at-xdc-2025-kosmickrisp-overview/)),
  Vulkan 1.4 conformant by 2026-09-25
  ([Khronos](https://www.khronos.org/news/permalink/kosmickrisp-achieves-vulkan-1.4-conformance-on-apple-silicon)).
- Requires macOS 26+, Apple M1–M5 and A18 Pro; tessellation, robustness2
  and multi-draw added; GFXBench Aztec Ruins on an M3 Pro from 3,702 /
  8,309 (June 2026) to 11,672 / 27,747, "slightly ahead of MoltenVK";
  3DMark Wild Life in the Android Emulator within a few percent of MoltenVK
  ([LunarG XDC 2026, 2026-09-28](https://www.lunarg.com/lunarg-at-xdc-2026-kosmickrisp-update/)).
- Still missing in October 2026: geometry shaders (an open Mesa merge
  request), `fillModeNonSolid`, `VK_EXT_transform_feedback`
  ([ScarletNX issue 1106](https://github.com/scarletnx/ScarletNX/issues/1106));
  the XDC 2026 slides list geometry shaders among future work (search
  summary of [the slides](https://www.lunarg.com/wp-content/uploads/2026/09/XDC-2026-KosmicKrisp-LunarG.pdf)).
  Forks patch these to run DXVK 3.1.1 D3D9 and D3D11 devices
  ([winecx-gptk PR 15](https://github.com/dappermint/winecx-gptk/pull/15));
  another found DXVK on KosmicKrisp drawing a black window
  ([Madeira PR 353](https://github.com/willfaust/Madeira/pull/353)).

### 6.4 D3DMetal

See Section 2.4: Apple's, closed, Direct3D 11 and 12 to Metal, found only
in x86-64 Wine under Rosetta. Not usable for ARM64 Windows code or in a
Linux process.

### 6.5 DXMT

- "A Metal-based translation layer for Direct3D 11 and 10 which allows
  running 3D applications on macOS using Wine", LGPL-2.1, with build files
  for win32, win64 and ARM64EC
  ([GitHub](https://github.com/3Shain/dxmt)).
- Its PE DLLs (`d3d11`, `dxgi`, `d3d10core`, `winemetal`) call a Unix-side
  `winemetal.so`, which calls Metal. The FX launcher carries those calls
  from the Linux guest over a virtio-gpu context (capset 30) to
  `libwmtr_host.dylib` in the VM process on the Mac; the protocol passes
  raw host addresses and "is not a VM security boundary"
  ([steamac wiki](https://github.com/fxgl/steamac/wiki)).
- Measured in that VM (M1 Max, macOS 27, 6 vCPUs, 8 GB): Death's Door title
  screen 117 fps (DXMT, Proton 10) against 41 fps (DXVK, Proton 11);
  d3d11bench fill rate 100 against 44–50 fps; d3d11bench draw calls 115
  against 133–139 fps (DXMT slower)
  ([xenospectrum 2026-11-03](https://xenospectrum.com/en/fx-steam-launcher-steamos-mac-silicon-graphics-pipeline/)).

### 6.6 Venus and virtio-gpu in libkrun and krunkit

- libkrun gives its VM a virtio-gpu device; in the guest, Mesa's Venus
  forwards Vulkan calls through shared memory; on the host, virglrenderer
  replays them on MoltenVK; krunkit is libkrun's GPU-enabled VM runner on
  macOS
  ([Red Hat 2025-06-05](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers),
  [libkrun](https://github.com/containers/libkrun)). Lima marks it
  experimental and needs a patched guest Mesa
  ([Lima docs](https://lima-vm.io/docs/config/vmtype/krunkit/)).
- Measured: llama.cpp with Vulkan in a krunkit container at 74–80 % of
  native Metal, "on par" with native llama.cpp on Vulkan; M4 Pro, macOS
  15.5, krunkit 0.1.4
  ([Red Hat](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers)).
  Compute with coarse calls hides the forwarding cost; no graphics
  frame-rate comparison of Venus against native was found.
- The FX launcher chooses the host Vulkan driver per VM boot with
  `VKR_VULKAN_DRIVER` (virglrenderer loads it at run time): Stellar Blade
  Demo on an M1 Max about 18 fps on MoltenVK, about 29 on KosmicKrisp; its
  first KosmicKrisp run spent about 28 minutes compiling shaders; an
  on-disk Metal cache cut one pipeline from 102 ms to 0.95 ms
  ([steamac wiki](https://github.com/fxgl/steamac/wiki)).
- Alpine 3.24 aarch64 ships the Venus guest driver as
  `mesa-vulkan-virtio` 26.1.6
  ([Alpine packages](https://pkgs.alpinelinux.org/packages?name=mesa-vulkan-*&branch=v3.24&arch=aarch64)).

### 6.7 For contrast: Asahi Linux

On Apple hardware running Linux, Asahi runs x86 games in a microVM (muvm)
with a 4 KiB-page kernel because x86 software expects 4 KiB pages and
Apple's are 16 KiB; its Vulkan driver (Honeykrisp) emulates geometry
shaders and tessellation with compute shaders, and implements robustness2
by redirecting out-of-bounds loads to a 64 GB zeroed region
([Asahi 2024-10-10](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/)).

## 7. Performance numbers in one place

| What | Result | Date | Source |
|---|---|---|---|
| NTSync vs server-side, 10 games | +21 % to +678 % | 2024-01 | [GamingOnLinux](https://gamingonlinux.com/2024/01/proposed-windows-nt-sync-driver-brings-big-wine-proton-performance-improvements/) |
| msync vs esync vs server-side on macOS | 3.79 s / 7.42 s / > 170 s for 10M contended waits; FFXIV 219 / 145 / 93 fps | undated (CX23-based) | [wine-msync](https://github.com/marzent/wine-msync) |
| FEX (ARM64 CrossOver) vs Rosetta (Intel CrossOver) | Dota 2 59.1 vs 30.4 fps (1 % lows 29.0 vs 8.7), runs at different temperatures; FFXIV benchmark 12,624 vs 11,966 (within noise); M5 MacBook Air, macOS 27.0 | 2026-08 | [Blendlogic](https://blendlogic.com/posts/crossover-arm64-fex-mac-gaming.html) |
| Rosetta CrossOver vs native, Cyberpunk 2077 | 19.6 vs 20.6 fps, 2.2× the CPU, 18.4 W vs 15.8 W | 2026-08 | same |
| GPTK 3 → GPTK 4 beta | GTA V 106 → 176 fps; RDR2 60 → 75 fps; M4 Pro | 2026-07 | [Macworld](https://www.macworld.com/article/3189951/apples-latest-game-porting-toolkit-beta-changed-how-i-think-about-mac-gaming.html) |
| DXMT vs DXVK (Venus, MoltenVK) in a VM | 117 vs 41 fps; fill 100 vs 44–50; draw calls 115 vs 133–139 | 2026-11 | [xenospectrum](https://xenospectrum.com/en/fx-steam-launcher-steamos-mac-silicon-graphics-pipeline/) |
| KosmicKrisp vs MoltenVK | Aztec Ruins slightly ahead; Wild Life within a few percent; Stellar Blade 29 vs 18 fps (in a VM) | 2026-09/11 | [LunarG](https://www.lunarg.com/lunarg-at-xdc-2026-kosmickrisp-update/), [steamac wiki](https://github.com/fxgl/steamac/wiki) |
| Venus compute vs native Metal | 74–80 % (native Vulkan 75–77 %) | 2025-06 | [Red Hat](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers) |
| Wine's address search on macOS | 40–170 ms per `VirtualAlloc2` over a 4 GB–1 TB range, Wine probing every 64 KB from the bottom through macOS's mappings | 2026-10-27 | [FH2 port issue 10](https://github.com/fladnaG86/FH2-Port-AppleSilicon/issues/10) |
| FEX overhead | "10 to 20 %" on certain code, attributed to Valve by a secondary source; Factorio's native ARM64 build about 11 % faster than x86-64 under FEX | 2026 | [Korben](https://korben.info/en/fex-x86-emulator-funded-by-valve.html), [Mixed](https://mixed-news.com/en/?p=32018) |

Not found: any measurement of a Windows ARM64 program under Wine on macOS
against the same program built for macOS; any measurement of the custom
x18 ABI's switch cost from outside fwe.

## 8. What fwe can take from these

Each idea names its source and what fwe would have to implement. The
roadmap items are M6 PR 5 (4 KiB pages), M6 PR 6 (Wine natively), M7 PR 2
(the GPU) and M7 PR 4 (graphical Wine) in [ROADMAP.md](../../ROADMAP.md).

1. **Provide `/dev/ntsync`.** Alpine's Wine 11.0, the one fwe runs, opens
   it in `wineserver` and needs no setting (Section 5.2); Proton 11 prefers
   it to fsync (Section 4.2). Without it every Windows wait is a socket
   round trip to `wineserver`, the column msync measured at over 170 s
   against 3.8 s for 10 million contended waits on macOS (Section 5.3).
   *fwe implements:* a misc device node `/dev/ntsync` (mode 0666) whose
   every open is an instance; the three create ioctls returning object
   descriptors; the eleven object and wait ioctls with the kernel's exact
   errors (`EINVAL`, `EOVERFLOW`, `EPERM`, `EOWNERDEAD`, `ETIMEDOUT`,
   `EINTR`); wait-all atomic across up to 64 objects; the `alert` event;
   absolute timeouts on `CLOCK_MONOTONIC` and `CLOCK_REALTIME`; object
   descriptors that cross processes with `SCM_RIGHTS` and fork (Wine sends
   the device and every object from `wineserver` to its clients), so
   object state lives in memory every fwe process maps, as fwe's shared
   futex table does, and waits sleep on the host's shared address waits
   (`__ulock_wait2`, which msync also found the fastest single-object path
   on macOS). The Linux selftest
   ([ntsync.c](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/drivers/ntsync))
   is a ready conformance test; msync's "contended wait" and "zigzag" are
   ready micro benchmarks.
2. **Keep `futex_waitv` on shared memory fast** for Proton's fsync. fwe
   has both pieces (Section 5.4); fsync's waits are `FUTEX_32` without the
   private flag on a `shm_open` file, so they take fwe's shared-futex path.
   *fwe implements:* nothing new; a micro benchmark of a shared
   `futex_waitv` wake-to-wake time would show its cost (source:
   [Proton fsync.c](https://github.com/ValveSoftware/wine/blob/bleeding-edge/dlls/ntdll/unix/fsync.c)).
3. **Leave esync alone.** It is gone from Proton 11 and was never in
   upstream Wine (Section 4.2), and it needs one eventfd per object, which
   fwe makes from several host objects (Section 5.4).
4. **x18: measure before choosing.** Windows ARM64 code reads `x18` for
   every TEB access, so the number of rewritten `x18` sites in Wine's PE
   DLLs and a program's, and their share of time, decide PR 6's speed. The
   macOS answers others use: the custom x18 ABI (fwe already probes it and
   rejected it for its per-switch cost and unreliability, Section 2.8) and
   an old-SDK link (`-Wl,-platform_version,macos,11.0,11.0`), under which
   the kernel preserves `x18`
   ([wine-devel](https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/CKG5CEN2BE5VRXZ7O7NX4YUSBH3247WH/)).
   The second would let `x18` uses run as they are, but makes correctness
   depend on a compatibility behaviour Apple may drop, which fwe's design
   has so far refused ([docs/architecture.md](../../docs/architecture.md)).
   *fwe implements:* counts of `x18` stubs executed per Wine program, and
   if the old-SDK behaviour is ever considered, a test that `x18` survives
   preemption and signals under it.
5. **4 KiB pages from the host on macOS 26.5.**
   `posix_spawnattr_set_4k_page_size_np()` spawns a process with 4 KiB
   pages (Section 2.9). For M6 PR 5 this is an alternative to emulating
   4 KiB protections on 16 KiB pages, for a guest that needs them (Wine:
   "ARM64 support requires the system page size to be 4K"; Wine 11's own
   4 KiB simulation "works for simple applications", Section 3.1).
   *fwe implements:* a spawn path for such guests, gated on the host
   version and on the entitlement it needs (which entitlement was not
   found; the post lists `com.apple.developer.cross-architecture-support`
   for these features together).
6. **A remappable `__PAGEZERO` (Xcode 26.4).** `-Wl,-x86_64_layout_emulation`
   lets a process change and remap its PAGEZERO (Section 2.9). fwe sends
   executables linked below 4 GiB to its VM because PAGEZERO cannot be
   mapped ([docs/linux-on-macos.md](../../docs/linux-on-macos.md)); Wine
   wants `0x7ffe0000` for `USER_SHARED_DATA` for the same reason.
   *fwe implements:* an experiment linking `fwe` with the flag to learn
   what can be mapped below 4 GiB natively and which entitlement it needs.
   Only one source documents the flag, so this is unverified.
7. **Make Wine's address search cheap.** Wine reserves memory in a range
   by probing every 64 KB from the bottom, which cost 40–170 ms per call
   on macOS ([FH2 port issue 10](https://github.com/fladnaG86/FH2-Port-AppleSilicon/issues/10)).
   Under fwe each probe is a Linux `mmap` that fwe answers. *fwe
   implements:* a micro benchmark of `VirtualAlloc2` with an address range
   under Wine, and a failed hinted or `MAP_FIXED_NOREPLACE` `mmap`
   answered from fwe's own map bookkeeping without a host call.
8. **The GPU through Venus, with the host driver chosen at run time.**
   libkrun's in-VM path (virtio-gpu, Venus, virglrenderer, MoltenVK) is
   what M7 PR 2 plans in-process; the FX launcher loads either MoltenVK or
   KosmicKrisp under virglrenderer (`VKR_VULKAN_DRIVER`) and measured
   KosmicKrisp 1.6× faster in one game (Section 6.6). The guest driver is
   Alpine's `mesa-vulkan-virtio`. *fwe implements:* `/dev/dri/renderD128`
   with the virtio-gpu DRM ioctls Venus uses (context creation with the
   Venus capset, blob resources, execbuffer, fences), backed by an
   in-process virglrenderer; blob memory shared between guest and host
   without a copy, which in-process needs no hypervisor mapping.
9. **Do not count on upstream DXVK over upstream MoltenVK.** DXVK 3 needs
   Vulkan 1.4 with `VK_EXT_transform_feedback`; one developer reports DXGI
   also refusing a device without geometry shaders
   ([post on X](https://x.com/multision/status/2107620946508955894), not
   fetched, quoted in a search summary). MoltenVK offers neither, and
   KosmicKrisp lacked both in October 2026 (Sections 4.3, 6.2, 6.3). M7 PR
   4's Direct3D demo needs a path that holds: DXVK with a MoltenVK that has
   geometry shaders (UTM's fork), a DXVK version or fork that accepts what
   MoltenVK has, VKD3D-Proton or vkd3d for Direct3D 12 (whether either
   runs on upstream MoltenVK was not found), or DXMT (next item). *fwe
   implements:* nothing in its ABI; a choice of pinned graphics components
   for CI.
10. **DXMT through a thunk instead of a VM channel.** DXMT's Unix side,
    `winemetal.so`, is a small interface the FX launcher forwards across
    virtio-gpu to `libwmtr_host.dylib`, a host executor, and it measured
    up to 2.9× DXVK's frame rate there (Section 6.5). In fwe's native
    backend there is no VM boundary: a Linux `winemetal.so` whose entry
    points fwe answers by calling a host-side executor in the same process
    would reach Metal with no Vulkan translation and no copy. This is the
    library thunking FEX and Box64 do
    ([docs/comparisons.md](../../docs/comparisons.md)). Caveats: DXMT is
    Direct3D 10/11 only, has no stream output, and builds as ARM64EC; an
    ARM64 (classic) build, which a pure ARM64 Windows program's process
    loads, was **not found**. *fwe implements:* a guest-to-host call
    mechanism for one named library and its host counterpart, and the
    trust model (the guest passes host addresses, as in the FX launcher).
11. **D3DMetal is not an option.** It is closed, Apple's, and found only in
    x86-64 Wine under Rosetta (Section 2.4).
12. **Proton itself on fwe** is within reach of the same work: Proton 11
    has ARM64 builds (Section 4.1); Steam's runtime container needs
    bubblewrap and unprivileged user namespaces, which fwe has from M3;
    its synchronisation needs `/dev/ntsync` or `futex_waitv`. x86 games
    would need FEX as ARM64EC inside Wine, which ROADMAP.md lists as not
    planned for 1.0; under fwe FEX's generated code would run by fwe's JIT
    translation like any run-time code.
13. **Benchmarks the sources already used** (AGENTS.md asks each speed PR
    for micro and macro benchmarks): msync's contended-wait and zigzag
    tests for synchronisation; d3d11bench's fill-rate and draw-call tests
    for Direct3D (used by the FX launcher); `vkcube` against MoltenVK
    natively for Vulkan (ROADMAP M7 PR 2); a Windows program's run under
    Wine against the same sources built for macOS (ROADMAP M6 PR 6).

## 9. Not found

- Apple documentation of the custom x18 ABI, its entitlement, the 4 KiB
  spawn attribute, `thread_set_x86_64_compat()` or
  `-x86_64_layout_emulation`; everything about them here comes from Wine
  developers, third-party forks and fwe's own probe.
- CodeWeavers' own text for the ARM64 Preview (their blog refused
  automated fetches) and its minimum macOS.
- An ARM64 or ARM64EC build of D3DMetal.
- A measurement of NTSync against fsync on the same machine.
- A graphics frame-rate comparison of Venus against the same Vulkan
  program natively on macOS.
- Whether macOS 28's Rosetta subset covers Windows games under Wine, in
  Apple's words.
