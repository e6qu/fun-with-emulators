# Wine on Asahi Linux: a 4 KiB ABI on 16 KiB pages

A survey, made on 2026-11-21, of how Windows programs run on Asahi Linux,
whose kernel uses 16 KiB pages on Apple Silicon while the Windows ABI
assumes 4 KiB pages: how Wine simulates 4 KiB pages on larger host pages,
what Fedora Asahi Remix does by default, how muvm's 4 KiB microVM shares
the host, what FEX and Box64 do about page size, and what it means for
fwe. It goes deeper than
[wine-on-apple-silicon.md](wine-on-apple-silicon.md) (which records Wine
10's 4 KiB requirement, Wine 11's one-line announcement of the simulation,
and that Asahi runs x86 games in muvm) and does not repeat it.

Each fact has its source beside it. Where a statement is a reading of
source code or of a binary, it says so, with the version and the date of
the reading. "Not found" means the search turned up nothing reliable;
nothing here is guessed. Section 7 is an assessment, kept apart from the
sourced facts. Fetches refused: phoronix.com (403), docs.fedoraproject.org
(a bot wall), the wine-gitlab archive of MR 4737 (404); Fedora's own
documentation is therefore taken from search summaries, marked as such.

## 1. The short version

1. **Wine's simulation is upstream since Wine 10.5 (2025-04-04), by
   Alexandre Julliard**, eight commits of 2025-03-25 in
   `dlls/ntdll/unix/virtual.c` and `server/mapping.c`, plus 64 KiB section
   alignment for Wine's own ARM64 PE files in Wine 10.6. It is on by
   itself whenever `sysconf(_SC_PAGESIZE)` is not 4096 on ARM64; there is
   no setting (Section 2).
2. **It is permissive, not exact.** Wine keeps its own 4 KiB protection
   table, gives each host page the *union* of its 4 KiB parts'
   protections, and never enforces the stricter parts. Image sections not
   aligned to the host page are read with `pread` into anonymous memory;
   unaligned *shared writable* sections fail to load; partial frees of a
   host page are refused; guard pages and write watches work per host page
   (Section 2.3).
3. **Fedora Asahi Remix ships no ARM64 Wine.** Fedora's `wine` package is
   `ExclusiveArch: %{ix86} x86_64`; Fedora 45 aarch64 has `fex-emu` 2604,
   `fex-emu-rootfs-fedora` and `muvm` 0.6.0. Windows programs run as x86
   Wine or Proton under FEX inside muvm, via `dnf install steam` or
   `binfmt-dispatcher`, which uses muvm when the page size is not 4 KiB
   (Section 3).
4. **Outside muvm** Asahi showed 32-bit x86 Windows games (2025-08) and
   64-bit ones (2025-10, "early alpha") in ARM64 Wine with FEX's Windows
   DLLs, then in 2026-11 removed the FEX hacks that relied on, and ran
   games outside muvm instead on Google's **P3S** (per-process 4 KiB pages
   on a 16 KiB kernel) patch set, which it will not ship yet (Section 3.3).
5. **muvm costs "about 20%"** by Asahi's own count, cannot use Wayland,
   has slow I/O and struggles with some input devices; it shares the host
   root over virtio-fs, `/dev/shm` over virtio-fs DAX, X11 over a
   virtio-gpu cross-domain proxy, the GPU by DRM native context, input
   over vsock to `uinput` (Section 4).
6. **FEX (Linux frontend) refuses 16 KiB hosts** and closed 4 KiB
   emulation as not planned. **Box64 emulates 4 KiB guest pages on larger
   host pages**, reports 4096 to the x86 program, and since 2026-08 runs
   x86-64 Linux Wine on 16 KiB hosts ("Wine works!") by special-casing
   Wine's mapping patterns (Section 5).
7. **For fwe (assessment, Section 7):** fwe reports 16 KiB in
   `AT_PAGESZ`, so Alpine's Wine 11.0 already turns its simulation on under
   fwe-native; Alpine's Wine ELF and PE files are all 64 KiB aligned. The
   cheapest first step to native Wine is to let Wine simulate and give it
   what it needs: a signal frame with the ESR record (fwe writes none
   today), mixed RX+RW host pages run by translation, and `x18`.

## 2. Wine's 4 KiB simulation on larger host pages

### 2.1 The commits

All by Alexandre Julliard, read through the GitHub mirror on 2026-11-21.

| Commit | Date | What | Files |
|---|---|---|---|
| [126c54cd25](https://github.com/wine-mirror/wine/commit/126c54cd2562ad2ea5fea803b4107b68f4fab9b3) | 2024-11-15 | "server: Print a warning if page size isn't 4k" (`wineserver: page size is %uk but Wine requires 4k pages, expect problems`) | `server/mapping.c` |
| [6e1c906fa6](https://github.com/wine-mirror/wine/commit/6e1c906fa6d12dd9c9db7d497b65ffe1efc62983) | 2025-03-25 | "ntdll: Retrieve the host page size on the Unix side on ARM64"; `page_size` becomes a constant 0x1000 on every architecture | `virtual.c`, `system.c`, `ntdll_misc.h` |
| [d813ffc355](https://github.com/wine-mirror/wine/commit/d813ffc3557083fd135a28d59f490bb83754263f) | 2025-03-25 | "Align virtual memory allocations to the host page size" | `virtual.c` |
| [71d51a7609](https://github.com/wine-mirror/wine/commit/71d51a76097d74ddbf7afe8c7dc8b22c58bb52a2) | 2025-03-25 | "Align virtual memory deallocations to the host page size. And refuse to free partial pages." | `virtual.c` |
| [102a49bbcb](https://github.com/wine-mirror/wine/commit/102a49bbcbf29ce1bd92630ea3e12d9836a4e1b6) | 2025-03-25 | "Apply virtual page protections to the entire host page" (adds `get_host_page_vprot`) | `virtual.c` |
| [d9d012965d](https://github.com/wine-mirror/wine/commit/d9d012965debb4b262741f04d557723eaac32cae) | 2025-03-25 | "Align file mappings to the host page size" | `virtual.c` |
| [7085166fd2](https://github.com/wine-mirror/wine/commit/7085166fd2473e0e2c5466e2e332ba7aba4cb221) | 2025-03-25 | "Align stack guard pages to the host page size" | `virtual.c` |
| [431cd9b0d6](https://github.com/wine-mirror/wine/commit/431cd9b0d6e9b4f5b3be01d5d43c200c25dd0a02) | 2025-03-25 | "Align to the host page size when calling mlock/munlock/msync" | `virtual.c` |
| [ee8a2bc88b](https://github.com/wine-mirror/wine/commit/ee8a2bc88b61a2f142c01096fd0a798c59299719) | 2025-03-25 | "server: Support the host page size being different from the Windows page size"; removes the 2024 warning | `server/mapping.c` |
| [e2686a5dff](https://github.com/wine-mirror/wine/commit/e2686a5dffe9f4db3a983a4c1d2aba4f46f35758), [12f00fa930](https://github.com/wine-mirror/wine/commit/12f00fa930) | 2025-04-07 | "winegcc: Set default section alignment to 64k on ARM64. To support larger page sizes."; "winebuild: Align sections to 64k on ARM64" | `tools/winegcc`, `tools/winebuild` |
| [ed091c479a](https://github.com/wine-mirror/wine/commit/ed091c479a4d1700a1716776c1f5b6f86ebf1381) (Jacek Caban) | 2026-05-07 | "server: Store the client page size in the process struct. Allows clients to use a different page size than the server." (after 11.0) | `server/*`, `ntdll/unix/server.c` |

- Wine 10.5 (tagged 2025-04-04) lists "Support for larger page sizes on
  ARM64" first in its summary and closes bug 52715, "wine segfaults on
  asahi linux due to 16k pages"; Wine 10.6 (2025-04-20) carries the 64 KiB
  alignment
  ([10.5 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.5/ANNOUNCE.md),
  [10.6 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.6/ANNOUNCE.md)).
  Wine 11.0's ANNOUNCE adds: "because it is not possible to completely
  hide the differences, more demanding applications may not work
  correctly"
  ([11.0 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md)).
- Julliard on bug 52715, 2025-03-26: "This should work now. It's not
  perfect, and can't be perfect by design, so feel free to file new bugs
  for remaining issues." The bug's history: Wine's ELF binaries were linked
  with `-Wl,-z,max-page-size=0x1000`; Fabian Maurer's "16k page hacks"
  (2023-12) needed the PE binaries built for 16 KiB pages too, which
  Julliard would not accept because "Wine must be able to load 4k
  binaries" (relayed by Maurer, 2024-02-07)
  ([bug 52715](https://bugs.winehq.org/show_bug.cgi?id=52715)). Maurer's
  merge request to align PE binaries to 64 KiB was closed on 2024-02-06
  ([MR 4737](https://gitlab.winehq.org/wine/wine/-/merge_requests/4737),
  read through the GitLab API; its discussion was not fetched).
- No wine-devel thread on the design was found; the commits went in
  directly. The Hangover developers' page on page sizes predates the
  result ([Hangover wiki, 2025-04-21](https://github.com/AndreRH/hangover/wiki/Page-Size)).

### 2.2 How it works

Read from
[`dlls/ntdll/unix/virtual.c` at wine-11.0](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/ntdll/unix/virtual.c)
on 2026-11-21:

- **Two page sizes.** `page_size` is the Windows one, `0x1000`, everywhere;
  `host_page_size` is `sysconf(_SC_PAGESIZE)` on `__aarch64__` and a
  constant `0x1000` on every other architecture, so the simulation exists
  only on ARM64 (`virtual_init`). Windows programs are told 4 KiB pages and
  64 KiB allocation granularity (`info->PageSize = page_size`,
  `AllocationGranularity = granularity_mask + 1`).
- **One protection byte per 4 KiB page.** Wine's `pages_vprot` table keeps
  read, write, write-copy, execute, guard, committed and write-watch bits
  per Windows page, as before. `VirtualQuery` reports from this table, so a
  program sees the protections it asked for.
- **Host protection is the union.** `get_host_page_vprot` ORs the bytes of
  all 4 KiB pages in a host page; `mprotect_range` applies the Unix
  protection of that union, host page by host page. A 4 KiB read-only or
  no-access page that shares a 16 KiB host page with a writable one is
  therefore writable; one beside an executable page is executable.
- **Allocations.** `map_view` rounds sizes to the host page and asserts
  that alignment is at least the host page (`align_mask >= host_page_mask`);
  reservations are 64 KiB aligned anyway, a multiple of 16 KiB (and equal
  to 64 KiB host pages). `anon_mmap_fixed` asserts host alignment of
  address and size.
- **Frees and decommits.** `free_pages` refuses ("unaligned partial free")
  with `STATUS_CONFLICTING_ADDRESSES` to shrink a view from the start or
  punch a hole unless the cut is host-aligned; freeing a whole view always
  works. `decommit_pages` replaces only the whole host pages inside the
  range with fresh `PROT_NONE` memory and clears the committed bits of all
  4 KiB pages, so partly covered host pages keep their contents.
  Placeholder splits (`free_pages_preserve_placeholder`) refuse unaligned
  cuts too.
- **File views** (`map_file_into_view`): when the view's 4 KiB-rounded
  start and size are host-aligned (or the range ends the view), the file
  is `mmap`ed `MAP_FIXED`; otherwise a shared writable mapping fails ("unaligned shared mapping %p-%p not supported",
  `STATUS_INVALID_PARAMETER`)
  and anything else is copied: `mprotect` read-write, then `pread` of the
  bytes. Data-file views start at multiples of 64 KiB, because Windows
  requires `MapViewOfFile` offsets to be "a multiple of the VirtualAlloc
  allocation granularity"
  ([Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)),
  so they map directly.
- **PE images** (`map_image_into_view`): the image's view is first an
  anonymous read-write reservation; the header is `mmap`ed up to the last
  whole host page and the rest `pread` (`map_pe_header`). Each section
  goes through `map_file_into_view`, so a section at a 4 KiB virtual
  address that is not host-aligned is read into the anonymous memory, a
  private copy per process, not shared with the page cache. Shared
  writable sections (`IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE`) are
  mapped from a shared file with write access, so unaligned ones fail to
  load. Section protections are then set per 4 KiB page and applied as the
  union.
- **Faults** (`virtual_handle_fault`): the faulting address is rounded to
  the host page and its union protection consulted. A guard bit anywhere
  in the host page raises `STATUS_GUARD_PAGE_VIOLATION` and clears guard
  on the whole host page, or grows the thread stack. A *write* fault on a
  write-watched host page clears the watch on all its 4 KiB pages and
  retries. Nothing catches an access to a stricter 4 KiB part, because the
  host never faults there. On Linux the read/write/execute kind comes from
  the signal frame's ESR record (`get_fault_esr` reads `ESR_MAGIC`; no
  record gives 0, a read fault)
  ([signal_arm64.c at wine-11.0](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/ntdll/unix/signal_arm64.c)).
- **Write watches** use `userfaultfd` write-protection and `PAGEMAP_SCAN`
  when the kernel has them (new in Wine 11.0), at host-page granularity:
  a written host page reports all its 4 KiB pages. Without them, they are
  `mprotect` plus write faults, as above.
- **Stacks** get guard regions of one or two host pages (`StackLimit`
  moves by `host_page_size`).
- **wineserver** uses `sysconf(_SC_PAGESIZE)` for view checks and rounds
  session mappings to it (11.0); after 11.0 each client sends its own page
  size (ed091c479a).

### 2.3 What fails, and why

From the code above, unless another source is named:

| Case | What happens |
|---|---|
| Executable and writable 4 KiB parts in one host page (a 4 KiB-aligned image whose `.text` ends where `.data` starts, in the same 16 KiB) | the host page is read-write-execute; writes to code and execution of data succeed; Google lists this layout as the cause of "W^X violations or SIGSEGV" on 16 KiB Android ([LPC 2026 slides](https://lpc.events/event/20/contributions/2630/)) |
| A program relying on a fault from a no-access or read-only 4 KiB page (its own guard pages, garbage-collector barriers, copy-on-write tricks) | no fault if a neighbour in the host page is more permissive |
| `PAGE_GUARD` on one 4 KiB page | the whole host page guards; the first touch anywhere clears it |
| Unaligned shared writable image sections | load fails |
| Image sections at 4 KiB offsets | copied, not mapped: more memory, no sharing between processes, read at load |
| `VirtualFree` of part of a host page | refused with `STATUS_CONFLICTING_ADDRESSES` |
| `MEM_DECOMMIT` of part of a host page | contents kept, not zeroed when recommitted |
| `GetWriteWatch` | reports 16 KiB at a time |
| Code that assumes 4 KiB physical pages | Asahi: "not all applications respect" 64 KiB; "Any applications which do this simply will not work, and will continue to require the use of muvm" ([Asahi 6.16 report](https://asahilinux.org/2025/08/progress-report-6-16/)); "almost all games bake in an assumed 4 KiB memory page size to enable certain performance optimisation" ([Asahi 7.3 report](https://asahilinux.org/2026/11/progress-report-7-3/)) |
| `AT_ROUND_TO_PAGE` views | disallowed on 64-bit since Wine 10.4 ([10.4 ANNOUNCE](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.4/ANNOUNCE.md)) |

Wine's own ARM64 PE files avoid all of these: since 10.6 they are linked
with 64 KiB section and file alignment. Read on 2026-11-21 from Alpine
3.24's `wine-11.0-r0` aarch64 package (SHA-256 `b9a2ae11...`, the one
fwe's Wine test fetches): `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`,
`user32.dll` and `cmd.exe` all have `SectionAlignment` and `FileAlignment`
`0x10000`; `wine`, `wine-preloader`, `ntdll.so` and `wineserver` have every
`PT_LOAD` aligned to `0x10000`. The simulation's weak points are therefore
third-party images with the Windows norm of 4 KiB sections, and programs'
own memory management.

### 2.4 On by default

Yes, with no switch: the host page size is read at start-up and every path
above follows it; the 2024 wineserver warning was removed. The only
related settings are build-time (winegcc's `--section-alignment`). Hangover
adds its own warning, "You are running with the wrong page size, expect
problems!" ([Hangover issue 193](https://github.com/AndreRH/hangover/issues/193)).

## 3. Windows programs on Asahi Linux today

### 3.1 What Fedora Asahi Remix ships

- **No ARM64 Wine in Fedora.** Fedora's `wine.spec` (11.21, rawhide) sets
  `ExclusiveArch: %{ix86} x86_64`, with the comment "Wine 9.15 and higher
  requires ARM MinGW binaries (dlltool)", although it has `%ifarch aarch64`
  branches ([wine.spec](https://src.fedoraproject.org/rpms/wine/blob/rawhide/f/wine.spec),
  read 2026-11-21). Fedora 45's aarch64 repository has no `wine` package
  but `fex-emu-2604`, `fex-emu-rootfs-fedora` and `muvm-0.6.0`; x86_64
  has `wine-11.21`
  ([aarch64 Packages/w](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Everything/aarch64/os/Packages/w/),
  [f](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Everything/aarch64/os/Packages/f/),
  [m](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Everything/aarch64/os/Packages/m/),
  listed 2026-11-21). Fedora 45 and its Asahi Remix were released on
  2026-11-03 ([Asahi 7.3 report](https://asahilinux.org/2026/11/progress-report-7-3/)).
- **Steam:** "just `dnf install steam` and play"
  ([Asahi 2024-10-10](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/));
  the package is Asahi's wrapper that installs and launches Steam inside
  muvm ([Copr @asahi/steam](https://copr.fedorainfracloud.org/coprs/g/asahi/steam);
  the Fedora x86-support page says the same, per a search summary of
  [docs.fedoraproject.org](https://docs.fedoraproject.org/en-US/fedora-asahi-remix/x86-support/)).
  Steam then runs x86-64 Proton under FEX in the VM. "most games require
  16GB of memory due to emulation overhead" (same Asahi post).
- **Any x86 program:** `binfmt-dispatcher`, packaged in Fedora, is the
  `binfmt_misc` handler; "If enabled (via the `use_muvm` config setting),
  binfmt-dispatcher will use muvm to execute the interpreter in a microVM
  if the system page-size is not 4k", and installs missing interpreters
  ([README](https://github.com/AsahiLinux/binfmt-dispatcher)). Inside,
  muvm registers FEX for x86 binaries
  ([muvm README](https://github.com/AsahiLinux/muvm)). Fedora's docs
  (search summary) say x86-64 programs "must be launched from the
  microVM", e.g. `muvm -- FEXBash`. So x86 Wine on Fedora Asahi is the
  x86_64 Wine of the FEX root filesystem, run in muvm.
- Asahi's list of fixed packages: Wine "Fixed since 10.5", box64 "fixed
  since 0.2.8"; "Fedora Linux Asahi Remix's `muvm` package is, by default,
  configured to virtualize a 4K kernel"
  ([Broken software](https://asahilinux.org/docs/sw/broken-software/)).

### 3.2 ARM64 Windows programs

They need an ARM64 Wine, which runs natively on the 16 KiB kernel through
Section 2's simulation. Fedora has none (3.1). Gentoo "automatically
installs FEX's WoW64 implementation on AArch64 systems when the `wow64`
USE flag is enabled" ([Asahi 6.16](https://asahilinux.org/2025/08/progress-report-6-16/)),
and from 2025-10 its Wine build makes "the required FEX DLLs"
([Asahi 6.17](https://asahilinux.org/2025/10/progress-report-6-17/)). The
AUR has `wine-asahi-git`, "Wine with ARM64EC support for Asahi Linux (16k
pages)": Wine 10.16 with staging and Billy Laws's ARM64EC patches, none of
which touch page size ([PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=wine-asahi-git),
read 2026-11-21). No report specific to ARM64-native Windows programs on
Asahi was found; Asahi's caption "AMD64 Notepad++ running in WINE's
ARM64EC mode" is the nearest (6.16).

### 3.3 x86 and x64 Windows programs

| Path | Where Wine runs | Status | Source |
|---|---|---|---|
| Steam / Proton or x86 Wine under FEX in muvm | 4 KiB guest kernel | the default; "about 20%" slower | 3.1; [7.3](https://asahilinux.org/2026/11/progress-report-7-3/) |
| ARM64 Wine + FEX `libwow64fex.dll` (as `xtajit.dll`) for 32-bit x86 | host, 16 KiB | 2025-08: works "without muvm!", needs Mesa 25.2's `VK_EXT_map_memory_placed` for 32-bit DXVK; "Since all Windows applications are allocated 64K pages, we … don't need to worry about page size", with the exceptions in 2.3; Fedora's Wine then lacked WoW64 | [6.16](https://asahilinux.org/2025/08/progress-report-6-16/) |
| ARM64 Wine + FEX ARM64EC for 64-bit x86 | host, 16 KiB | 2025-10: Hollow Knight and NieR:Automata on Gentoo; "Consider it an early alpha"; ARM64X/ARM64EC "still incomplete" | [6.17](https://asahilinux.org/2025/10/progress-report-6-17/) |
| The same, 2026-11 | host | the earlier runs "relied on ugly hacks inside FEX which have since been removed in the interests of maintainability and translation correctness" (not described further); "compatibility was hit-and-miss" | [7.3](https://asahilinux.org/2026/11/progress-report-7-3/) |
| FEX + Wine on a P3S kernel (4 KiB process on a 16 KiB kernel) | host, process in 4 KiB mode | 2026-11: Star Wars Battlefront, Wolfenstein: The New Order (144+ fps on an M2 Max), GTA IV, Fallout: New Vegas "outside of muvm"; "a shim is required to force P3S on"; not shipped: "we do not want to ship this in our downstream tree" until Google's plans are known | [7.3](https://asahilinux.org/2026/11/progress-report-7-3/) |
| Hangover (Wine + FEX or Box64) | host | its wiki says it "needs a 4k page size" and suggests muvm, untested; it ran on 64 KiB pages after Wine 10.5, "not every program will run" | [wiki](https://github.com/AndreRH/hangover/wiki/Page-Size), [issue 130](https://github.com/AndreRH/hangover/issues/130) |
| x86-64 Linux Wine under Box64 | host, 16 KiB | 2026-08: "Wine works!" (Section 5.2) | [box64 PR 4187](https://github.com/ptitSeb/box64/pull/4187) |

**P3S** (Google, Linux Plumbers 2026-10-05): a 16 KiB kernel switches the
user translation granule `TCR_EL1.TG0` to 4 KiB for a process exec'd with
`ADDR_PAGE_SIZE_4KB` (children inherit), 39-bit user addresses; the page
cache keeps 16 KiB folios and a 4 KiB process maps four 4 KiB PTEs to
their slices (`vm_slice_off`); faults past EOF inside the last folio give
`SIGBUS`; THP, hugetlbfs and KSM are gated off, `userfaultfd` only for
anonymous memory. Google's own comparison puts a "Bionic Linker Compat"
of "userspace copy & segment remapping" at "~70–80%" compatibility, a
4 KiB guest VM at 100 % with "High CPU & RAM", and P3S at "~100%" and
"~0% (Native)" overhead. Status: patches posted on `android17-6.18-p3s`
([talk](https://lpc.events/event/20/contributions/2630/),
[slides](https://lpc.events/event/20/contributions/2630/attachments/2041/4583/Compatibility%20of%204KB%20Applications%20on%20Large%20Page-Sized%20Systems.pdf),
[Gerrit topic](https://r.android.com/q/topic:p3s_v1)). Asahi: "XNU allows
userspace processes to map themselves at any page granularity, so all
Rosetta needs to do is tell XNU to map 4 KiB pages for its child
processes" ([7.3](https://asahilinux.org/2026/11/progress-report-7-3/)).

So: no default Fedora Asahi path runs Wine on the 16 KiB kernel; ARM64
Wine does so by itself, x86 code joins it through FEX's Windows DLLs with
mixed results, and Box64 runs x86-64 Linux Wine there.

## 4. muvm and libkrun's 4 KiB guest

Read from [muvm](https://github.com/AsahiLinux/muvm) `main` (0.7.0,
2026-09-24) and [libkrunfw](https://github.com/containers/libkrunfw) on
2026-11-21 unless marked.

- **Guest kernel:** libkrunfw's `config-libkrunfw_aarch64` is Linux 6.12.91
  with `CONFIG_ARM64_4K_PAGES=y`, `CONFIG_DRM_VIRTIO_GPU=y`,
  `CONFIG_VIRTIO_FS=y`, `CONFIG_FUSE_DAX=y`. KVM lets the guest choose its
  own granule: "While Linux can't mix page sizes between processes, it can
  virtualize another Arm Linux kernel with a different page size"
  ([Asahi 2024-10-10](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/)).
- **Files:** `krun_set_root(ctx, "/")`, the host's root over virtio-fs;
  `/dev/shm` as a second virtio-fs device (`devshm`, a 512 MiB DAX
  window) so host and guest map the same memory (`bin/muvm.rs`). FEX's
  root filesystem images (erofs) are mounted and overlaid inside
  (`guest/mount.rs`).
- **Display:** first sommelier with Xwayland in the guest (2024-10),
  dropped because it "does _too much_ and _too little_"; then
  `muvm-x11bridge`, a thin X11 proxy to the host X server over a
  virtio-gpu cross-domain channel, buffers shared without copies
  ([Asahi Lina, 2024-12-12](https://asahilinux.org/2024/12/muvm-x11-bridging/)).
  In the code: cross-domain capset 5, channel type X11 `0x11`; DRI3
  `PixmapFromBuffer(s)` and fences handled; xshmfence futexes moved into
  `/dev/shm` files by `ptrace`-attaching the client and injecting
  `mmap`/`munmap` through a `svc` found in its vDSO (`guest/bridge/x11.rs`).
  "muvm cannot use Wayland" ([7.3](https://asahilinux.org/2026/11/progress-report-7-3/)).
- **GPU:** default `--gpu-mode` is DRM native context
  (`VIRGLRENDERER_DRM`), with Venus and software as options; VRAM reported
  defaults to 50 % of RAM, guest memory to 80 %, not reserved up front
  (`cli_options.rs`, README). Native context "runs the GPU kernel driver on
  the host, and the GPU userspace driver (Mesa) on the guest"; only small
  execution buffers cross through the VMM and virglrenderer; "fire-and-
  forget" workloads get "nearly native performance", ones that wait on the
  GPU see higher latency; implicit sync is emulated in Mesa on both sides
  ([2024-12-12](https://asahilinux.org/2024/12/muvm-x11-bridging/)). So
  Asahi's Vulkan driver (Honeykrisp) runs as guest Mesa.
- **Input, sound, rest:** `muvm-hidpipe` sends host input devices over
  vsock to `uinput` in the guest (`guest/hidpipe.rs`, [hidpipe](https://github.com/AsahiLinux/hidpipe));
  PulseAudio and PipeWire sockets are bridged over vsock; network through
  `passt`; an AT-SPI accessibility bridge since 0.7.0.
- **Cost:** "about 20% depending on the workload"; "muvm cannot use
  Wayland, has slow I/O performance, and struggles with certain types of
  input devices"; "the assumption that DRM Native Context would enable"
  near-native graphics "did not hold"
  ([7.3](https://asahilinux.org/2026/11/progress-report-7-3/)). The 6.16
  report lists what leaving the VM removes: paravirtualised GPU, network
  and file system, and proxied X11 and PipeWire, with Wine able to use
  Wayland directly.

## 5. FEX and Box64 on 16 KiB host pages

### 5.1 FEX

- FEX's Linux frontend does not support 16 KiB kernels: "FEX only supports
  4kb page size systems ... FEX isn't going to support 4kb page size
  emulation" (Sonicadvance1, 2024-03-17,
  [issue 3496](https://github.com/FEX-Emu/FEX/issues/3496)); "FEX doesn't
  support 16KB page size kernels" (2026-05-22,
  [issue 5517](https://github.com/FEX-Emu/FEX/issues/5517)).
- 4 KiB emulation was discussed in 2022: marcan (Hector Martin) proposed partial
  support (file mappings not at fixed addresses placed at an offset in a
  16 KiB page; straddling pages given the union of protections); FEX's
  developer found loader segments too tightly packed; Alyssa Rosenzweig
  closed it on 2024-06-02 as not planned: "the relevant use cases are
  better served by krun"
  ([issue 1921](https://github.com/FEX-Emu/FEX/issues/1921),
  [issue 1221](https://github.com/FEX-Emu/FEX/issues/1221)).
- FEX does read the page size at run time
  ([PR 3215](https://github.com/FEX-Emu/FEX/pull/3215),
  [PR 4991](https://github.com/FEX-Emu/FEX/pull/4991)), which is what lets
  its Windows DLLs run inside an ARM64 Wine, where Wine, not FEX, owns
  memory (Section 3.3).

### 5.2 Box64

Read from [box64](https://github.com/ptitSeb/box64) `main` on 2026-11-21:

- Box64 wraps the x86 program's libc and answers `getpagesize()` and
  `sysconf(_SC_PAGESIZE)` with 4096 (`my_getpagesize`, `my_sysconf` in
  `src/wrapped/wrappedlibc.c`).
- It keeps the guest's protections per 4 KiB page (`memprot_guest`) beside
  the host's, applies host-page protections from them, and handles
  self-modifying-code write protection when a neighbouring 4 KiB page in
  the host page needs write access (`src/custommem.c`;
  [PR 3557](https://github.com/ptitSeb/box64/pull/3557),
  [PR 4527](https://github.com/ptitSeb/box64/pull/4527), 2026-10-03).
- Its ELF loader maps segments by host page, preserves overlapping
  segments and maps unaligned ones from the file when offset and address
  agree modulo the host page (PRs
  [4158](https://github.com/ptitSeb/box64/pull/4158),
  [4160](https://github.com/ptitSeb/box64/pull/4160),
  [4182](https://github.com/ptitSeb/box64/pull/4182), 2026-08).
- For Wine on 16 KiB hosts ([PR 4187](https://github.com/ptitSeb/box64/pull/4187),
  2026-08-04, "Wine works!"), `my_mmap64` special-cases two patterns: a
  fixed private anonymous mapping inside an existing host page is done by
  making the host page writable, zeroing the 4 KiB range and restoring the
  union of protections; a fixed private file mapping of a PE file into
  Wine's writable reservation is done with `pread` of only the requested
  4 KiB pages, so the neighbouring section is not overwritten. A
  `PROT_NONE` fixed anonymous mapping of part of a mapped host page
  returns success without doing anything. [PR 4237](https://github.com/ptitSeb/box64/pull/4237)
  disables its 64 KiB alignment check on non-4 KiB hosts.

## 6. macOS's per-process 4 KiB pages, in XNU's published source

Read from [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu)
at tag `xnu-12377.121.6` (imported 2026-06-17) on 2026-11-21:

- The loader creates a 4 KiB map when spawned with
  `_POSIX_SPAWN_FORCE_4K_PAGES` (`0x1000`): `pmap_flags |=
  PMAP_CREATE_FORCE_4K_PAGES`, then `vm_map_set_page_shift(map,
  FOURK_PAGE_SHIFT)` (`bsd/kern/mach_loader.c`); `PMAP_CREATE_FORCE_4K_PAGES`
  exists where `__ARM_MIXED_PAGE_SIZE__` (`osfmk/vm/pmap.h`).
- In `bsd/sys/spawn.h` that flag is `PRIVATE` and defined only `#if (DEBUG
  || DEVELOPMENT)`; XNU's test `tests/vm_spawn_tool.c` sets it only when
  `debug.vm_mixed_pagesize_supported` is non-zero.
- `posix_spawnattr_set_4k_page_size_np` (macOS 26.5, Section 2.9 of the
  earlier note) was not found in this source tree; which kernel path and
  entitlement it uses is not published.

## 7. What this means for fwe (assessment)

This section is an assessment built on the facts above and on fwe's
sources as of 2026-11-21; it is not itself sourced fact.

**Where fwe stands.** Natively fwe puts the host page size, 16384, in
`AT_PAGESZ` (`crates/native/src/lib.rs`;
[docs/linux-on-macos.md](../../docs/linux-on-macos.md)), and musl's
`sysconf(_SC_PAGESIZE)` returns `libc.page_size = aux[AT_PAGESZ]` on
aarch64 (musl `src/env/__libc_start_main.c`, `src/internal/libc.h`, read
through the [kraj/musl mirror](https://github.com/kraj/musl)). So Alpine's
Wine 11.0, a musl program, already runs its 4 KiB simulation whenever fwe
runs it natively; nothing has to be reported differently for that. Its
ELF and PE files are 64 KiB aligned (2.3), so Wine's own code maps as
ordinary 16 KiB-aligned files.

**What Wine's simulation would need from fwe natively** (beyond the `x18`
rewriting of M6 PR 6 and the low reservations the preloader makes):
1. **The ESR record in fault signal frames.** Linux adds an `esr_context`
   (`ESR_MAGIC`) to the frame whenever the signal comes from a fault
   ([arch/arm64/kernel/signal.c](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/signal.c):
   `if (add_all || current->thread.fault_code)`); fwe's frame
   (`crates/kernel/src/signal.rs`) has only the FP/SIMD record. Without it
   Wine classes every fault as a read, so a write to a write-watched page
   becomes an access violation instead of a retried write, and SEH
   handlers see the wrong `ExceptionInformation[0]`. fwe has no
   `userfaultfd` (`CONFIG_USERFAULTFD is not set` in its `/proc/config.gz`),
   so Wine takes the `mprotect`-and-fault path for write watches. This is
   small, and right for every Linux program, not only Wine.
2. **Read-write-execute host pages.** A 4 KiB-aligned image (fwe's own
   `guests/windows/winprog.c`, built by zig's MinGW, is the likely case;
   its alignment was not checked) gets its sections `pread` into anonymous
   memory and mixed pages made RWX by Wine. fwe runs writable and
   executable memory by translation, so such programs work but their mixed
   pages run translated; whole-16 KiB code pages run as prepared code.
3. **`mmap`/`mprotect` exactly as Linux at 16 KiB**: `MAP_FIXED` over
   Wine's reservations, `pread` into them, `PROT_NONE` remaps for
   decommit, which fwe already provides natively.

**The three ways, compared.**

| | Wine's own simulation | fwe emulates 4 KiB (M6 PR 5) | `posix_spawnattr_set_4k_page_size_np` |
|---|---|---|---|
| What fwe reports | 16384 (today) | 4096 | 4096 |
| Exactness | union protections; stricter parts unenforced; unaligned shared writable sections fail; partial frees refused | can enforce stricter parts by faults, as the roadmap item says; Box64 shows Wine's mapping patterns can be met this way | hardware 4 KiB, exact, as Rosetta and P3S get |
| fwe work | ESR record; nothing page-specific | per-4 KiB protection table, fault-and-retry for stricter parts, file contents at 4 KiB offsets copied, `MAP_SHARED` at 4 KiB offsets impossible to keep shared | spawn path, a host-page-size variable through fwe's own mapping code, macOS 26.5, a restricted entitlement and `.app` packaging; kernel path unpublished (Section 6) |
| Cost at run time | none for aligned images; copies and translated mixed pages for 4 KiB images | a fault per access to a stricter part sharing a host page with a laxer one | none for paging; 4 KiB TLB reach |
| Programs reached | Wine only, and only "simple applications" | every Linux program that needs 4 KiB, Wine included | every program, on macOS 26.5+ with the entitlement |

**Most promising, in order.** First, Wine's own simulation: it is already
active under fwe-native, needs only the ESR record (and the `x18` work PR
6 needs regardless), and Wine's own code is 64 KiB aligned; the gap is
third-party images and programs that manage memory finely, which Wine
upstream itself calls "not perfect ... by design". It is the shortest way
to PR 6's "Windows console programs without `fwe --vm`" and a fair first
test of how far "simple applications" reach. Second, for exactness,
`posix_spawnattr_set_4k_page_size_np` is the only answer without a
correctness gap, as P3S is on Linux, but it is gated on an entitlement
fwe would have to obtain and ship, on macOS 26.5, and on fwe's own code
working with a 4 KiB host page; it should be probed, not planned around,
until its entitlement is known. M6 PR 5's emulation is the general answer
for non-Wine programs that need 4 KiB pages; for Wine it would turn Wine's
simulation off (by reporting 4096) and replace a permissive layer with a
stricter one fwe maintains, which buys fidelity Wine does not ask for at
the price of faults on mixed host pages. Reporting 4096 only to Wine is
not needed and would remove the layer Wine tested on Asahi.

## Sources

Wine:
- Commits: [126c54cd25](https://github.com/wine-mirror/wine/commit/126c54cd2562ad2ea5fea803b4107b68f4fab9b3), [6e1c906fa6](https://github.com/wine-mirror/wine/commit/6e1c906fa6d12dd9c9db7d497b65ffe1efc62983), [d813ffc355](https://github.com/wine-mirror/wine/commit/d813ffc3557083fd135a28d59f490bb83754263f), [71d51a7609](https://github.com/wine-mirror/wine/commit/71d51a76097d74ddbf7afe8c7dc8b22c58bb52a2), [102a49bbcb](https://github.com/wine-mirror/wine/commit/102a49bbcbf29ce1bd92630ea3e12d9836a4e1b6), [d9d012965d](https://github.com/wine-mirror/wine/commit/d9d012965debb4b262741f04d557723eaac32cae), [7085166fd2](https://github.com/wine-mirror/wine/commit/7085166fd2473e0e2c5466e2e332ba7aba4cb221), [431cd9b0d6](https://github.com/wine-mirror/wine/commit/431cd9b0d6e9b4f5b3be01d5d43c200c25dd0a02), [ee8a2bc88b](https://github.com/wine-mirror/wine/commit/ee8a2bc88b61a2f142c01096fd0a798c59299719), [e2686a5dff](https://github.com/wine-mirror/wine/commit/e2686a5dffe9f4db3a983a4c1d2aba4f46f35758), [12f00fa930](https://github.com/wine-mirror/wine/commit/12f00fa930), [ed091c479a](https://github.com/wine-mirror/wine/commit/ed091c479a4d1700a1716776c1f5b6f86ebf1381), [67a26bddad](https://github.com/wine-mirror/wine/commit/67a26bddad0583f24801fc59589562037243d6a8)
- Source at wine-11.0: [virtual.c](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/ntdll/unix/virtual.c), [signal_arm64.c](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/ntdll/unix/signal_arm64.c)
- ANNOUNCE files: [10.0](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.0/ANNOUNCE.md), [10.4](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.4/ANNOUNCE.md), [10.5](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.5/ANNOUNCE.md), [10.6](https://raw.githubusercontent.com/wine-mirror/wine/wine-10.6/ANNOUNCE.md), [11.0](https://raw.githubusercontent.com/wine-mirror/wine/wine-11.0/ANNOUNCE.md)
- [Bug 52715](https://bugs.winehq.org/show_bug.cgi?id=52715); [MR 4737](https://gitlab.winehq.org/wine/wine/-/merge_requests/4737)
- Alpine 3.24 [`wine-11.0-r0` aarch64](https://dl-cdn.alpinelinux.org/alpine/v3.24/community/aarch64/wine-11.0-r0.apk) (headers read, not run)
- Microsoft: [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)

Asahi and Fedora:
- Asahi blog: [AAA gaming, 2024-10-10](https://asahilinux.org/2024/10/aaa-gaming-on-asahi-linux/), [X11 bridging in muvm, 2024-12-12](https://asahilinux.org/2024/12/muvm-x11-bridging/), [Linux 6.16, 2025-08-07](https://asahilinux.org/2025/08/progress-report-6-16/), [Linux 6.17, 2025-10-24](https://asahilinux.org/2025/10/progress-report-6-17/), [Linux 7.3, 2026-11-07](https://asahilinux.org/2026/11/progress-report-7-3/)
- [Asahi broken software](https://asahilinux.org/docs/sw/broken-software/)
- [muvm](https://github.com/AsahiLinux/muvm), [hidpipe](https://github.com/AsahiLinux/hidpipe), [binfmt-dispatcher](https://github.com/AsahiLinux/binfmt-dispatcher), [libkrunfw](https://github.com/containers/libkrunfw)
- Fedora: [wine.spec](https://src.fedoraproject.org/rpms/wine/blob/rawhide/f/wine.spec), [Fedora 45 aarch64 packages](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Everything/aarch64/os/Packages/), [x86-support docs](https://docs.fedoraproject.org/en-US/fedora-asahi-remix/x86-support/) (fetch refused; search summary), [Copr @asahi/steam](https://copr.fedorainfracloud.org/coprs/g/asahi/steam)
- AUR: [wine-asahi-git](https://aur.archlinux.org/packages/wine-asahi-git)

Emulators:
- FEX: issues [1221](https://github.com/FEX-Emu/FEX/issues/1221), [1921](https://github.com/FEX-Emu/FEX/issues/1921), [3496](https://github.com/FEX-Emu/FEX/issues/3496), [5517](https://github.com/FEX-Emu/FEX/issues/5517); PRs [3215](https://github.com/FEX-Emu/FEX/pull/3215), [4991](https://github.com/FEX-Emu/FEX/pull/4991)
- Box64: [source](https://github.com/ptitSeb/box64), PRs [3557](https://github.com/ptitSeb/box64/pull/3557), [4158](https://github.com/ptitSeb/box64/pull/4158), [4160](https://github.com/ptitSeb/box64/pull/4160), [4182](https://github.com/ptitSeb/box64/pull/4182), [4187](https://github.com/ptitSeb/box64/pull/4187), [4237](https://github.com/ptitSeb/box64/pull/4237), [4527](https://github.com/ptitSeb/box64/pull/4527)
- Hangover: [Page-Size wiki](https://github.com/AndreRH/hangover/wiki/Page-Size), issues [130](https://github.com/AndreRH/hangover/issues/130), [193](https://github.com/AndreRH/hangover/issues/193)

Kernels:
- Google P3S: [LPC 2026 talk](https://lpc.events/event/20/contributions/2630/), [slides](https://lpc.events/event/20/contributions/2630/attachments/2041/4583/Compatibility%20of%204KB%20Applications%20on%20Large%20Page-Sized%20Systems.pdf), [Gerrit topic p3s_v1](https://r.android.com/q/topic:p3s_v1)
- Linux [arch/arm64/kernel/signal.c](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/signal.c)
- XNU [xnu-12377.121.6](https://github.com/apple-oss-distributions/xnu/tree/xnu-12377.121.6): `bsd/kern/mach_loader.c`, `bsd/sys/spawn.h`, `osfmk/vm/pmap.h`, `tests/vm_spawn_tool.c`
- musl ([kraj/musl mirror](https://github.com/kraj/musl)): `src/env/__libc_start_main.c`, `src/internal/libc.h`, `src/conf/sysconf.c`

fwe: `crates/native/src/lib.rs` (`AT_PAGESZ`), `crates/kernel/src/signal.rs` (signal frame), `crates/kernel/src/procfs.rs`, [docs/linux-on-macos.md](../../docs/linux-on-macos.md), [ROADMAP.md](../../ROADMAP.md) (M6 PRs 5 and 6), [wine-on-apple-silicon.md](wine-on-apple-silicon.md).
