# Terminal emulators and the pty on macOS

A survey, made on 2026-11-20, of how fast terminal emulators on macOS read
a program's output, how the macOS pseudo-terminal (pty) behaves, and what
fwe's tty path can learn from both. Each fact has its source beside it.
"Not found" means the search turned up nothing reliable; nothing here is
guessed. Where a statement is a reading of source code rather than a quote,
it says so.

Terms used throughout:

- **pty**: a pair of devices. The terminal emulator holds the *master*
  (on macOS `/dev/ptmx`, `posix_openpt`); the program (a shell, `cat`,
  vim) holds the *slave* (`/dev/ttysNNN`) as its stdin, stdout and stderr.
  Bytes the program writes to the slave come out of the master; bytes the
  terminal writes to the master (key strokes) go through the *line
  discipline* (echo, Ctrl-C, line editing) to the slave.
- **output queue** (`t_outq`): the kernel buffer between a program's
  `write` on the slave and the terminal's `read` on the master.
- **wakeup**: the kernel telling a sleeping reader (in `read`, `poll`,
  `select` or `kevent`) that there is data.

## 1. The short version

1. **On macOS a read on the pty master never returns more than 1024
   bytes**, because the output queue is a fixed 1024-byte ring. kitty,
   Ghostty and iTerm2 each found this and each now reads in a loop to get
   past it. Ghostty measured 6,337 reads of exactly 1024 bytes for a
   6.49 MB file. Linux hands out about 4 KiB per read. (Section 3.1.)
2. **A writer is woken back and forth with the terminal about once per
   KiB.** When the queue is full the program sleeps until the terminal has
   drained it. Terminals that parse between reads stall the program.
   Ghostty gained 25–55% throughput (July 2026) and kitty gained 15–60%
   on macOS only (October 2026) by gathering reads. (Sections 2.1, 2.2.)
3. **Every `write` on a macOS pty wakes the reader at once**, in 100-byte
   steps (reading of XNU `ttwrite`). Linux instead queues the data and
   wakes the reader from a work item, which merges small writes. (Section 3.2.)
4. **Canonical-mode input is capped at 1024 bytes on macOS** (`MAX_INPUT`,
   `TTYHOG`), against 4096 on Linux. Pasted lines longer than that are cut
   short, with a bell. Multi-line input over about 1 KiB can block or garble
   (VS Code fixed this in March 2026). (Section 3.3.)
5. **On macOS, unread output can be lost when the slave closes**, and a
   master read after hang-up returns 0 (EOF) where Linux returns `EIO`.
   (Section 3.4.)
6. **Terminals avoid drawing each small write** by waiting a few
   milliseconds (kitty's `input_delay` 3 ms, WezTerm's 3 ms coalesce), by
   drawing at most once per screen refresh, and by honouring synchronized
   output (mode 2026). The timeouts differ: Alacritty 150 ms, Ghostty
   1 s, kitty 2 s. (Sections 2 and 4.)
7. **Reliable typing-latency numbers for macOS in 2025–2026 were not
   found.** The ranked lists online are undated blog posts with no stated
   method. (Section 5.)

## 2. The terminals

### 2.1 Ghostty

**Reading the pty.** Ghostty's main branch reads in two stages on two
threads (`src/termio/Exec.zig`, `ReadThread`,
https://github.com/ghostty-org/ghostty/blob/main/src/termio/Exec.zig):

- `io-gather` sets the master to `O_NONBLOCK` and reads in a loop into
  one of 4 rotating buffers of 64 KiB each (`buffer_count = 4`,
  `buffer_capacity = 64 * 1024`). It sleeps in `poll()` on the pty plus a
  quit pipe.
- `io-reader` takes each filled buffer, locks the terminal, parses the
  VT stream and schedules a render.
- A batch smaller than 1 KiB goes out on the first `EAGAIN`, with no added
  delay (interactive echo).
- A batch of 1 KiB or more means "the writer filled the kernel queue". The
  gather thread then retries an empty read up to 16 times
  (`bridge_spin_max = 16`, "~0.5us read syscalls"). After that it polls
  for 1 ms (`bridge_poll_timeout_ms = 1`), within a budget of 3 ms per
  batch (`gather_budget_ns`).
- It bridges like this only while the parser is busy. A self-pipe lets the
  parser cut the poll short once it goes idle.
- Both threads set macOS QoS `user_initiated`. The source says: "at default
  QoS the scheduler may place them on efficiency cores", worth "a 15%
  throughput difference" on an M4 Max.
- On Windows it is still a single blocking loop with a 1024-byte buffer.

The source comment states the macOS finding plainly: "I found on macOS that
the kernel tty output queue caps every read on the master at 1 KB no matter
how large the read buffer is", and the old loop meant "producers (e.g.
`cat`) stall".

**Measured gains** (M4 Max, macOS 26, timing `cat file > /dev/ttysN`):

- PR #13209, merged July 2026,
  https://github.com/ghostty-org/ghostty/pull/13209, commit `2f0e6659dd`:

  | stream | before | after |
  |---|---|---|
  | ascii.txt 6.5 MB | 91–92 MB/s | 114–123 MB/s (+25–30%) |
  | unicode.txt 8 MB | 116–117 MB/s | 180–183 MB/s (+55%) |
  | DOOM-Fire-Zig | 530 fps | 770 fps (+45%) |

  It also records "6,337 reads where every read was exactly 1024 bytes"
  for a 6.49 MB file read with a 64 KB buffer.
- PR #13237, https://github.com/ghostty-org/ghostty/pull/13237, commit
  `bb0ac4c723`, fixed a regression in #13209. A program that writes a frame
  and then waits for the answer to a cursor-position query (`CSI 6n`) was
  held back by the 1 ms bridge poll: "adding ~1.2ms to every round trip".
  After the fix, `fps -fire` at 80x24 went from 0.262 ms/frame (before
  #13209) to 0.234 ms. `cat` of 19.3 MB went from 0.204 s (95 MB/s) to
  0.082 s (236 MB/s).

**Parsing.** The parser looks for ESC 16 bytes at a time with NEON and
decodes UTF-8 with SIMD. ASCII parsing was "7.3x faster" on an M3 Max
(Devlog 006, 2024-02-12, https://mitchellh.com/writing/ghostty-devlog-006).

**Rendering.**

- Metal on macOS (`src/renderer/Metal.zig`), on its own renderer thread
  (`src/renderer/Thread.zig`).
- With vsync, the renderer "only draw[s] when we're forced to" outside the
  display link.
- `window-vsync` defaults to true "because out-of-sync rendering on macOS
  can cause kernel panics (macOS 14.4+)" (`src/config/Config.zig`,
  https://github.com/ghostty-org/ghostty/blob/main/src/config/Config.zig).

**Synchronized output.** Mode 2026 is reset by a timer after
`sync_reset_ms = 1000` (`src/termio/Thread.zig`,
https://github.com/ghostty-org/ghostty/blob/main/src/termio/Thread.zig).

**`cat` of a big file.**

- 2024: `cat japanese-bible.txt` (5.4 MB), mean of 10 runs, machine not
  stated (Devlog 006). Ghostty 73 ms, Alacritty 0.13.1 66 ms, Terminal.app
  (macOS 14.3) 124 ms, WezTerm 20240203 140 ms, kitty 0.32.1 392 ms (an
  unreleased SIMD branch: 103 ms), iTerm2 3.4.23 470 ms.
- 2026: 19.3 MB in 0.082 s, about 236 MB/s (PR #13237).

### 2.2 kitty

**Reading the pty.** One I/O thread serves every window
(`kitty/child-monitor.c`, `io_loop`,
https://github.com/kovidgoyal/kitty/blob/master/kitty/child-monitor.c):

- It calls `poll()` over all the children's masters plus a wakeup fd and
  a signal fd.
- Reads go straight into the parser's buffer, which is 1 MiB per window
  (`BUF_SZ (1024u * 1024u)` in `kitty/vt-parser.c`).
- On macOS only, `read_bytes()` keeps reading while each read returns a
  full 1024 bytes, up to 64 KiB (`PTY_READ_CHUNK 1024u`,
  `PTY_GATHER_MAX (64u * 1024u)`). Each read goes to the parser as soon as
  it completes. The source comment: "The macOS pty driver hands out data
  in chunks of at most 1024 bytes, so with a single read per poll() a
  child producing bulk output costs us a poll() and a wakeup of the I/O
  thread per kilobyte." On other systems: "Other platforms return more
  data in a single read()".
- This came from PR #10611 (closed 2026-10-06 by commit `5466034fcf`,
  "macOS: Improve throughput when input_delay=0",
  https://github.com/kovidgoyal/kitty/issues/10611). Its numbers (kitten
  `__benchmark__`, macOS arm64, `input_delay 0`, MB/s):

  | test | before | after |
  |---|---|---|
  | long escape codes | 193 | 310 |
  | images | 192 | 296 |
  | ASCII | 262 | 300 |

  The maintainer: Linux "typically returns 4KB chunks", and the first
  version of the patch "actually decreases throughput under Linux".

**Batching output to frames.** These are the option texts in
`kitty/options/definition.py`
(https://github.com/kovidgoyal/kitty/blob/master/kitty/options/definition.py):

- `input_delay` = 3 ms: "Delay before input from the program running in
  the terminal is processed". Since 2026-09-27 (commit `b0d3d1b4c0`) the
  delay "is also ignored when less than 1 KB of input is pending, such as
  when the program echoes typed characters, but at most once per delay
  period, so continuous streams of small writes are still coalesced".
- `repaint_delay` = 10 ms, about 100 FPS.
- `sync_to_monitor` = yes.
- Waking the main loop is described as "an expensive operation on some
  platforms, such as cocoa" (comment in `io_loop`).

**Rendering.** OpenGL, also on macOS (`kitty/gl.c`,
https://github.com/kovidgoyal/kitty/blob/master/kitty/gl.c).

**Synchronized output.** Rendering is paused for up to 2000 ms by default
(`if (for_in_ms <= 0) for_in_ms = 2000;` in `screen_pause_rendering`,
`kitty/screen.c`, https://github.com/kovidgoyal/kitty/blob/master/kitty/screen.c).

**Published numbers** (https://sw.kovidgoyal.net/kitty/performance/,
undated):

- Throughput on Linux/X11 with a Ryzen 7 PRO 5850U, in MB/s: kitty 0.33
  ASCII 121.8 / Unicode 105.0 / CSI 59.8 / images 251.6. Alacritty 0.13.1:
  43.1 / 46.5 / 32.5 / 94.1. WezTerm 20230712: 16.4 / 26.0 / 11.1 / 140.5.
  Rendering is off by default in this benchmark.
- Latency on macOS: "hardware-based measurement" puts kitty and
  Terminal.app sharing "the crown for best latency". No numbers are on
  the page.

### 2.3 Alacritty

**Reading the pty.** One PTY thread per window
(`alacritty_terminal/src/event_loop.rs`,
https://github.com/alacritty/alacritty/blob/master/alacritty_terminal/src/event_loop.rs):

- It waits with the `polling` crate (kqueue on macOS) in level-triggered
  mode (`PollMode::Level`).
- It reads into a 1 MiB buffer (`READ_BUFFER_SIZE: usize = 0x10_0000`).
- It parses while holding the terminal lock for at most 65,535 bytes
  (`MAX_LOCKED_READ`). It uses `try_lock_unfair`, so if the renderer holds
  the lock it keeps reading, and blocks only once 1 MiB is waiting unparsed.
- The master is set non-blocking (`alacritty_terminal/src/tty/unix.rs`).

**Synchronized output.** The `vte` crate holds up to 2 MiB
(`SYNC_BUFFER_SIZE = 0x20_0000`) for at most 150 ms
(`SYNC_UPDATE_TIMEOUT`, https://github.com/alacritty/vte/blob/master/src/ansi.rs).

**Rendering.** OpenGL. Damage tracking feeds `swap_buffers_with_damage`
only on Wayland EGL. On macOS the whole buffer is swapped
(`alacritty/src/display/mod.rs`, `swap_buffers`,
https://github.com/alacritty/alacritty/blob/master/alacritty/src/display/mod.rs).
Latest release: v0.17.0, 2026-04-06.

### 2.4 WezTerm

**Reading the pty** (`mux/src/lib.rs`,
https://github.com/wezterm/wezterm/blob/main/mux/src/lib.rs):

- One thread per pane does blocking reads into a 1 MiB buffer
  (`BUFSIZE`).
- It writes each chunk into a `socketpair`, whose send and receive buffers
  are set to 1 MiB.
- A second thread (`parse_buffered_data`) reads the socketpair, parses,
  and holds actions back for up to `mux_output_parser_coalesce_delay_ms`
  (default 3) while less than `mux_output_parser_buffer_size` (default
  128 KiB) has gathered. The config comment says this is "to increase the
  chances that we coalesce a full 'frame' from an unoptimized TUI program".
- During synchronized output (`?2026h`) it holds all actions until
  `?2026l` or a soft reset (`config/src/config.rs`).
- So each chunk costs one extra copy and two extra system calls (a
  `write` and a `read` on the socketpair). This is a reading of the code;
  no measurement was found.

**Rendering.** The `front_end` default is `OpenGL`; `WebGpu` (Metal on
macOS through wgpu) and `Software` can be chosen
(`config/src/frontend.rs`).

**Releases.** The last tagged release is 20240203-110809-5046fc22. The
main branch is active (commits on 2026-11-20).

### 2.5 iTerm2

**Reading the pty** (`sources/Tasks/TaskNotifier.m`, `PTYTask.m`,
https://github.com/gnachman/iTerm2/tree/master/sources/Tasks):

- One `TaskNotifier` thread calls `select()` over every session's fd,
  with a pipe to interrupt it. An advanced setting, `useTaskIOMonitors`,
  switches to GCD dispatch read sources instead
  (`sources/Channels/FileDescriptorMonitor.swift`).
- `processRead` reads at most 4 × 1024 bytes per wakeup (`MAXRW 1024`,
  `iterations = 4`). It stops at the first short read. The comment: "For
  some apparently undocumented reason, read() never returns more than 1024
  bytes (at least on OS 10.6)".
- A May 2025 comment: "I think what's happening is that the TTY driver
  has an internal buffer of 1024 bytes. Because token execution is slower
  than reading and parsing, we enter a backpressure situation."
- Reading pauses while the token executor is full
  (`TaskReadCapacity.swift`).

**Rendering.** Metal, since 3.2 (2018-08-07,
https://iterm2.com/downloads/stable/iTerm2-3_2_0.changelog).

**Numbers.** `cat` of 5.4 MB: 470 ms (iTerm2 3.4.23, Devlog 006, 2024).
For vtebench, see 2.7.

### 2.6 Warp

Warp's client has been open source since late April 2026 (AGPL,
https://www.warp.dev/blog/warp-is-now-open-source,
https://github.com/warpdotdev/warp).

**Reading the pty.** An Alacritty-derived loop
(`crates/warp_terminal/src/local_tty/event_loop.rs`,
https://github.com/warpdotdev/warp/blob/master/crates/warp_terminal/src/local_tty/event_loop.rs):

- It uses `mio` (kqueue on macOS) and drains until `WouldBlock`, since
  "we won't receive another until the operation would block".
- It reads into a 256 KiB buffer (`READ_BUFFER_SIZE: usize = 0x4_0000`)
  and holds the lock for at most 64 KiB (`MAX_LOCKED_READ = 0x1_0000`).
- It tracks how much output is held for synchronized output.

**Rendering.** A Metal renderer and a wgpu renderer
(`crates/warpui/src/platform/mac/rendering/{metal,wgpu}`). The 2021
article reported an "average time to redraw the screen ... 1.9 ms" and
">144fps" on 4K (https://www.warp.dev/blog/how-warp-works, 2021-07-12).

**Shell integration.** Shell hooks (precmd/preexec) send a DCS carrying
JSON, from which Warp builds its "blocks" (same article).

### 2.7 Terminal.app

- Closed source. How it reads the pty or renders: **not found**.
- macOS 26 added 24-bit colour and Powerline glyphs
  (https://www.macrumors.com/2025/06/16/apples-terminal-app-macos-tahoe/).
- `cat` of 5.4 MB: 124 ms (macOS 14.3, Devlog 006, 2024).

The only cross-terminal vtebench and termbench numbers that include
Terminal.app are Warp's, from around April 2022 (versions Warp
v0.2022.04.01, Terminal 2.11, iTerm2 3.4.15, Alacritty 0.10.1, WezTerm
20220319; https://docs.warp.dev/terminal/comparisons/performance).
vtebench, in milliseconds (lower is better):

| test | Warp | Terminal.app | iTerm2 | Alacritty | WezTerm |
|---|---|---|---|---|---|
| dense_cells | 43.88 | 24.91 | 144.84 | 7.25 | 28.15 |
| scrolling | 30.06 | 283.34 | 1257.57 | 31.75 | 687.77 |
| unicode | 66.47 | 34.45 | 93.01 | 16.78 | 1279.25 |

In termbench "small", Terminal.app took 453.99 s on FGPerChar (a colour
change on every character), against Alacritty's 0.28 s.

## 3. The macOS pty itself

All XNU references are to the `main` branch of
https://github.com/apple-oss-distributions/xnu, at commit `f6217f891ac0`
(tag xnu-12377.1.9, macOS 26, 2025-10-04). Linux references are to
https://github.com/torvalds/linux (master, 2026-11).

### 3.1 Buffer sizes

| What | macOS (XNU) | Linux |
|---|---|---|
| output queue (slave write → master read) | ring of `TTYCLSIZE 1024` bytes, allocated once in `ttymalloc` (`clalloc(&tp->t_outq, TTYCLSIZE, 0)`, `bsd/kern/tty.c`; `bsd/sys/tty.h`) | flip buffers of up to `TTYB_DEFAULT_MEM_LIMIT (640 * 1024UL)` per port (`drivers/tty/tty_buffer.c`), then the line discipline's `N_TTY_BUF_SIZE 4096` (`drivers/tty/n_tty.c`) |
| high/low water marks | `ttsetwater`: low = clamp(speed/20, 32, 256), high = clamp(low + speed/10, 100, 2048), rounded up to `CBSIZE` (48 on 64-bit: `CBLOCK 64` less a pointer and 8 quote bytes, `bsd/sys/param.h`). At 9600 baud (the pty default `TTYDEF_SPEED`) high = 1248; at 38400, 2064. Both are above the 1024-byte ring, so the ring's size is the real limit. | n/a (`pty_write_room` = flip space left) |
| one master `read` | at most what is queued, so ≤ 1024. Copied out 100 bytes at a time (`#define BUFSIZ 100`, `ptcread`, `bsd/kern/tty_dev.c`) | "typically 4KB" (kitty maintainer, kitty #10611) |
| one slave `write`, as the kernel processes it | in steps of `OBUFSIZ 100` bytes. Each step ends with `ttstart` → `ptsstart` → `ptcwakeup` (`selwakeup`, `wakeup`, `KNOTE`) (`ttwrite`, `bsd/kern/tty.c`; `tty_dev.c`) | in chunks of 2048 bytes (`chunk = 2048`, 65536 with `TTY_NO_WRITE_SPLIT`, `tty_write` in `drivers/tty/tty_io.c`); the reader is woken from a queued work item (`tty_flip_buffer_push` → `queue_work`) |
| input (master write → slave read) | `TTYHOG 1024` for raw plus canonical queues; `MAX_INPUT` is 1024. A master write blocks, or returns `EWOULDBLOCK`, at `TTYHOG - 2` (`ptcwrite`). Input is fed to the line discipline one byte at a time (`l_rint`). | `N_TTY_BUF_SIZE 4096`; a canonical line is at most 4095 bytes |
| number of ptys | `PTMX_MAX_DEFAULT 511` (512), hard limit 999 (`bsd/kern/tty_ptmx.c`; sysctl `kern.tty.ptmx_max`) | `/proc/sys/kernel/pty/max` |

Three independent confirmations of the 1024-byte master read: Ghostty's
measurement (6,337 reads of exactly 1024 bytes), the kitty source comment,
and iTerm2's comments (2.1, 2.2, 2.5). Other projects have hit the same
size:

- GCC's test suite: "on macOS ... this is 1024 bytes"
  (https://gcc.gnu.org/pipermail/gcc-bugs/2025-September/928186.html).
- Coder: a test hangs when more than 1024 bytes go unread
  (https://github.com/coder/coder/issues/2122).

### 3.2 Why throughput is lower than on Linux

This is a reading of the XNU and Linux source; the figures are from the
PRs cited.

- **The writer can run only 1 KiB ahead of the terminal.** Once the ring is
  full, `ttwrite` sleeps (`ttysleep(... "ttywri" ...)`) until the queue
  drains to the low-water mark. Each master read ends by calling the line
  discipline's `l_start`, which for the standard discipline is `ttwwakeup`
  (`bsd/kern/tty_conf.c`). `ttwwakeup` wakes the writer only once
  `t_outq.c_cc <= t_lowat`, and the low-water mark is 256 at both 9600 and
  38400 baud. A terminal that parses between reads leaves
  the writer asleep during the parse. Ghostty: "the child could never run
  more than 1 KiB ahead of us, so while we parsed the child (e.g. `cat`)
  sat blocked on a full kernel queue" (PR #13209). On Linux the writer can
  be 640 KiB ahead.
- **Wakeups per KiB.** Every 1 KiB costs the terminal a `poll` return and
  a `read`, and costs the writer a sleep and a wakeup. Ghostty measured
  that the writer "refills the drained kernel queue within a few
  microseconds, while a sleep and wakeup through poll costs several more".
  It also measured a "~10us cadence of the pty producer/consumer dance"
  (Exec.zig comments).
- **Each `write` wakes the reader at once.** It wakes again for each
  further 100 bytes (`ttstart` inside the `ttwrite` loop). Linux commits
  into the flip buffer and queues work (`tty_buffer_queue_work`), so
  several small writes made before the worker runs reach the reader as one
  wakeup.
- **Output post-processing.** With `OPOST` set, every chunk is scanned
  for special characters (`scanc` with `char_type`). Characters such as
  `\n` with `ONLCR` go one at a time through `ttyoutput`. With `OPOST`
  off, the whole chunk is copied at once (`ttwrite`).

The best measured macOS rates for bulk `cat` are about 236 MB/s (Ghostty,
M4 Max, PR #13237) and 300 MB/s ASCII (kitty's own benchmark, PR #10611).
A like-for-like Linux figure on the same hardware: **not found**.

### 3.3 Known quirks

**Long canonical input.**

- Above `MAX_INPUT` (1024) bytes in the raw plus canonical queues,
  further input is dropped. With `IMAXBEL` set (it is in macOS's
  `TTYDEF_IFLAG`) the terminal rings a bell (`ttyinput`, "Check for input
  buffer overflow").
- VS Code found that multi-line input over about 1 KiB, written to a
  shell whose line editor echoes, "corrupts the write". Python's
  synchronous `os.write()` "blocks when multiline input exceeds ~1024
  bytes" on macOS 14 and 15 but not on Linux
  (https://github.com/jcansdale/macos-pty-multiline-bug; Apple feedback
  FB22178840).
- VS Code now writes such input in 512-byte chunks with 5 ms pauses on
  macOS (PR #298993, merged 2026-03-10,
  https://github.com/microsoft/vscode/pull/298993).

**`O_NONBLOCK` on the slave.**

- `ttwrite` returns a short count, or `EWOULDBLOCK` if nothing was
  written, once the queue is over the high-water mark (`IO_NDELAY` path).
- With a 1 KiB queue, a program with non-blocking stdout on a tty gets
  `EAGAIN` after about 1 KiB on macOS, where Linux accepts hundreds of KiB
  first. This is a reading of the code; no bug report was found that names
  it.

**Writability readiness.** `kevent`/`select` report a slave writable only
when the queue is at or below the low-water mark and the line is connected
(`ptsd_kqops_common` EVFILT_WRITE, `ptsselect` FWRITE).

**Window size and `SIGWINCH`.** `TIOCSWINSZ` stores the size and signals
the foreground process group only if the size changed (`bcmp`, then
`tty_pgsignal_locked(tp, SIGWINCH, 1)`, `bsd/kern/tty.c`). A process
outside the foreground group is not told.

**Flow control.**

- macOS's default input flags include `IXON | IXANY`
  (`bsd/sys/ttydefaults.h`).
- Once Ctrl-S stops output (`TS_TTSTOP`), the master reports nothing
  readable, by `read`, `select` or `kevent` (`ptcread`, `ptcselect`,
  `ptmx_kqops_common`).

**`kqueue` and `poll` on ptys.**

- XNU now has dedicated kqueue filters for both ends:
  - `ptsd_kqops`: EVFILT_READ uses `ttnread`; EV_EOF is set when the tty
    is a zombie.
  - `ptmx_kqops`: EVFILT_READ fires when the output queue is non-empty
    and not stopped.
  - Both are chosen in `spec_kqfilter` via `CDEVSW_IS_PTS` and
    `CDEVSW_IS_PTC` (`bsd/miscfs/specfs/spec_vnops.c`).
- `poll()` is built on kqueue. Any fd whose kevent registration fails
  gets `POLLNVAL` (`bsd/kern/sys_generic.c`).
- The man page still says "The poll() system call currently does not
  support devices" (`bsd/man/man2/poll.2`, BUGS).
- Older software still works around this:
  - tmux sets `EVENT_NOKQUEUE` and `EVENT_NOPOLL` on macOS: "kqueue and
    poll are both completely broken and don't work on anything except
    socket file descriptors" (`osdep-darwin.c`,
    https://github.com/tmux/tmux/blob/master/osdep-darwin.c).
  - libuv tests each stream fd with a 1 ns kevent and, on failure, runs
    `select()` on a separate thread: "kqueue doesn't work with some files
    from /dev mount on osx" (`uv__stream_try_select`, `src/unix/stream.c`,
    https://github.com/libuv/libuv/blob/v1.x/src/unix/stream.c).
  - libvirt accepts `POLLNVAL` from macOS in its tests
    (https://listman.redhat.com/archives/libvir-list/2020-October/209897.html).
- Current Alacritty, Warp (kqueue) and Ghostty and kitty (`poll`) use
  these calls on the master without workarounds.

### 3.4 End of output: hang-up and lost data

- **EOF.** A master read after the slave side has gone returns 0 on macOS
  (`ptcread`: `if ((tp->t_state & TS_CONNECTED) == 0) goto out; /* EOF */`
  with no error). iTerm2's comment agrees: "A pty master reads 0 once its
  slave has no openers". Linux returns `EIO`. The Apple forum post below
  shows Linux reading all the data and then `err = 5` (EIO), and macOS
  reading 0 bytes.
- **Lost output.** If the child writes and exits before the terminal reads,
  the output can be gone:
  - Reported on macOS 10.15.7
    (https://developer.apple.com/forums/thread/663632, October 2020, no
    Apple reply).
  - Reproduced on macOS 13.2 and 14.7.2 (Ruby bug #20682,
    https://bugs.ruby-lang.org/issues/20682, closed 2025-02-28 by adding a
    `sleep 0.1` to its tests).
  - In XNU, closing the slave flushes both queues: `ttylclose` flushes at
    once if the close is non-blocking or the drain fails; `ttyclose` calls
    `ttyflush(tp, FREAD | FWRITE)`; `ptsclose` then calls `ptsstop`.
  - The known workaround is for the child to open and close `/dev/tty`
    before it exits, which makes the exit path drain the output.

## 4. Protocols that touch the pty path

**Synchronized output (mode 2026).**

- The spec is at
  https://gist.github.com/christianparpart/d8a62cc1ab659194337d73e399004036.
  It has moved to contour-terminal/vt-extensions; the gist was last
  active 2026-07-13.
- A program brackets a frame with `CSI ? 2026 h` (begin) and
  `CSI ? 2026 l` (end). The terminal keeps showing the old screen until the
  end.
- To ask for support, send DECRQM `CSI ? 2026 $ p`. The reply's value
  means: 0 not recognised, 1 set, 2 reset, 4 permanently reset (not
  supported). No reply also means not supported.
- The spec sets no timeout. Implementations: Alacritty 150 ms, Ghostty
  1000 ms, kitty 2000 ms, WezTerm until end or soft reset (Section 2).
- Listed as supporting it: WezTerm, iTerm2, kitty, Warp, Alacritty (since
  0.13.0), foot, Windows Terminal, Contour, mintty, Zellij and others.
  Ghostty supports it per its source; Terminal.app is not listed.

**kitty graphics protocol** (https://sw.kovidgoyal.net/kitty/graphics-protocol/):

- Image data can travel in the escape code itself (`t=d`: base64, chunks
  "no larger than 4096 bytes", `m=1` on every chunk but the last). It can
  also be named by path, so the pixels never cross the pty: `t=f` a file,
  `t=t` a temporary file whose path contains `tty-graphics-protocol`, or
  `t=s` a POSIX shared-memory object.
- Programs query support with `a=q` followed by `ESC [ c` (primary device
  attributes). A program waits for the replies, so every such query is a
  round trip through the pty.
- The cell size in pixels comes from `TIOCGWINSZ` `ws_xpixel` and
  `ws_ypixel`, or from `CSI 14 t`. "Some terminals return 0".
- Ghostty also implements the protocol (`src/terminal/kitty/graphics*.zig`,
  https://github.com/ghostty-org/ghostty/tree/main/src/terminal/kitty).

**Shell integration.**

- kitty injects scripts (zsh via `ZDOTDIR`, fish via `XDG_DATA_DIRS`,
  bash via `ENV` in POSIX mode). The shell then writes OSC 133 prompt
  marks (`\e]133;A\a`, `C;cmdline=…`, `D;<status>`), OSC 7 for the current
  directory and OSC 2 for titles. kitty-specific data goes in chunked DCS
  `\eP@kitty-…` (https://sw.kovidgoyal.net/kitty/shell-integration/).
- kitty erases the prompt on resize and lets the shell redraw it.
- Ghostty injects for bash, elvish, fish, nushell and zsh, but not for
  macOS's `/bin/bash` (https://ghostty.org/docs/features/shell-integration).
- All of this is extra bytes in the output stream plus `SIGWINCH`-driven
  redraws; none of it changes the pty itself.

## 5. Input latency

No rigorous macOS study dated 2025 or 2026 was found. What exists:

- **Luke Harris, 2022-07-06** (https://www.lkhrs.com/blog/terminal-latency/).
  Method: a slow-motion phone camera ("Is It Snappy") on an M1 Pro running
  macOS 12.4, with 60 Hz 4K displays. Results in ms: kitty (tuned) 29.2,
  kitty 37.5, Terminal.app 45.4, WezTerm 45.8, Alacritty 57.9, iTerm2 GPU
  62.5, iTerm2 87.5. The author says the data "is not accurate".
- **kitty's performance page** (undated): on macOS, hardware measurement
  puts kitty and Terminal.app equal best. No numbers.
- **beuke.org, 2024-03-16** (https://beuke.org/terminal-latency/). Linux
  only (Xorg, Ryzen 4750U), Typometer, averages in ms: xterm 5.3,
  Alacritty 6.9, kitty-tuned 10.7, kitty 23.8, WezTerm 26.1. Not macOS.
- **vizenc/terminal-benchmark** (https://github.com/vizenc/terminal-benchmark).
  Linux Wayland, undated. Input latency: Alacritty 16.7 ms, kitty 18.3,
  Ghostty 38.3. `cat` of 11 MB: about 400 ms for Alacritty, kitty and
  Ghostty, 1246 ms for WezTerm.
- **2026 "best terminal for Mac" posts** (for example
  https://dev.to/vibehackers/best-terminal-for-mac-in-2026-ghostty-kitty-wezterm-alacritty-warp-more-4pe6)
  give 1–15 ms figures with no stated method. Not reliable.

Settings that trade latency for CPU:

- kitty: `input_delay 0`, `repaint_delay 2`, `sync_to_monitor no`
  (kitty performance page).
- Ghostty: `window-vsync = false`, which on macOS 14.4 and later risks a
  kernel panic (Ghostty config).

## 6. Why many small writes are slow, and what is done about it

**Costs per write**, on macOS:

1. The `write` system call itself.
2. In the kernel, under the tty lock: copying, the `OPOST` scan, and
   queueing.
3. A wakeup of the terminal's reader for each write, and again for each
   further 100 bytes (3.2).
4. On the terminal's side: return from `poll`/`kevent`, then a `read`.
   Ghostty measured about 0.5 µs per `read` and "several more" µs for a
   sleep and wakeup through `poll`.
5. Taking the terminal-state lock, parsing, and scheduling a render.
   Ghostty: in the old loop, "all per-call overhead (terminal lock, render
   wakeup, cursor timestamp) was paid per kilobyte of bulk output"
   (PR #13209).

If the terminal is faster than the program, every write becomes its own
wakeup and its own small read.

**What programs do.**

- C stdio buffers output, line by line when stdout is a terminal: "a stream
  connected to an interactive device such as a terminal is initially line
  buffered" (glibc manual,
  https://www.gnu.org/software/libc/manual/html_node/Buffering-Concepts.html).
  A program printing a line at a time makes one `write` per line.
- Full-screen programs build a frame and write it in one go, and bracket
  it with synchronized output (Section 4).

**What terminals do.**

- Read more per wakeup: Ghostty's gather thread, kitty's macOS loop,
  iTerm2's 4 × 1024 reads.
- Delay waking the parser or renderer: kitty `input_delay` 3 ms (none for
  under 1 KB, at most once per delay); WezTerm 3 ms coalescing.
- Draw at most once per frame: vsync in Ghostty and kitty; kitty's
  `repaint_delay` 10 ms.
- Hold drawing during synchronized output.
- Keep parsing apart from reading, so the kernel queue keeps draining:
  Ghostty's two stages, WezTerm's two threads.

**What the kernel does.** Linux merges writes through its flip-buffer work
queue, and lets the writer run up to 640 KiB ahead. macOS does neither
(3.1, 3.2).

**The cost of batching.** Ghostty's regression (#13237) shows that holding
output back hurts any program that writes a query and waits for the reply
(`CSI 6n`, DA1, DECRQM, kitty `a=q`). The hold-back then shows up as
latency on every round trip: "~1.2ms" in that case.

## 7. What fwe can take from these

fwe today:

- The guest's terminal is the host's. A guest `write` to a tty becomes one
  host `write`, after about a dozen in-process checks for other kinds of fd
  (`crates/kernel/src/lib.rs`, the `n::WRITE` arm: `specialfd`,
  `specialwrite`, `netlink`, `seqpacket`, `net::corked`,
  `memfd::grow_refused`, `bpf`, `tmpfs::room`, `fdstate::capped_write`,
  `pipelock::whole_write`), followed by `linux_result`'s hooks
  (`inotify::after_io`, `exclusive::wrote`, `fdmarks`, `net`).
- `TCGETS` is one host `tcgetattr`; `TCSETS`, `TCSETSW` and `TCSETSF` are
  one host `tcsetattr`.
- `TIOCGWINSZ` and `TIOCSWINSZ` pass through.
- `/dev/ptmx` is a host `posix_openpt` (`crates/kernel/src/term.rs`,
  `crates/kernel/src/syscalls.rs` `sys_ioctl`, `crates/kernel/src/pty.rs`).

So fwe adds only its own per-system-call cost to each terminal operation;
the macOS limits above apply to fwe exactly as to a native macOS program.
The ideas below are ordered by how safe they are. Per AGENTS.md, any of
them that is meant to change speed needs, built before the change:

- counters: tty writes, a histogram of bytes per write, time in the host
  `write`, and `TCGETS` and `TIOCGWINSZ` calls per second;
- a micro benchmark: 1-, 64- and 4096-byte writes to a pty whose master is
  drained by a reader thread, natively and under fwe;
- macro benchmarks: `cat` of a 20 MB file and `seq 1 1000000` into a pty
  drained the way Ghostty measures it (`cat file > /dev/ttysN`).

### 7.1 Safe, low gain or correctness only

**a. Translate the master's EOF.**
- What: a read on a guest `/dev/ptmx` master that returns 0 on macOS could
  return `EIO`, as Linux does once the slave is gone and the queue is
  empty.
- Source: 3.4 (`ptcread`; Apple forum thread 663632).
- Risk: low. It must apply only to master fds fwe opened, and only to a
  0-byte read with a non-zero count. Today fwe does not appear to translate
  it (no such case in `pty.rs`); worth confirming with a guest test that
  runs `script` or Python's `pty`.

**b. Document the macOS limits a guest can see.**
- What, in `docs/architecture.md` limitations and the terminals section
  of `docs/linux-on-macos.md`:
  - canonical lines are capped at 1024 bytes, not 4095 (3.3);
  - a non-blocking tty gives `EAGAIN` after about 1 KiB (3.3);
  - unread pty output can be discarded when the slave closes (3.4).
- Risk: none. These come from the host kernel and fwe cannot lift them
  without a line discipline of its own.

**c. Pass bytes through untouched.**
- What: fwe already never splits, merges or reorders a guest's write, and
  never reads its escape sequences. Keep it that way, so synchronized
  output (`?2026h` … `?2026l`), DECRQM, `CSI 6n` and kitty graphics
  queries behave exactly as natively.
- Source: Section 4; Ghostty #13237.
- Risk: none.

**d. Leave the termios speed alone.**
- What: fwe's `TCSETS` writes 38400 baud. In XNU that only moves the water
  marks (high water 2064, low water 256), and the 1024-byte ring caps the
  queue either way, so it has no throughput effect.
- Source: `ttsetwater`, 3.1.
- Risk: none. Nothing to change.

### 7.2 Possible, measure first

**e. A short path for writes to a terminal.**
- What: a guest write runs through the fd-kind checks listed above before
  the host `write`. A per-fd "is a terminal" mark, set when the fd is
  opened or inherited (a `TCGETS` that succeeds, or `S_ISCHR` plus
  `isatty` once), could send tty writes straight to the host `write`.
  This needs a check first: does any of those checks take a lock or make a
  host call for a tty fd? (`memfd::grow_refused` calls `fstat` and
  `fcntl`, but only once a sealed memfd exists.)
- Source: the per-write costs in Section 6. This is the only part of the
  per-write cost that is fwe's own.
- Risks:
  - Skipping a check that does apply to a terminal (for example, `inotify`
    modify events on `/dev/pts/N`, if Linux raises them).
  - A stale mark after `dup2` or `close` reuses the fd number. The mark
    must live in the same fd table that those calls already update.
- Gain: worth exactly the time those checks take. The micro benchmark of
  1-byte writes shows it directly.

**f. Cache `TIOCGWINSZ`.**
- What: answer it from fwe's own copy, refreshed when the host
  `SIGWINCH` arrives.
- Source: `TIOCSWINSZ` signals only the foreground process group and only
  on a change (3.3).
- Risks:
  - A process in a background group, or one that is not in the tty's
    session, never gets `SIGWINCH`, so its cached size goes stale.
  - fwe would have to catch `SIGWINCH` even when the guest leaves it at
    the default (today the host default, ignore, stays in place).
  - Another fwe process cannot see the cache.
- Gain: programs ask on start-up and on `SIGWINCH`, so a host `ioctl` of
  about a microsecond is rarely on a hot path. Not worth it unless the
  counters show a program asking per line.

**g. Cache `TCGETS`.**
- What: answer from a cached copy (glibc's `isatty` is a `TCGETS`).
- Source: none of the terminals do this. It is listed because the task
  asked.
- Risks: termios is shared by every process on the tty. The shell, `stty`
  in another process, a child, or the terminal itself (via the master, for
  example `EXTPROC`) can change it, and macOS has no notice or generation
  number to invalidate a cache. A stale `ICANON` or `ECHO` would break line
  editing, password prompts and job control.
- Recommendation: do not cache. At most, skip re-translating when the
  guest calls `TCGETS` twice in a row with nothing between, which saves
  almost nothing.

### 7.3 Faster than native, with real risk: merge a guest's small writes

**h. Write-behind for tty fds.**
- What: copy small consecutive `write`s to the same tty into a per-thread
  buffer and send them as one host `write`. This is what Linux's flip
  buffer achieves inside its kernel (3.2), and it would cut the macOS
  per-write wakeups (6). The writer itself is unchanged.
- Rules it would need:
  - Flush before any other system call that touches a terminal or can
    block or be observed: any `read`, `poll`, `select`, `epoll_wait`,
    `ioctl` (`TCSETSW` drains, `TIOCGWINSZ`), `fsync`, `close`, `dup`,
    `fork`, `exec`, `exit`, `nanosleep`, `futex` wait, and any signal
    delivery.
  - Flush when the buffer reaches 1 KiB (the host queue size) and after
    a short time bound. Ghostty's numbers suggest well under 1 ms; any
    hold-back adds directly to query round trips (#13237).
  - Never buffer a non-blocking fd. `EAGAIN` and short counts must come
    from the host at the moment of the call.
  - Never buffer when `TOSTOP` is set and the process is in a background
    group. `SIGTTOU` must arrive at the `write`.
- Risks:
  - Ordering against other processes writing to the same terminal: a
    parent shell, a sibling job, `stderr` from a child that inherited
    the fd. A buffered write would land after output that was really
    later.
  - `stdout` and `stderr` going to the same tty in the same process must
    stay in order, so the buffer must be per terminal, not per fd.
  - The `write` return value claims success before the host accepted the
    bytes. A hang-up (`EIO`) or a full non-blocking queue would be found
    later, at the flush.
  - Echo: the line discipline echoes input into the same output queue,
    so held program output would appear after newer echo.
  - A crash or `SIGKILL` loses buffered bytes that Linux would already
    have queued in the kernel.
- Source: Linux `tty_buffer.c`; Ghostty #13209 and #13237; kitty
  `input_delay`.
- Recommendation: build the counters and benchmarks first. Most Linux
  programs already buffer through stdio, so the gain may be small. If a
  common program (a compiler printing progress, `make -j`, `ninja`,
  `cargo`, a Python `print` loop) shows thousands of tiny tty writes a
  second, prototype it behind those benchmarks. Otherwise leave it.

### 7.4 Not for fwe

- **Reading the master in a loop, gather threads, QoS.** These live on the
  terminal's side. A guest terminal emulator running under fwe (for
  example a Linux `tmux`, `screen` or `script`) would make the same
  1024-byte reads; its own loop is the guest's business.
- **Merging input.** VS Code's 512-byte chunking is for a program writing
  keystrokes into the master. fwe does not sit there for the host
  terminal.
