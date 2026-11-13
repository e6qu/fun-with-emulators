//! A software stand-in for Hypervisor.framework (`fwe --hv-standin`): the
//! calls the backend makes ([`super::ffi`]) carried out by Unicorn, QEMU's
//! CPU emulator as a library, loaded with `dlopen` only in this mode.
//!
//! It exists so the VM backend can be developed and tested without a real
//! VM: misusing the framework can bring the machine down (see the safety
//! rules in `docs/hypervisor.md`). It can never prove the real backend
//! works — only the real framework on real hardware can — so VM changes
//! still run there now and then.
//!
//! What it models, as the backend sees it:
//!
//! - **One VM per process, one vCPU per thread.** `hv_vm_create` twice is
//!   `HV_BUSY`; a vCPU is used only from the thread that made it, and
//!   `hv_vm_destroy` with a vCPU alive fails.
//! - **Stage 2 is the map calls.** Guest-physical memory is exactly what
//!   `hv_vm_map` mapped, with its flags; an access to anything else stops
//!   the vCPU with a stage-2 abort, as the framework reports it. Mapping
//!   asks the host memory behind it to be mapped, page-aligned (16 KiB),
//!   and able to become readable and writable: the real framework mapped
//!   memory whose most was RWX or RW, whatever the flags, but refused a
//!   vfork child's code, which could only ever be read (an inferred rule,
//!   to be confirmed on real hardware).
//! - **Stage 1 is fwe's own tables**, walked as the hardware walks them
//!   and cached until fwe's TLB stub runs; only what they let EL0 touch is
//!   mapped for the emulated CPU.
//! - **EL0 exceptions go through the vector to `hvc`**: an `svc`, `brk`,
//!   undefined instruction, alignment fault or trapped system instruction
//!   sets `ESR_EL1`/`ELR_EL1`/`SPSR_EL1`/`FAR_EL1` and exits with the `hvc`
//!   syndrome, as fwe's vector makes the real one do. A read of
//!   `CNTPCT_EL0` and `wfi`/`wfe` exit directly, as under the framework.
//! - **System registers EL0 may use** behave as on the host: `CNTFRQ_EL0`
//!   is the host's frequency and `CNTVCT_EL0` the host counter less the
//!   vCPU's offset; `CTR_EL0` is Apple Silicon's value (as the native
//!   backend reports it) and `DCZID_EL0` QEMU's 64-byte block, as Apple's.
//! - **`hv_vcpus_exit`** stops a running vCPU, or makes its next run return
//!   at once, from any thread or signal handler.
//!
//! `FWE_STANDIN_DEBUG=1` reports every exception and exit it models.
//!
//! Every rule the backend must keep that the stand-in can see is checked:
//! a break prints a line starting `fwe hv stand-in: VIOLATION:` and the
//! tests fail on it. A process that ends, by any means, with its VM alive
//! is caught by a watcher process started with the VM (`fwe
//! --hv-standin-watch`), which sees the process's end of a pipe close.
//!
//! Only one vCPU emulates at a time (a fair lock, handed on at the next
//! block whenever another vCPU waits): Unicorn instances are independent
//! CPUs, and running one at a time keeps the guest's atomics atomic.
//!
//! Each Unicorn engine is driven only by its own thread: mapping changes
//! are logged and applied by each vCPU before it next emulates, and a stop
//! is a flag its block hook acts on. Unicorn's API is not safe to call on
//! an engine another thread is running, `uc_emu_stop` included, though its
//! documentation suggests it: on Apple Silicon every call begins and ends
//! with unsynchronised updates of the engine's JIT bookkeeping
//! (`save_jit_state`/`restore_jit_state`: `nested`, `current_executable`),
//! which the emulating thread updates too on each register access from a
//! hook, and from which it re-applies the JIT region's write protection
//! after each hook. Stops and mapping changes from other threads corrupted
//! guest state (a register update lost about once in ten runs of a
//! threaded test); confined to their own threads, none in 300. The block
//! hook costs about half the emulation speed in tight loops.
//!
//! Not modelled: the virtual
//! timer, the exact fault address of an alignment fault outside the
//! exclusive and atomic instructions, stack-pointer alignment checks, and
//! code another vCPU writes without a mapping change (each emulated CPU
//! sees its own writes to code, and every mapping change discards
//! translated code).

#![allow(non_upper_case_globals)]

use super::ffi::*;
use std::collections::{BTreeMap, VecDeque};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, Ordering::SeqCst};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

// --- Whether it is in use -------------------------------------------------

static ON: AtomicBool = AtomicBool::new(false);

/// Use the stand-in for every framework call from now on. Called at
/// startup, before any VM exists.
pub fn enable() {
    ON.store(true, SeqCst);
}

/// The stand-in is in use (`--hv-standin`).
#[inline]
pub fn active() -> bool {
    ON.load(SeqCst)
}

// --- Framework return codes -----------------------------------------------

const HV_SUCCESS: hv_return_t = 0;
const HV_ERROR: hv_return_t = 0xfae9_4001_u32 as i32;
const HV_BUSY: hv_return_t = 0xfae9_4002_u32 as i32;
const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003_u32 as i32;
const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005_u32 as i32;

// --- Unicorn ----------------------------------------------------------------

type Uc = *mut c_void;

const UC_ARCH_ARM64: c_int = 2;
const UC_MODE_ARM: c_int = 0;
const UC_CPU_ARM64_MAX: c_int = 3;
const UC_CTL_CPU_MODEL_W: u32 = 0x4400_0007;
const UC_CTL_TLB_TYPE_W: u32 = 0x4400_000c;
const UC_CTL_TLB_FLUSH_W: u32 = 0x4000_000b;
const UC_CTL_TB_FLUSH_W: u32 = 0x4000_000a;
const UC_TLB_VIRTUAL: c_int = 1;

const UC_HOOK_INTR: c_int = 1;
const UC_HOOK_INSN: c_int = 2;
const UC_HOOK_BLOCK: c_int = 8;
const UC_HOOK_MEM_UNMAPPED: c_int = 112;
const UC_HOOK_MEM_PROT: c_int = 896;
const UC_HOOK_TLB_FILL: c_int = 131_072;

const UC_MEM_WRITE_UNMAPPED: c_int = 20;
const UC_MEM_FETCH_UNMAPPED: c_int = 21;
const UC_MEM_WRITE_PROT: c_int = 22;
const UC_MEM_FETCH_PROT: c_int = 24;

const UC_PROT_READ: u32 = 1;
const UC_PROT_WRITE: u32 = 2;
const UC_PROT_EXEC: u32 = 4;

const UC_ARM64_INS_MRS: c_int = 1;
const UC_ARM64_INS_MSR: c_int = 2;
const UC_ARM64_INS_SYS: c_int = 3;
const UC_ARM64_INS_SYSL: c_int = 4;

const R_X0: c_int = 199; // X0..X28 are consecutive
const R_X29: c_int = 1;
const R_X30: c_int = 2;
const R_SP: c_int = 4;
const R_Q0: c_int = 104; // Q0..Q31 are consecutive
const R_PC: c_int = 260;
const R_TPIDR_EL0: c_int = 262;
const R_PSTATE: c_int = 265;
const R_CPACR_EL1: c_int = 261;
const R_FPCR: c_int = 291;
const R_FPSR: c_int = 292;
const R_CP_REG: c_int = 290;

/// QEMU's exception numbers, as Unicorn's interrupt hook reports them.
const EXCP_UDEF: u32 = 1;
const EXCP_SWI: u32 = 2;
const EXCP_PREFETCH_ABORT: u32 = 3;
const EXCP_DATA_ABORT: u32 = 4;
const EXCP_BKPT: u32 = 7;

/// Where emulation stops by itself: Unicorn's usual 0 (it translates code
/// at this address when the CPU halts, so it must be one it can fetch from
/// or fault on cleanly). A guest that jumps there gets the instruction abort
/// the VM gives it, as page 0 is never mapped.
const UNTIL: u64 = 0;

#[repr(C)]
struct CpReg {
    crn: u32,
    crm: u32,
    op0: u32,
    op1: u32,
    op2: u32,
    val: u64,
}

#[repr(C)]
struct TlbEntry {
    paddr: u64,
    perms: u32,
}

type OpenFn = unsafe extern "C" fn(c_int, c_int, *mut Uc) -> c_int;
type CtlFn = unsafe extern "C" fn(Uc, u32, ...) -> c_int;
type RegReadFn = unsafe extern "C" fn(Uc, c_int, *mut c_void) -> c_int;
type RegWriteFn = unsafe extern "C" fn(Uc, c_int, *const c_void) -> c_int;
type MemMapPtrFn = unsafe extern "C" fn(Uc, u64, usize, u32, *mut c_void) -> c_int;
type MemUnmapFn = unsafe extern "C" fn(Uc, u64, usize) -> c_int;
type HookAddFn =
    unsafe extern "C" fn(Uc, *mut usize, c_int, *mut c_void, *mut c_void, u64, u64, ...) -> c_int;
type EmuStartFn = unsafe extern "C" fn(Uc, u64, u64, u64, usize) -> c_int;
type EmuStopFn = unsafe extern "C" fn(Uc) -> c_int;

type StrerrorFn = unsafe extern "C" fn(c_int) -> *const c_char;

struct Api {
    open: OpenFn,
    ctl: CtlFn,
    reg_read: RegReadFn,
    reg_write: RegWriteFn,
    mem_map_ptr: MemMapPtrFn,
    mem_unmap: MemUnmapFn,
    hook_add: HookAddFn,
    emu_start: EmuStartFn,
    emu_stop: EmuStopFn,
    strerror: StrerrorFn,
}

/// Where Unicorn is looked for: `FWE_UNICORN`, then Homebrew's places.
const LIBRARIES: &[&str] = &[
    "/opt/homebrew/lib/libunicorn.2.dylib",
    "/usr/local/lib/libunicorn.2.dylib",
    "libunicorn.2.dylib",
];

fn api() -> &'static Api {
    static API: OnceLock<Api> = OnceLock::new();
    API.get_or_init(|| match load() {
        Ok(a) => a,
        Err(e) => die(&format!("{e} (the stand-in needs Unicorn: `brew install unicorn`)")),
    })
}

fn load() -> Result<Api, String> {
    let mut names: Vec<String> = std::env::var("FWE_UNICORN").into_iter().collect();
    names.extend(LIBRARIES.iter().map(|s| s.to_string()));
    let handle = names
        .iter()
        .find_map(|n| {
            let c = std::ffi::CString::new(n.as_str()).ok()?;
            // SAFETY: loading a library by a NUL-terminated name.
            let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            (!h.is_null()).then_some(h)
        })
        .ok_or_else(|| "Unicorn could not be loaded".to_string())?;
    let sym = |name: &str| -> Result<*mut c_void, String> {
        let c = std::ffi::CString::new(name).unwrap();
        // SAFETY: looking up a symbol in the library just loaded.
        let p = unsafe { libc::dlsym(handle, c.as_ptr()) };
        if p.is_null() { Err(format!("Unicorn has no {name}")) } else { Ok(p) }
    };
    // SAFETY: each symbol has the C signature of the field it fills
    // (unicorn.h, Unicorn 2).
    unsafe {
        Ok(Api {
            open: std::mem::transmute::<*mut c_void, OpenFn>(sym("uc_open")?),
            ctl: std::mem::transmute::<*mut c_void, CtlFn>(sym("uc_ctl")?),
            reg_read: std::mem::transmute::<*mut c_void, RegReadFn>(sym("uc_reg_read")?),
            reg_write: std::mem::transmute::<*mut c_void, RegWriteFn>(sym("uc_reg_write")?),
            mem_map_ptr: std::mem::transmute::<*mut c_void, MemMapPtrFn>(sym("uc_mem_map_ptr")?),
            mem_unmap: std::mem::transmute::<*mut c_void, MemUnmapFn>(sym("uc_mem_unmap")?),
            hook_add: std::mem::transmute::<*mut c_void, HookAddFn>(sym("uc_hook_add")?),
            emu_start: std::mem::transmute::<*mut c_void, EmuStartFn>(sym("uc_emu_start")?),
            emu_stop: std::mem::transmute::<*mut c_void, EmuStopFn>(sym("uc_emu_stop")?),
            strerror: std::mem::transmute::<*mut c_void, StrerrorFn>(sym("uc_strerror")?),
        })
    }
}

fn uc_error(rc: c_int) -> String {
    // SAFETY: Unicorn returns a static string for every code.
    let s = unsafe { std::ffi::CStr::from_ptr((api().strerror)(rc)) };
    s.to_string_lossy().into_owned()
}

// --- Diagnostics ------------------------------------------------------------

/// Report a broken rule. Async-signal-safe.
fn violation(msg: &str) {
    VIOLATIONS.fetch_add(1, SeqCst);
    say("VIOLATION: ", msg);
}

/// Broken rules seen so far in this process (for the stand-in's own tests).
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// A note that is not a broken rule. Async-signal-safe.
fn note(msg: &str) {
    say("", msg);
}

fn say(kind: &str, msg: &str) {
    let mut buf = [0u8; 512];
    let mut n = 0;
    // The process, as several (a fork's parent and child) may be writing.
    let mut pid = [0u8; 12];
    // SAFETY: plain host call.
    let mut v = unsafe { libc::getpid() } as u32;
    let mut i = pid.len();
    loop {
        i -= 1;
        pid[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let pid = std::str::from_utf8(&pid[i..]).unwrap_or("");
    for part in ["fwe hv stand-in: ", kind, msg, " [", pid, "]", "\n"] {
        for &b in part.as_bytes() {
            if n < buf.len() - 1 {
                buf[n] = b;
                n += 1;
            }
        }
    }
    if buf[n - 1] != b'\n' {
        buf[n] = b'\n';
        n += 1;
    }
    // SAFETY: writing a diagnostic to standard error.
    unsafe { libc::write(2, buf.as_ptr().cast(), n) };
}

fn die(msg: &str) -> ! {
    say("", msg);
    // SAFETY: ending the process; no real VM exists in this mode.
    unsafe { libc::_exit(127) }
}

// --- The VM -----------------------------------------------------------------

/// A stage-2 mapping: guest-physical `[ipa, end)` backed by host memory.
#[derive(Clone, Copy, Debug)]
struct Mapping {
    end: u64,
    host: u64,
    flags: u64,
}

struct Vm {
    ipa_bits: u32,
    /// Stage 2, by start address.
    maps: BTreeMap<u64, Mapping>,
    /// Stage 2 as it was when a vCPU first ran: it may not change after
    /// (shared segments come and go beside it).
    first_run: Option<Vec<(u64, u64)>>,
    /// The host memory behind each mapping: `(start, end, VM object)` of
    /// each host region, so a replacement is seen.
    objects: Vec<(u64, u64, u32)>,
    /// Runs since the last check of `objects`.
    runs: u64,
}

/// Lock order: `VM`, then `TURN`, then `LOG`, then a vCPU's `engine`.
static VM: Mutex<Option<Vm>> = Mutex::new(None);
static VM_LIVE: AtomicBool = AtomicBool::new(false);
/// The watcher's pipe: written `C` when the VM is created and `D` when it
/// is destroyed.
static WATCH_FD: AtomicI32 = AtomicI32::new(-1);

fn vm() -> MutexGuard<'static, Option<Vm>> {
    VM.lock().unwrap_or_else(|e| e.into_inner())
}

const PAGE: u64 = 16 << 10;

// --- vCPUs ------------------------------------------------------------------

const MAX_VCPUS: usize = 256;

struct Vcpu {
    /// The Unicorn instance; used under `engine`, or by its `emu_stop`.
    uc: Uc,
    engine: Mutex<Engine>,
    exit: *mut hv_vcpu_exit_t,
    owner: libc::pthread_t,
    /// `hv_vcpus_exit` asked for a stop.
    cancel: AtomicBool,
    /// Another wants the turn: stop at the next block.
    yield_now: AtomicBool,
    /// `TTBR0_EL1`, for walks from hooks.
    ttbr0: AtomicU64,
    /// Code pages the vCPU has fetched from that are BTI guarded (page
    /// numbers), so only blocks there pay for the BTI check.
    guarded: Mutex<std::collections::BTreeSet<u64>>,
    any_guarded: AtomicBool,
    /// The block hook ended the last emulation (a yield or a cancel).
    hook_stopped: AtomicBool,
    /// Inside `uc_emu_start`.
    running: AtomicBool,
    vtimer_offset: AtomicU64,
}

/// What only the owner thread (or a mapping change, under the turn) uses.
struct Engine {
    /// Stage 2 has been applied to this CPU.
    synced: bool,
    /// How much of the mapping log it has applied (an absolute index).
    applied: usize,
    /// The EL1 registers the vector would see, and the others fwe sets.
    esr: u64,
    elr: u64,
    spsr: u64,
    far: u64,
    sys: BTreeMap<hv_sys_reg_t, u64>,
    /// What a hook decided during the last emulation.
    event: Option<Event>,
    /// `CPSR` set to an EL1 mode: the vCPU resumes in fwe's EL1 code.
    el1: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
enum Event {
    /// The guest took an exception to EL1: the vector's `hvc` exits.
    El1 { esr: u64, elr: u64, far: u64 },
    /// A stage-2 abort or trapped access exits straight to the host, with
    /// the vCPU's pc at `pc`.
    Direct { syndrome: u64, va: u64, pc: u64 },
}

// SAFETY: a Vcpu's raw pointers are owned by it and used by its owner
// thread, or under its `engine` lock, or (`uc_emu_stop`) from anywhere, which
// Unicorn allows.
unsafe impl Send for Vcpu {}
// SAFETY: as for Send; shared use goes through atomics and the lock.
unsafe impl Sync for Vcpu {}

static VCPUS: [AtomicPtr<Vcpu>; MAX_VCPUS] =
    [const { AtomicPtr::new(std::ptr::null_mut()) }; MAX_VCPUS];

fn vcpu(id: hv_vcpu_t) -> Option<&'static Vcpu> {
    let p = VCPUS.get(id as usize)?.load(SeqCst);
    // SAFETY: a vCPU, once registered, is never freed.
    (!p.is_null()).then(|| unsafe { &*p })
}

/// The vCPU, used from its own thread (the framework's rule).
fn own(id: hv_vcpu_t, what: &str) -> Option<&'static Vcpu> {
    let v = vcpu(id);
    match v {
        None => violation(&format!("{what} on vCPU {id}, which does not exist")),
        // SAFETY: plain host call.
        Some(v) if unsafe { libc::pthread_equal(v.owner, libc::pthread_self()) } == 0 => {
            violation(&format!("{what} on vCPU {id} from a thread other than its own"));
            return None;
        }
        _ => {}
    }
    v
}

fn engine(v: &Vcpu) -> MutexGuard<'_, Engine> {
    v.engine.lock().unwrap_or_else(|e| e.into_inner())
}

fn read(uc: Uc, reg: c_int) -> u64 {
    let mut v = 0u64;
    // SAFETY: reading a 64-bit register into a u64.
    unsafe { (api().reg_read)(uc, reg, (&mut v as *mut u64).cast()) };
    v
}

fn write(uc: Uc, reg: c_int, v: u64) {
    // SAFETY: writing a 64-bit register from a u64.
    unsafe { (api().reg_write)(uc, reg, (&v as *const u64).cast()) };
}

fn xreg(n: u32) -> c_int {
    match n {
        0..=28 => R_X0 + n as c_int,
        29 => R_X29,
        _ => R_X30,
    }
}

// --- Taking turns -------------------------------------------------------------

/// Who emulates (one vCPU at a time) or changes the mappings: a queue
/// served in order.
struct Turn {
    holder: Option<usize>,
    queue: VecDeque<usize>,
}

static TURN: (Mutex<Turn>, Condvar) =
    (Mutex::new(Turn { holder: None, queue: VecDeque::new() }), Condvar::new());
/// The vCPU emulating now, for preemption.
static CURRENT: AtomicPtr<Vcpu> = AtomicPtr::new(std::ptr::null_mut());
/// A mapping change's place in the queue (vCPUs use their ids).
const MAPPER: usize = usize::MAX;

/// Wait for our turn; `None` if `give_up` became true meanwhile.
fn take_turn(who: usize, give_up: &dyn Fn() -> bool) -> Option<()> {
    let mut t = TURN.0.lock().unwrap_or_else(|e| e.into_inner());
    t.queue.push_back(who);
    loop {
        if t.holder.is_none() && t.queue.front() == Some(&who) {
            t.queue.pop_front();
            t.holder = Some(who);
            return Some(());
        }
        if give_up() {
            t.queue.retain(|&w| w != who);
            TURN.1.notify_all();
            return None;
        }
        // Whoever emulates is asked to hand on.
        preempt();
        t = TURN.1.wait_timeout(t, Duration::from_millis(1)).unwrap_or_else(|e| e.into_inner()).0;
    }
}

fn end_turn() {
    let mut t = TURN.0.lock().unwrap_or_else(|e| e.into_inner());
    t.holder = None;
    TURN.1.notify_all();
}

/// Ask the vCPU emulating now to stop at its next block and hand the turn
/// on. An engine is never stopped from another thread: Unicorn stopped
/// asynchronously sometimes resumes with its registers and pc out of step
/// (seen as a register update lost across the stop), so every stop is the
/// engine's own, from its block hook ([`on_block`]).
fn preempt() {
    let p = CURRENT.load(SeqCst);
    if !p.is_null() {
        // SAFETY: vCPUs are never freed.
        unsafe { (*p).yield_now.store(true, SeqCst) };
    }
}

// --- The calls ------------------------------------------------------------------

pub fn vm_config_create() -> hv_vm_config_t {
    Box::into_raw(Box::new(40u32)).cast()
}

/// The stand-in offers what an M3 or later does: 40-bit IPAs.
pub fn vm_config_get_max_ipa_size(bits: *mut u32) -> hv_return_t {
    if bits.is_null() {
        return HV_BAD_ARGUMENT;
    }
    // SAFETY: the caller's out-parameter.
    unsafe { *bits = 40 };
    HV_SUCCESS
}

pub fn vm_config_set_ipa_size(config: hv_vm_config_t, bits: u32) -> hv_return_t {
    if config.is_null() || !(32..=40).contains(&bits) {
        return HV_BAD_ARGUMENT;
    }
    // SAFETY: a configuration made by vm_config_create.
    unsafe { *config.cast::<u32>() = bits };
    HV_SUCCESS
}

pub fn vm_create(config: hv_vm_config_t) -> hv_return_t {
    let _ = api();
    let mut g = vm();
    if g.is_some() {
        return HV_BUSY;
    }
    // SAFETY: a configuration made by vm_config_create, or none.
    let ipa_bits = if config.is_null() { 36 } else { unsafe { *config.cast::<u32>() } };
    start_watcher();
    *g =
        Some(Vm { ipa_bits, maps: BTreeMap::new(), first_run: None, objects: Vec::new(), runs: 0 });
    VM_LIVE.store(true, SeqCst);
    tell_watcher(b'C');
    HV_SUCCESS
}

/// Async-signal-safe, as teardown may run in a handler: the records go
/// with the process.
pub fn vm_destroy() -> hv_return_t {
    if !VM_LIVE.load(SeqCst) {
        return HV_BAD_ARGUMENT;
    }
    let live = VCPUS.iter().filter(|p| !p.load(SeqCst).is_null()).count();
    if live > 0 {
        violation(&format!("hv_vm_destroy with {live} vCPU(s) still alive"));
        return HV_BUSY;
    }
    VM_LIVE.store(false, SeqCst);
    tell_watcher(b'D');
    // Not a lock a handler may wait on: drop the records only if free.
    if let Ok(mut g) = VM.try_lock() {
        *g = None;
    }
    HV_SUCCESS
}

pub fn vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t {
    let host = addr as u64;
    let len = size as u64;
    if !VM_LIVE.load(SeqCst) {
        violation("hv_vm_map without a VM");
        return HV_ERROR;
    }
    if !host.is_multiple_of(PAGE)
        || !ipa.is_multiple_of(PAGE)
        || !len.is_multiple_of(PAGE)
        || len == 0
    {
        note(&format!("hv_vm_map refused: {host:#x} -> {ipa:#x}+{len:#x} is not 16 KiB aligned"));
        return HV_BAD_ARGUMENT;
    }
    if flags & !(HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC) != 0 {
        return HV_BAD_ARGUMENT;
    }
    if let Err(e) = host_allows(host, len, flags) {
        note(&format!("hv_vm_map refused at {ipa:#x}+{len:#x}: {e}"));
        return HV_BAD_ARGUMENT;
    }
    let mut g = vm();
    let Some(v) = g.as_mut() else { return HV_ERROR };
    if ipa.checked_add(len).is_none_or(|end| end > 1 << v.ipa_bits) {
        return HV_BAD_ARGUMENT;
    }
    let end = ipa + len;
    if v.maps.range(..end).next_back().is_some_and(|(_, m)| m.end > ipa) {
        note(&format!("hv_vm_map refused: {ipa:#x}+{len:#x} overlaps a mapping"));
        return HV_BAD_ARGUMENT;
    }
    v.maps.insert(ipa, Mapping { end, host, flags });
    for (lo, hi, obj, _, _) in host_regions(host, len) {
        v.objects.push((lo, hi, obj));
    }
    apply(vec![Op::Map(ipa, end, host, uc_perms(flags)), Op::Flush]);
    HV_SUCCESS
}

pub fn vm_unmap(ipa: u64, size: usize) -> hv_return_t {
    let Some(end) = ipa.checked_add(size as u64) else { return HV_BAD_ARGUMENT };
    if !VM_LIVE.load(SeqCst) {
        violation("hv_vm_unmap without a VM");
        return HV_ERROR;
    }
    if !ipa.is_multiple_of(PAGE) || !(size as u64).is_multiple_of(PAGE) {
        return HV_BAD_ARGUMENT;
    }
    let mut g = vm();
    let Some(v) = g.as_mut() else { return HV_ERROR };
    // The range must be mapped throughout.
    let mut at = ipa;
    while at < end {
        match v.maps.range(..=at).next_back() {
            Some((_, m)) if m.end > at => at = m.end,
            _ => break,
        }
    }
    if at < end {
        note(&format!("hv_vm_unmap refused: {ipa:#x}+{size:#x} is not all mapped"));
        return HV_BAD_ARGUMENT;
    }
    let hit: Vec<(u64, Mapping)> =
        v.maps.range(..end).rev().take_while(|(_, m)| m.end > ipa).map(|(&s, &m)| (s, m)).collect();
    let mut gone = Vec::new();
    for (s, m) in hit {
        v.maps.remove(&s);
        let (lo, hi) = (s.max(ipa), m.end.min(end));
        if s < lo {
            v.maps.insert(s, Mapping { end: lo, ..m });
        }
        if m.end > hi {
            v.maps.insert(hi, Mapping { end: m.end, host: m.host + (hi - s), flags: m.flags });
        }
        gone.push((lo, hi));
        let (h, hl) = (m.host + (lo - s), hi - lo);
        v.objects.retain(|&(a, b, _)| b <= h || a >= h + hl);
    }
    if let Some(first) = &v.first_run
        && first.iter().any(|&(a, b)| ipa < b && end > a)
    {
        violation(&format!(
            "hv_vm_unmap of {ipa:#x}+{size:#x}, part of the stage 2 the VM ran with: \
                 stage 2 may not change while the VM runs"
        ));
    }
    let mut ops: Vec<Op> = gone.iter().map(|&(lo, hi)| Op::Unmap(lo, hi)).collect();
    ops.push(Op::Flush);
    apply(ops);
    HV_SUCCESS
}

/// A change to the emulated memory map, which each vCPU's CPU applies on
/// its own thread before it next emulates: a Unicorn engine is driven only
/// by its own thread (QEMU keeps per-thread state), except `uc_emu_stop`.
#[derive(Clone, Copy)]
enum Op {
    /// `(lo, hi, host, perms)`.
    Map(u64, u64, u64, u32),
    Unmap(u64, u64),
    /// Discard translations and translated code (after a change of
    /// guest-physical memory, or of code in it).
    Flush,
    /// Discard every cached translation: the guest ran `tlbi vmalle1is`.
    FlushAll,
}

/// The changes, from absolute index `base` on.
struct Log {
    base: usize,
    ops: Vec<Op>,
}

static LOG: Mutex<Log> = Mutex::new(Log { base: 0, ops: Vec::new() });

fn log() -> MutexGuard<'static, Log> {
    LOG.lock().unwrap_or_else(|e| e.into_inner())
}

/// Log `ops` with no vCPU emulating, so none touches memory being changed
/// until it has applied them.
fn apply(ops: Vec<Op>) {
    take_turn(MAPPER, &|| false);
    {
        let mut w = walk_map();
        for &op in &ops {
            match op {
                Op::Map(lo, hi, h, _) => {
                    w.insert(lo, (hi, h));
                }
                Op::Unmap(lo, hi) => {
                    let hit: Vec<(u64, (u64, u64))> = w
                        .range(..hi)
                        .rev()
                        .take_while(|(_, (e, _))| *e > lo)
                        .map(|(&a, &b)| (a, b))
                        .collect();
                    for (a, (e, h)) in hit {
                        w.remove(&a);
                        if a < lo {
                            w.insert(a, (lo, h));
                        }
                        if e > hi {
                            w.insert(hi, (e, h + (hi - a)));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let mut l = log();
    l.ops.extend(ops);
    // Drop what every vCPU has applied.
    if l.ops.len() > 4096 {
        let done = VCPUS
            .iter()
            .filter_map(|slot| {
                let p = slot.load(SeqCst);
                // SAFETY: registered vCPUs are never freed (see `vcpu`).
                (!p.is_null())
                    .then(|| engine(unsafe { &*p }))
                    .filter(|e| e.synced)
                    .map(|e| e.applied)
            })
            .min()
            .unwrap_or(l.base + l.ops.len());
        let n = done - l.base;
        l.ops.drain(..n);
        l.base = done;
    }
    drop(l);
    end_turn();
}

/// Apply the logged changes this vCPU has not; on its own thread, in its
/// turn.
fn catch_up(v: &Vcpu) {
    let l = log();
    let start = engine(v).applied.max(l.base) - l.base;
    // Unicorn may run the vCPU's hooks inside these calls: the engine
    // lock, which hooks take, is not held across them.
    for &op in &l.ops[start..] {
        apply_op(v.uc, op);
    }
    engine(v).applied = l.base + l.ops.len();
}

fn apply_op(uc: Uc, op: Op) {
    match op {
        Op::Map(lo, hi, h, perms) => {
            // SAFETY: host memory the VM maps, kept until it is unmapped
            // (checked to be mapped when it was).
            let rc =
                unsafe { (api().mem_map_ptr)(uc, lo, (hi - lo) as usize, perms, h as *mut c_void) };
            if rc != 0 {
                violation(&format!(
                    "emulated mapping of {lo:#x}+{:#x} failed: {}",
                    hi - lo,
                    uc_error(rc)
                ));
            }
        }
        Op::Unmap(lo, hi) => {
            // SAFETY: removing an emulated mapping made by vm_map.
            let rc = unsafe { (api().mem_unmap)(uc, lo, (hi - lo) as usize) };
            if rc != 0 {
                violation(&format!(
                    "emulated unmapping of {lo:#x}+{:#x} failed: {}",
                    hi - lo,
                    uc_error(rc)
                ));
            }
        }
        Op::Flush => flush(uc),
        Op::FlushAll => {
            // SAFETY: a control call on an engine not emulating.
            unsafe { (api().ctl)(uc, UC_CTL_TLB_FLUSH_W) };
        }
    }
}

/// Discard every cached translation and all translated code. (Unicorn's
/// per-range removal takes guest-virtual addresses and translates them
/// through the TLB hook: no use for a change of guest-physical memory.)
fn flush(uc: Uc) {
    // SAFETY: control calls on an engine not emulating.
    unsafe {
        (api().ctl)(uc, UC_CTL_TLB_FLUSH_W);
        (api().ctl)(uc, UC_CTL_TB_FLUSH_W);
    }
}

/// The host memory `[host, host + len)` is mapped and allows `flags`.
fn host_allows(host: u64, len: u64, flags: u64) -> Result<(), String> {
    let want = (if flags & HV_MEMORY_READ != 0 { libc::PROT_READ } else { 0 })
        | (if flags & HV_MEMORY_WRITE != 0 { libc::PROT_WRITE } else { 0 })
        | (if flags & HV_MEMORY_EXEC != 0 { libc::PROT_EXEC } else { 0 });
    let end = host + len;
    let mut at = host;
    while at < end {
        let Some(r) = fwe_kernel::mm::region::query(at) else {
            return Err(format!("host memory at {at:#x} is not mapped"));
        };
        if r.start > at {
            return Err(format!("host memory at {at:#x} is not mapped"));
        }
        // Inferred from what the real framework did, not documented: it
        // mapped memory whose most was RWX (with any flags) and RW (as R+X,
        // a fork child's code), but refused memory that could only ever be
        // read (a vfork child's shared code, as R+X). So the host must allow
        // reading and writing at most, whatever the VM asks for.
        let _ = want;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        if r.max_protection & rw != rw {
            return Err(format!(
                "host memory at {at:#x} allows at most {:#x}, not reading and writing",
                r.max_protection
            ));
        }
        at = r.start + r.size;
    }
    Ok(())
}

/// The emulated CPU's permissions for stage-2 `flags`.
fn uc_perms(flags: u64) -> u32 {
    (if flags & HV_MEMORY_READ != 0 { UC_PROT_READ } else { 0 })
        | (if flags & HV_MEMORY_WRITE != 0 { UC_PROT_WRITE } else { 0 })
        | (if flags & HV_MEMORY_EXEC != 0 { UC_PROT_EXEC } else { 0 })
}

// --- Stage 1: fwe's page tables, walked as the hardware walks them ----------

/// Stage 2 for the walker, `ipa -> (end, host)`: kept with the emulated
/// memory map (changed with the turn held, so no walk runs meanwhile).
static WALK: Mutex<BTreeMap<u64, (u64, u64)>> = Mutex::new(BTreeMap::new());

fn walk_map() -> MutexGuard<'static, BTreeMap<u64, (u64, u64)>> {
    WALK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The host address of guest-physical `ipa`, if stage 2 maps it.
fn ipa_host(ipa: u64) -> Option<u64> {
    let w = walk_map();
    let (&lo, &(hi, host)) = w.range(..=ipa).next_back()?;
    (ipa < hi).then_some(host + (ipa - lo))
}

/// The outcome of a walk.
#[derive(Debug, Clone, Copy)]
enum Walked {
    /// A page: its guest-physical address (with the offset), what EL0
    /// may do with it, and whether it is a BTI guarded page.
    Page { ipa: u64, perms: u32, guarded: bool },
    /// A translation fault at this level.
    Fault { level: u64 },
}

const DESC_ADDR: u64 = 0x0000_ffff_ffff_f000;

/// Walk fwe's tables (4 KiB granule, 40 bits, level 0 first, pages only at
/// level 3, as `pagetables` builds them) for `va`.
fn walk(ttbr0: u64, va: u64) -> Walked {
    if va >= 1 << 40 {
        return Walked::Fault { level: 0 };
    }
    let mut table = ttbr0 & DESC_ADDR;
    for level in 0..=3u64 {
        let idx = (va >> (12 + 9 * (3 - level))) & 511;
        let Some(h) = ipa_host(table + idx * 8) else { return Walked::Fault { level } };
        // SAFETY: host memory behind a mapped guest-physical address.
        let d = unsafe { std::ptr::read_volatile(h as *const u64) };
        if d & 0b11 != 0b11 {
            // Invalid, or a block (fwe's tables have none): a fault.
            return Walked::Fault { level };
        }
        if level < 3 {
            table = d & DESC_ADDR;
            continue;
        }
        let el0 = d & (1 << 6) != 0;
        let read_only = d & (1 << 7) != 0;
        let uxn = d & (1 << 54) != 0;
        let mut perms = 0;
        if el0 {
            perms |= UC_PROT_READ;
            if !read_only {
                perms |= UC_PROT_WRITE;
            }
        }
        if !uxn {
            perms |= UC_PROT_EXEC;
        }
        let guarded = d & (1 << 50) != 0;
        return Walked::Page { ipa: (d & DESC_ADDR) | (va & 0xfff), perms, guarded };
    }
    unreachable!()
}

/// Read 4 bytes of guest memory at `va` through the vCPU's tables.
fn fetch_va(ttbr0: u64, va: u64) -> Option<u32> {
    match walk(ttbr0, va) {
        // SAFETY: host memory behind a mapped page.
        Walked::Page { ipa, .. } => {
            ipa_host(ipa).map(|h| {
                // SAFETY: host memory behind a page the tables map.
                unsafe { (h as *const u32).read_unaligned() }
            })
        }
        Walked::Fault { .. } => None,
    }
}

// --- Host memory behind stage 2 ----------------------------------------------

/// The host regions of `[host, host + len)`: `(start, end, VM object id,
/// share mode, file-backed)`.
fn host_regions(host: u64, len: u64) -> Vec<(u64, u64, u32, u8, bool)> {
    #[repr(C)]
    #[derive(Default)]
    struct TopInfo {
        obj_id: u32,
        ref_count: u32,
        private_pages_resident: u32,
        shared_pages_resident: u32,
        share_mode: u8,
    }
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_region(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: c_int,
            info: *mut c_int,
            count: *mut u32,
            object_name: *mut u32,
        ) -> c_int;
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedInfo {
        protection: c_int,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u16,
        external_pager: u8,
        share_mode: u8,
        pages_reusable: u32,
    }
    const VM_REGION_TOP_INFO: c_int = 12;
    const VM_REGION_EXTENDED_INFO: c_int = 13;
    let end = host + len;
    let mut out = Vec::new();
    let mut at = host;
    while at < end {
        let (mut start, mut size) = (at, 0u64);
        let mut info = TopInfo::default();
        let mut count = (size_of::<TopInfo>() / size_of::<c_int>()) as u32;
        let mut name = 0u32;
        // SAFETY: querying our own address space into a record of the
        // size given.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut start,
                &mut size,
                VM_REGION_TOP_INFO,
                (&mut info as *mut TopInfo).cast(),
                &mut count,
                &mut name,
            )
        };
        if kr != 0 || start >= end {
            break;
        }
        let mut ext = ExtendedInfo::default();
        let mut count = (size_of::<ExtendedInfo>() / size_of::<c_int>()) as u32;
        let mut s2 = start;
        let mut z2 = 0u64;
        // SAFETY: as above, for the extended record.
        unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut s2,
                &mut z2,
                VM_REGION_EXTENDED_INFO,
                (&mut ext as *mut ExtendedInfo).cast(),
                &mut count,
                &mut name,
            )
        };
        out.push((
            start.max(host),
            (start + size).min(end),
            info.obj_id,
            info.share_mode,
            ext.external_pager != 0,
        ));
        at = start + size;
    }
    out
}

/// The host memory behind stage 2 must not have been replaced since it was
/// mapped: the framework keeps the pages it found then. Checked now and
/// then and when stage 2 changes.
fn check_objects(v: &mut Vm) {
    let mut updated = Vec::with_capacity(v.objects.len());
    for &(lo, hi, obj) in &v.objects {
        for (a, b, now, _, _) in host_regions(lo, hi - lo) {
            // An object appears when anonymous memory is first touched.
            if obj != 0 && now != 0 && now != obj {
                violation(&format!(
                    "the host memory at {a:#x}..{b:#x} behind stage 2 was replaced while the VM \
                     maps it (the framework keeps the pages it mapped)"
                ));
            }
            updated.push((a, b, if now != 0 { now } else { obj }));
        }
    }
    v.objects = updated;
}

pub fn vcpu_create(
    id: *mut hv_vcpu_t,
    exit: *mut *mut hv_vcpu_exit_t,
    _config: *mut c_void,
) -> hv_return_t {
    if !VM_LIVE.load(SeqCst) {
        violation("hv_vcpu_create without a VM");
        return HV_ERROR;
    }
    let a = api();
    let mut uc: Uc = std::ptr::null_mut();
    // SAFETY: Unicorn calls with valid out-pointers; the engine is ours.
    unsafe {
        let rc = (a.open)(UC_ARCH_ARM64, UC_MODE_ARM, &mut uc);
        if rc != 0 {
            note(&format!("uc_open failed: {}", uc_error(rc)));
            return HV_NO_RESOURCES;
        }
        (a.ctl)(uc, UC_CTL_CPU_MODEL_W, UC_CPU_ARM64_MAX);
        (a.ctl)(uc, UC_CTL_TLB_TYPE_W, UC_TLB_VIRTUAL);
    }
    // EL0 from the start, so the stack pointer written is EL0's; FP/SIMD
    // enabled; SCTLR as fwe sets it (EL0 cache maintenance and `dc zva`
    // allowed), without the MMU, which the TLB hook stands for.
    write(uc, R_PSTATE, 0);
    write(uc, R_CPACR_EL1, 0b11 << 20);
    let res1 = (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23) | (1 << 28) | (1 << 29);
    let sctlr = res1
        | (1 << 2)
        | (1 << 4)
        | (1 << 12)
        | (1 << 14)
        | (1 << 15)
        | (1 << 16)
        | (1 << 18)
        | (1 << 26);
    let cp = CpReg { crn: 1, crm: 0, op0: 3, op1: 0, op2: 0, val: sctlr };
    // SAFETY: writing SCTLR_EL1 through Unicorn's coprocessor-register form.
    unsafe { (a.reg_write)(uc, R_CP_REG, (&cp as *const CpReg).cast()) };
    // The emulated CPU has EL2 and EL3, and starts in Secure state, where
    // QEMU traps pointer authentication whatever HCR_EL2 says. Run the
    // guest as a VM runs: Non-secure (SCR_EL3.NS), EL1 and EL2 AArch64
    // (SCR_EL3.RW, HCR_EL2.RW), pointer authentication not trapped
    // (HCR_EL2.API/APK, SCR_EL3.API/APK) — a VM whose ID registers offer
    // the feature lets its guest use it.
    let hcr = (1u64 << 41) | (1 << 40) | (1 << 31);
    let scr = (1u64 << 17) | (1 << 16) | (1 << 10) | 1;
    for (op1, bits) in [(4, hcr), (6, scr)] {
        let mut c = CpReg { crn: 1, crm: 1, op0: 3, op1, op2: 0, val: 0 };
        // SAFETY: reading then writing HCR_EL2 or SCR_EL3 of the engine.
        unsafe {
            (a.reg_read)(uc, R_CP_REG, (&mut c as *mut CpReg).cast());
            c.val |= bits;
            (a.reg_write)(uc, R_CP_REG, (&c as *const CpReg).cast());
        }
    }

    let exit_rec = Box::into_raw(Box::new(hv_vcpu_exit_t {
        reason: 0,
        exception: hv_vcpu_exit_exception_t {
            syndrome: 0,
            virtual_address: 0,
            physical_address: 0,
        },
    }));
    let v = Box::into_raw(Box::new(Vcpu {
        uc,
        engine: Mutex::new(Engine {
            synced: false,
            applied: 0,
            esr: 0,
            elr: 0,
            spsr: 0,
            far: 0,
            sys: BTreeMap::new(),
            event: None,
            el1: None,
        }),
        exit: exit_rec,
        // SAFETY: plain host call.
        owner: unsafe { libc::pthread_self() },
        cancel: AtomicBool::new(false),
        yield_now: AtomicBool::new(false),
        ttbr0: AtomicU64::new(0),
        guarded: Mutex::new(std::collections::BTreeSet::new()),
        any_guarded: AtomicBool::new(false),
        hook_stopped: AtomicBool::new(false),
        running: AtomicBool::new(false),
        vtimer_offset: AtomicU64::new(0),
    }));
    // Hooks get the vCPU as their data.
    // SAFETY: hooks with the signatures Unicorn calls them with, and data
    // that outlives the engine.
    unsafe {
        let data = v.cast::<c_void>();
        let mut h = 0usize;
        (a.hook_add)(uc, &mut h, UC_HOOK_TLB_FILL, on_tlb_fill as *mut c_void, data, 1, 0);
        (a.hook_add)(uc, &mut h, UC_HOOK_BLOCK, on_block as *mut c_void, data, 1, 0);
        (a.hook_add)(uc, &mut h, UC_HOOK_INTR, on_exception as *mut c_void, data, 1, 0);
        (a.hook_add)(uc, &mut h, UC_HOOK_MEM_UNMAPPED, on_stage2 as *mut c_void, data, 1, 0);
        (a.hook_add)(uc, &mut h, UC_HOOK_MEM_PROT, on_stage2 as *mut c_void, data, 1, 0);
        for ins in [UC_ARM64_INS_MRS, UC_ARM64_INS_MSR, UC_ARM64_INS_SYS, UC_ARM64_INS_SYSL] {
            (a.hook_add)(uc, &mut h, UC_HOOK_INSN, on_system as *mut c_void, data, 1, 0, ins);
        }
    }
    let Some(slot) = VCPUS
        .iter()
        .position(|s| s.compare_exchange(std::ptr::null_mut(), v, SeqCst, SeqCst).is_ok())
    else {
        return HV_NO_RESOURCES;
    };
    // SAFETY: out-parameters the caller passed.
    unsafe {
        *id = slot as hv_vcpu_t;
        *exit = exit_rec;
    }
    HV_SUCCESS
}

/// Async-signal-safe: the vCPU leaves the table and is freed later.
pub fn vcpu_destroy(id: hv_vcpu_t) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_destroy") else { return HV_BAD_ARGUMENT };
    if v.running.load(SeqCst) {
        violation("hv_vcpu_destroy of a running vCPU");
        return HV_BUSY;
    }
    // Never freed: another thread may still hold it (a late
    // `hv_vcpus_exit`, a mapping change, a preemption), and a guest makes few
    // enough threads for the leak not to matter in a stand-in.
    VCPUS[id as usize].store(std::ptr::null_mut(), SeqCst);
    HV_SUCCESS
}

pub fn vcpus_exit(ids: *mut hv_vcpu_t, count: u32) -> hv_return_t {
    for i in 0..count as usize {
        // SAFETY: `count` ids the caller passed.
        let id = unsafe { *ids.add(i) };
        if let Some(v) = vcpu(id) {
            // Seen at the vCPU's next block, or before it next emulates.
            v.cancel.store(true, SeqCst);
        }
    }
    HV_SUCCESS
}

/// Under `FWE_STANDIN_DEBUG`, the registers a run starts or ends with.
fn debug_exit(v: &Vcpu, id: hv_vcpu_t, what: &str) {
    if std::env::var_os("FWE_STANDIN_DEBUG").is_some() {
        let _e = engine(v);
        note(&format!(
            "vcpu {id} {what}: pc {:#x} x8 {} x0 {:#x} x1 {:#x} sp {:#x}",
            read(v.uc, R_PC),
            read(v.uc, xreg(8)),
            read(v.uc, xreg(0)),
            read(v.uc, xreg(1)),
            read(v.uc, R_SP)
        ));
    }
}

pub fn vcpu_run(id: hv_vcpu_t) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_run") else { return HV_BAD_ARGUMENT };
    debug_exit(v, id, "runs");
    // SAFETY: the vCPU's exit record, written only here.
    let exit = unsafe { &mut *v.exit };
    let me = id as usize;
    loop {
        let cancelled = || v.cancel.load(SeqCst);
        if v.cancel.swap(false, SeqCst) {
            exit.reason = HV_EXIT_REASON_CANCELED;
            debug_exit(v, id, "cancelled");
            return HV_SUCCESS;
        }
        if !engine(v).synced
            && let Err(e) = sync(v)
        {
            violation(&e);
            return HV_ERROR;
        }
        {
            let mut g = vm();
            if let Some(vmr) = g.as_mut() {
                vmr.runs += 1;
                if vmr.runs % 4096 == 1 {
                    check_objects(vmr);
                }
            }
        }
        if take_turn(me, &cancelled).is_none() {
            continue;
        }
        catch_up(v);
        if let Err(msg) = enter_el1(v) {
            end_turn();
            violation(&msg);
            return HV_ERROR;
        }
        let mut e = engine(v);
        e.event = None;
        v.hook_stopped.store(false, SeqCst);
        let pc = read(v.uc, R_PC);
        v.running.store(true, SeqCst);
        CURRENT.store(v as *const Vcpu as *mut Vcpu, SeqCst);
        let rc = if v.cancel.load(SeqCst) {
            0
        } else {
            // Hooks reach the engine records through the vCPU pointer, not
            // this guard (they run on this thread, inside this call).
            let uc = v.uc;
            drop(e);
            // SAFETY: emulating on the engine this thread owns.
            let rc = unsafe { (api().emu_start)(uc, pc, UNTIL, 0, 0) };
            e = engine(v);
            rc
        };
        CURRENT.store(std::ptr::null_mut(), SeqCst);
        v.running.store(false, SeqCst);
        let event = e.event.take();
        end_turn();
        match event {
            Some(Event::El1 { esr, elr, far }) => {
                e.esr = esr;
                e.elr = elr;
                e.far = far;
                e.spsr = read(v.uc, R_PSTATE);
                exit.reason = HV_EXIT_REASON_EXCEPTION;
                // The vector's `hvc #2` (ESR_EL2: EC 0x16, IL, imm 2).
                exit.exception = hv_vcpu_exit_exception_t {
                    syndrome: (0x16 << 26) | (1 << 25) | 2,
                    virtual_address: 0,
                    physical_address: 0,
                };
                return HV_SUCCESS;
            }
            Some(Event::Direct { syndrome, va, pc }) => {
                write(v.uc, R_PC, pc);
                exit.reason = HV_EXIT_REASON_EXCEPTION;
                exit.exception = hv_vcpu_exit_exception_t {
                    syndrome,
                    virtual_address: va,
                    physical_address: va,
                };
                return HV_SUCCESS;
            }
            None => {}
        }
        if rc != 0 {
            violation(&format!(
                "emulation stopped: {} at pc {:#x}",
                uc_error(rc),
                read(v.uc, R_PC)
            ));
            return HV_ERROR;
        }
        drop(e);
        let now = read(v.uc, R_PC);
        if now == UNTIL && !v.cancel.load(SeqCst) {
            // A jump to 0, where emulation stops by itself: the
            // instruction abort the walk of page 0 gives.
            let level = match walk(v.ttbr0.load(SeqCst), 0) {
                Walked::Fault { level } => level,
                Walked::Page { .. } => 3,
            };
            let mut e = engine(v);
            e.esr = (0x20 << 26) | (1 << 25) | (0x04 | level);
            e.elr = 0;
            e.far = 0;
            e.spsr = read(v.uc, R_PSTATE);
            exit.reason = HV_EXIT_REASON_EXCEPTION;
            exit.exception = hv_vcpu_exit_exception_t {
                syndrome: (0x16 << 26) | (1 << 25) | 2,
                virtual_address: 0,
                physical_address: 0,
            };
            return HV_SUCCESS;
        }
        // `wfi`/`wfe` halt the emulated CPU past the instruction; the
        // framework exits at it.
        if let Some(insn) = fetch_va(v.ttbr0.load(SeqCst), now.wrapping_sub(4)) {
            let halted = !v.hook_stopped.load(SeqCst) && !v.cancel.load(SeqCst);
            if (insn == 0xd503_207f || insn == 0xd503_205f) && halted && now != pc {
                write(v.uc, R_PC, now - 4);
                exit.reason = HV_EXIT_REASON_EXCEPTION;
                exit.exception = hv_vcpu_exit_exception_t {
                    syndrome: (0x01 << 26) | (1 << 25) | u64::from(insn == 0xd503_205f),
                    virtual_address: 0,
                    physical_address: 0,
                };
                return HV_SUCCESS;
            }
        }
        // Stopped for a cancel (seen at the loop's top) or to hand the
        // turn on: go round.
    }
}

/// fwe's TLB stub, `tlbi vmalle1is; dsb ish; isb; eret`.
const TLB_STUB: [u32; 4] = [0xd508_831f, 0xd503_3b9f, 0xd503_3fdf, 0xd69f_03e0];

/// The vCPU was set to resume at EL1: only fwe's TLB stub may run there.
/// Carry it out — every emulated CPU's cached translations go — and return
/// to EL0 as its `eret` does. With the turn held.
fn enter_el1(v: &Vcpu) -> Result<(), String> {
    let (pc, vbar, ttbr0, elr, spsr) = {
        let mut e = engine(v);
        let Some(_) = e.el1.take() else { return Ok(()) };
        let vbar = e.sys.get(&HV_SYS_REG_VBAR_EL1).copied().unwrap_or(0);
        (read(v.uc, R_PC), vbar, v.ttbr0.load(SeqCst), e.elr, e.spsr)
    };
    if pc != vbar + 0x800 {
        return Err(format!("vCPU run at EL1 at {pc:#x}, not fwe's TLB stub"));
    }
    for (i, &w) in TLB_STUB.iter().enumerate() {
        if fetch_va(ttbr0, pc + 4 * i as u64) != Some(w) {
            return Err(format!(
                "fwe's TLB stub at {pc:#x} is not `tlbi vmalle1is; dsb ish; isb; eret`"
            ));
        }
    }
    if spsr & 0xf != 0 {
        return Err(format!("the TLB stub would return to SPSR {spsr:#x}, not EL0"));
    }
    log().ops.push(Op::FlushAll);
    catch_up(v);
    let _e = engine(v);
    write(v.uc, R_PC, elr);
    write(v.uc, R_PSTATE, spsr);
    Ok(())
}

/// Apply stage 2 to this vCPU's CPU, reading stage 1 first if it is the
/// VM's first run.
fn sync(v: &Vcpu) -> Result<(), String> {
    let mut g = vm();
    let Some(vmr) = g.as_mut() else { return Err("hv_vcpu_run without a VM".into()) };
    {
        let e = engine(v);
        let get = |r| e.sys.get(&r).copied().unwrap_or(0);
        for (reg, name) in [
            (HV_SYS_REG_TTBR0_EL1, "TTBR0_EL1"),
            (HV_SYS_REG_TCR_EL1, "TCR_EL1"),
            (HV_SYS_REG_VBAR_EL1, "VBAR_EL1"),
            (HV_SYS_REG_SCTLR_EL1, "SCTLR_EL1"),
        ] {
            if !e.sys.contains_key(&reg) {
                return Err(format!("vCPU run before {name} was set"));
            }
        }
        if get(HV_SYS_REG_SCTLR_EL1) & 1 == 0 {
            return Err("vCPU run with the MMU off".into());
        }
        if get(HV_SYS_REG_CPACR_EL1) >> 20 & 3 != 3 {
            return Err("vCPU run with FP/SIMD trapped".into());
        }
        let tcr = get(HV_SYS_REG_TCR_EL1);
        if tcr & 0x3f != 24 || (tcr >> 14) & 3 != 0 {
            return Err(format!("TCR_EL1 {tcr:#x} is not the 40-bit, 4 KiB-granule regime"));
        }
        // The vector: `hvc #2; b .` at each entry (not `hvc #0`, which the
        // framework may take for a firmware call).
        let vbar = get(HV_SYS_REG_VBAR_EL1);
        let ttbr0 = get(HV_SYS_REG_TTBR0_EL1);
        for i in 0..16u64 {
            let at = vbar + i * 0x80;
            if (fetch_va(ttbr0, at), fetch_va(ttbr0, at + 4))
                != (Some(0xd400_0042), Some(0x1400_0000))
            {
                return Err(format!("vector entry {i} at {at:#x} is not `hvc #2; b .`"));
            }
        }
    }
    if vmr.first_run.is_none() {
        // The stage 2 the VM runs with: fixed from now on, and none of it
        // shared with another process.
        vmr.first_run = Some(vmr.maps.iter().map(|(&s, m)| (s, m.end)).collect());
        let ranges: Vec<(u64, u64)> = vmr.maps.iter().map(|(&s, m)| (m.host, m.end - s)).collect();
        for (host, len) in ranges {
            for (a, b, _, share, file) in host_regions(host, len) {
                // SM_SHARED, SM_TRUESHARED, SM_SHARED_ALIASED, of memory
                // that is not a file's: anonymous memory in two processes'
                // VMs at once (a file's pages are what `MAP_SHARED` shares).
                if matches!(share, 4 | 5 | 7) && !file {
                    violation(&format!(
                        "anonymous host memory {a:#x}..{b:#x} behind the VM's stage 2 is \
                         shared with another process"
                    ));
                }
            }
        }
    }
    let pieces: Vec<(u64, u64, u64, u32)> =
        vmr.maps.iter().map(|(&s, m)| (s, m.end, m.host, uc_perms(m.flags))).collect();
    take_turn(MAPPER, &|| false);
    // Everything logged so far is in `maps` (the VM lock, held, keeps new
    // changes out meanwhile).
    let l = log();
    engine(v).applied = l.base + l.ops.len();
    drop(l);
    // As in `catch_up`, hooks may run inside these calls.
    for (lo, hi, h, perms) in pieces {
        // SAFETY: as in vm_map.
        let rc =
            unsafe { (api().mem_map_ptr)(v.uc, lo, (hi - lo) as usize, perms, h as *mut c_void) };
        if rc != 0 {
            end_turn();
            return Err(format!(
                "emulated mapping of {lo:#x}+{:#x} failed: {}",
                hi - lo,
                uc_error(rc)
            ));
        }
    }
    engine(v).synced = true;
    end_turn();
    Ok(())
}

/// The instruction at guest address `pc` of the vCPU whose hook data is
/// `d`, if mapped.
fn fetch(d: *mut c_void, pc: u64) -> Option<u32> {
    // SAFETY: the hook's data is its vCPU, never freed.
    let v = unsafe { &*d.cast::<Vcpu>() };
    fetch_va(v.ttbr0.load(SeqCst), pc)
}

// --- Hooks ----------------------------------------------------------------------

/// At each block: stop if `hv_vcpus_exit` or another vCPU's turn asks, and
/// check BTI, which Unicorn's TLB hook cannot tell QEMU about: a block
/// entered by an indirect branch (`PSTATE.BTYPE` set) on a guarded page
/// must begin with a landing pad compatible with the branch, or the guest
/// takes a branch target exception, as the hardware raises it. QEMU sets
/// `BTYPE` as for branches from unguarded pages (a `br` through a register
/// other than x16 or x17 gives `0b01`, not `0b11`), so `bti c` and
/// `paciasp` are taken as landing pads there too.
extern "C" fn on_block(uc: Uc, addr: u64, _size: u32, d: *mut c_void) {
    // SAFETY: the hook's data is its vCPU.
    let v = unsafe { &*d.cast::<Vcpu>() };
    // Only on a guarded page the vCPU fetched from (confirmed by a walk
    // below): reading PSTATE at every block would halve the speed.
    let maybe_guarded = v.any_guarded.load(SeqCst)
        && v.guarded.lock().unwrap_or_else(|e| e.into_inner()).contains(&(addr >> 12));
    let btype = if maybe_guarded { (read(uc, R_PSTATE) >> 10) & 3 } else { 0 };
    if btype != 0
        && let Walked::Page { guarded: true, .. } = walk(v.ttbr0.load(SeqCst), addr)
    {
        let insn = fetch_va(v.ttbr0.load(SeqCst), addr).unwrap_or(0);
        // bti c, bti j, bti jc; paciasp, pacibsp (with SCTLR.BT0 set,
        // as fwe sets it: not for BTYPE 0b11).
        let ok = match insn {
            0xd503_245f => btype != 0b11,
            0xd503_249f => btype != 0b10,
            0xd503_24df => true,
            0xd503_233f | 0xd503_237f => btype != 0b11,
            _ => false,
        };
        if !ok {
            record(d, Event::El1 { esr: (0x0d << 26) | (1 << 25) | btype, elr: addr, far: 0 });
            // SAFETY: stopping the engine whose hook this is.
            unsafe { (api().emu_stop)(uc) };
            return;
        }
    }
    if v.cancel.load(SeqCst) || v.yield_now.swap(false, SeqCst) {
        v.hook_stopped.store(true, SeqCst);
        // SAFETY: stopping the engine whose hook this is, on its thread.
        unsafe { (api().emu_stop)(uc) };
    }
}

/// Stage 1 is fwe's page tables, walked as the hardware walks them; stage 2
/// is the emulated memory map, whose permissions Unicorn enforces. A walk
/// that finds no page, or a page that does not allow the access, is the
/// fault EL1 would take: a translation fault at the level the walk
/// stopped, or a permission fault, with the faulting address.
extern "C" fn on_tlb_fill(uc: Uc, va: u64, t: c_int, out: *mut TlbEntry, d: *mut c_void) -> bool {
    const UC_MEM_WRITE: c_int = 17;
    const UC_MEM_FETCH: c_int = 18;
    // SAFETY: the hook's data is its vCPU, never freed.
    let v = unsafe { &*d.cast::<Vcpu>() };
    let fetching = t == UC_MEM_FETCH;
    // The top byte is ignored for data (TCR_EL1.TBI0), not for fetches.
    let addr = if fetching { va } else { va & 0x00ff_ffff_ffff_ffff };
    let want = match t {
        UC_MEM_WRITE => UC_PROT_WRITE,
        UC_MEM_FETCH => UC_PROT_EXEC,
        _ => UC_PROT_READ,
    };
    let fault = |fsc: u64| {
        // The instruction that faulted is at pc: for a fetch, the block
        // QEMU was translating (none of it ran). The hook is given a fetch's
        // address rounded down to QEMU's 1 KiB page; the instruction's own
        // address is the fault address when it lies on the faulting page.
        let pc = read(uc, R_PC);
        let far = if fetching && pc & !0xfff == va & !0xfff { pc } else { va };
        let ec = if fetching { 0x20 } else { 0x24 };
        let wnr = if t == UC_MEM_WRITE { 1 << 6 } else { 0 };
        record(d, Event::El1 { esr: (ec << 26) | (1 << 25) | wnr | fsc, elr: pc, far });
        false
    };
    match walk(v.ttbr0.load(SeqCst), addr) {
        Walked::Fault { level } => fault(0x04 | level),
        Walked::Page { perms, .. } if perms & want == 0 => fault(0x0c | 3),
        Walked::Page { ipa, perms, guarded } => {
            if fetching && guarded {
                v.guarded.lock().unwrap_or_else(|e| e.into_inner()).insert(addr >> 12);
                v.any_guarded.store(true, SeqCst);
            }
            // SAFETY: Unicorn passes an entry to fill.
            unsafe { *out = TlbEntry { paddr: ipa, perms } };
            true
        }
    }
}

fn record(d: *mut c_void, ev: Event) {
    // SAFETY: the hook's data is its vCPU, on whose thread hooks run.
    let v = unsafe { &*d.cast::<Vcpu>() };
    // Unicorn also runs hooks from its own calls outside emulation (memory
    // changes): no guest access happened then.
    if !v.running.load(SeqCst) {
        return;
    }
    // The run loop released the guard before emulating. The first event
    // of a run is the one that happened (a failed translation is followed
    // by QEMU's exception for it).
    let mut e = engine(v);
    if std::env::var_os("FWE_STANDIN_DEBUG").is_some() {
        note(&format!(
            "event {ev:?} (already {:?}) pc {:#x} x19 {:#x} x20 {:#x} x25 {:#x}",
            e.event,
            read(v.uc, R_PC),
            read(v.uc, xreg(19)),
            read(v.uc, xreg(20)),
            read(v.uc, xreg(25))
        ));
    }
    if e.event.is_none() {
        e.event = Some(ev);
    }
    drop(e);
    // SAFETY: stopping the engine whose hook this is.
    unsafe { (api().emu_stop)(v.uc) };
}

/// An exception QEMU raised at EL0: what the EL1 vector would be given.
extern "C" fn on_exception(uc: Uc, intno: u32, d: *mut c_void) {
    // SAFETY: the hook's data is its vCPU.
    if engine(unsafe { &*d.cast::<Vcpu>() }).event.is_some() {
        return;
    }
    let pc = read(uc, R_PC);
    let il = 1u64 << 25;
    let ev = match intno {
        // pc is past the `svc`.
        EXCP_SWI => {
            let imm = fetch(d, pc - 4).map_or(0, |i| u64::from((i >> 5) & 0xffff));
            Event::El1 { esr: (0x15 << 26) | il | imm, elr: pc, far: 0 }
        }
        EXCP_BKPT => {
            let imm = fetch(d, pc).map_or(0, |i| u64::from((i >> 5) & 0xffff));
            Event::El1 { esr: (0x3c << 26) | il | imm, elr: pc, far: 0 }
        }
        EXCP_UDEF => Event::El1 { esr: il, elr: pc, far: 0 },
        EXCP_PREFETCH_ABORT if pc & 3 != 0 => {
            Event::El1 { esr: (0x22 << 26) | il, elr: pc, far: pc }
        }
        EXCP_DATA_ABORT => {
            // Alignment (stage 1 never faults otherwise, and stage 2 faults
            // come through the memory hooks): DFSC 0x21.
            let far = fetch(d, pc).map_or(0, |i| exclusive_or_atomic_base(uc, i));
            let wnr = fetch(d, pc).map_or(0, |i| u64::from(i & (1 << 22) == 0) << 6);
            Event::El1 { esr: (0x24 << 26) | il | wnr | 0x21, elr: pc, far }
        }
        other => {
            violation(&format!("exception {other} at pc {pc:#x} is not modelled"));
            Event::El1 { esr: il, elr: pc, far: 0 }
        }
    };
    record(d, ev);
}

/// The address an exclusive or atomic instruction uses: its base register
/// (they have no offset). Anything else gives 0, which the stand-in does
/// not model.
fn exclusive_or_atomic_base(uc: Uc, insn: u32) -> u64 {
    let exclusive = insn & 0x3f00_0000 == 0x0800_0000;
    let atomic = insn & 0x3f20_0c00 == 0x3820_0000;
    if !(exclusive || atomic) {
        return 0;
    }
    let rn = (insn >> 5) & 31;
    if rn == 31 { read(uc, R_SP) } else { read(uc, xreg(rn)) }
}

/// A stage-2 abort: the framework's exit, at the faulting instruction.
extern "C" fn on_stage2(
    uc: Uc,
    t: c_int,
    addr: u64,
    _size: c_int,
    _value: i64,
    d: *mut c_void,
) -> bool {
    let pc = read(uc, R_PC);
    let fetch_fault = t == UC_MEM_FETCH_UNMAPPED || t == UC_MEM_FETCH_PROT;
    let write = t == UC_MEM_WRITE_UNMAPPED || t == UC_MEM_WRITE_PROT;
    let permission = t == UC_MEM_WRITE_PROT || t == UC_MEM_FETCH_PROT || t == 23;
    let fsc = if permission { 0x0f } else { 0x07 };
    let ec = if fetch_fault { 0x20 } else { 0x24 };
    let syndrome = (ec << 26) | (1 << 25) | (u64::from(write) << 6) | fsc;
    let pc = if fetch_fault { addr } else { pc };
    record(d, Event::Direct { syndrome, va: addr, pc });
    false
}

/// The counter frequency: the host's (macOS keeps `CNTFRQ_EL0` from user
/// space, but its timebase is the counter's).
fn counter_hz() -> u64 {
    static HZ: OnceLock<u64> = OnceLock::new();
    *HZ.get_or_init(|| {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_timebase_info(info: *mut Timebase) -> c_int;
        }
        let mut tb = Timebase { numer: 0, denom: 0 };
        // SAFETY: filling a timebase record.
        unsafe { mach_timebase_info(&mut tb) };
        if tb.numer == 0 {
            24_000_000
        } else {
            1_000_000_000 * u64::from(tb.denom) / u64::from(tb.numer)
        }
    })
}

/// A system instruction at EL0 (`mrs`, `msr`, `sys`, `sysl`): returns 1 if
/// handled here, 0 to let QEMU carry it out.
extern "C" fn on_system(uc: Uc, reg: c_int, cp: *const CpReg, d: *mut c_void) -> u32 {
    // SAFETY: Unicorn passes the instruction's encoding fields.
    let cp = unsafe { &*cp };
    let pc = read(uc, R_PC);
    let insn = fetch(d, pc).unwrap_or(0);
    let read_dir = insn & (1 << 21) != 0;
    let rt = insn & 31;
    let key = (cp.op0, cp.op1, cp.crn, cp.crm, cp.op2);
    // SAFETY: the hook's data is its vCPU.
    let v = unsafe { &*d.cast::<Vcpu>() };
    let set_rt = |val: u64| {
        if rt != 31 {
            write(uc, reg, val);
        }
    };
    match key {
        // What EL0 has under fwe's SCTLR and CNTKCTL, done by QEMU: the
        // thread pointers, flags and FP control, cache maintenance, `dc zva`.
        (3, 3, 13, 0, 2)
        | (3, 3, 13, 0, 3)
        | (3, 3, 4, 2, 0)
        | (3, 3, 4, 4, 0)
        | (3, 3, 4, 4, 1)
        | (3, 3, 4, 2, 5)
        | (3, 3, 4, 2, 6)
        | (3, 3, 4, 2, 7) => 0,
        (1, 3, 7, 4, 1)
        | (1, 3, 7, 5, 1)
        | (1, 3, 7, 10, 1)
        | (1, 3, 7, 11, 1)
        | (1, 3, 7, 12, 1)
        | (1, 3, 7, 13, 1)
        | (1, 3, 7, 14, 1) => 0,
        // Apple Silicon's cache type, as the native backend reports it
        // (macOS keeps the host's from user space).
        (3, 3, 0, 0, 1) if read_dir => {
            set_rt(crate::hwcap::CTR_EL0);
            1
        }
        // QEMU's `dc zva` block, 64 bytes as on Apple's cores.
        (3, 3, 0, 0, 7) if read_dir => 0,
        // The host's counter frequency.
        (3, 3, 14, 0, 0) if read_dir => {
            set_rt(counter_hz());
            1
        }
        // The virtual counter: the host's, less the vCPU's offset.
        (3, 3, 14, 0, 2) | (3, 3, 14, 0, 6) if read_dir => {
            // SAFETY: plain host call.
            let now = unsafe { mach_absolute_time() };
            set_rt(now.wrapping_sub(v.vtimer_offset.load(SeqCst)));
            1
        }
        // The physical counter traps to the host under the framework.
        (3, 3, 14, 0, 1) | (3, 3, 14, 0, 5) if read_dir => {
            let iss = sysreg_iss(cp, rt, read_dir);
            record(d, Event::Direct { syndrome: (0x18 << 26) | (1 << 25) | iss, va: 0, pc });
            write(uc, R_PC, pc);
            1
        }
        // Anything else is not EL0's: the ID registers trap to EL1 as a
        // system register access, the rest is undefined there.
        _ => {
            let esr = if cp.op0 == 3 && cp.op1 == 0 && cp.crn == 0 {
                (0x18 << 26) | (1 << 25) | sysreg_iss(cp, rt, read_dir)
            } else {
                1 << 25
            };
            record(d, Event::El1 { esr, elr: pc, far: 0 });
            write(uc, R_PC, pc);
            1
        }
    }
}

/// ISS of a trapped `mrs`/`msr` (EC 0x18).
fn sysreg_iss(cp: &CpReg, rt: u32, read: bool) -> u64 {
    u64::from(cp.op0) << 20
        | u64::from(cp.op2) << 17
        | u64::from(cp.op1) << 14
        | u64::from(cp.crn) << 10
        | u64::from(rt) << 5
        | u64::from(cp.crm) << 1
        | u64::from(read)
}

// --- Registers ------------------------------------------------------------------

/// The framework's number for a system register is its encoding,
/// `op0:op1:CRn:CRm:op2` in 2, 3, 4, 4 and 3 bits: Unicorn's form of it.
fn cp(reg: hv_sys_reg_t) -> CpReg {
    let r = u32::from(reg);
    CpReg {
        op0: r >> 14 & 3,
        op1: r >> 11 & 7,
        crn: r >> 7 & 0xf,
        crm: r >> 3 & 0xf,
        op2: r & 7,
        val: 0,
    }
}

fn cp_read(uc: Uc, reg: hv_sys_reg_t) -> u64 {
    let mut c = cp(reg);
    // SAFETY: reading a system register of the engine into the record.
    unsafe { (api().reg_read)(uc, R_CP_REG, (&mut c as *mut CpReg).cast()) };
    c.val
}

fn cp_write(uc: Uc, reg: hv_sys_reg_t, val: u64) {
    let c = CpReg { val, ..cp(reg) };
    // SAFETY: writing a system register of the engine from the record.
    unsafe { (api().reg_write)(uc, R_CP_REG, (&c as *const CpReg).cast()) };
}

/// The `SCTLR_EL1` bits the emulated CPU takes from fwe's value: pointer
/// authentication's enables and BT0 (the rest is the stand-in's own: no
/// MMU, as the TLB hook walks the tables).
const SCTLR_PASSED: u64 = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13) | (1 << 35);

pub fn vcpu_get_reg(id: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_get_reg") else { return HV_BAD_ARGUMENT };
    let e = engine(v);
    let r = match reg {
        0..=30 => read(v.uc, xreg(reg)),
        HV_REG_PC => read(v.uc, R_PC),
        HV_REG_FPCR => read(v.uc, R_FPCR),
        HV_REG_FPSR => read(v.uc, R_FPSR),
        HV_REG_CPSR => match e.el1 {
            Some(ps) => ps,
            None => read(v.uc, R_PSTATE),
        },
        _ => return HV_BAD_ARGUMENT,
    };
    // SAFETY: the caller's out-parameter.
    unsafe { *value = r };
    HV_SUCCESS
}

pub fn vcpu_set_reg(id: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_set_reg") else { return HV_BAD_ARGUMENT };
    let mut e = engine(v);
    match reg {
        0..=30 => write(v.uc, xreg(reg), value),
        HV_REG_PC => write(v.uc, R_PC, value),
        HV_REG_FPCR => write(v.uc, R_FPCR, value),
        HV_REG_FPSR => write(v.uc, R_FPSR, value),
        HV_REG_CPSR => {
            if value & 0xf != 0 {
                // fwe's EL1 code: carried out when the vCPU runs (see
                // `vcpu_run`), the emulated CPU staying at EL0.
                e.el1 = Some(value);
                return HV_SUCCESS;
            }
            e.el1 = None;
            write(v.uc, R_PSTATE, value);
        }
        _ => return HV_BAD_ARGUMENT,
    }
    HV_SUCCESS
}

pub fn vcpu_get_sys_reg(id: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_get_sys_reg") else { return HV_BAD_ARGUMENT };
    let e = engine(v);
    let r = match reg {
        HV_SYS_REG_SP_EL0 => read(v.uc, R_SP),
        HV_SYS_REG_TPIDR_EL0 => read(v.uc, R_TPIDR_EL0),
        HV_SYS_REG_ESR_EL1 => e.esr,
        HV_SYS_REG_ELR_EL1 => e.elr,
        HV_SYS_REG_SPSR_EL1 => e.spsr,
        HV_SYS_REG_FAR_EL1 => e.far,
        // What the emulated CPU offers (QEMU's `max`): pointer
        // authentication and BTI among them.
        HV_SYS_REG_ID_AA64ISAR1_EL1 | HV_SYS_REG_ID_AA64PFR1_EL1 => cp_read(v.uc, reg),
        r => e.sys.get(&r).copied().unwrap_or(0),
    };
    // SAFETY: the caller's out-parameter.
    unsafe { *value = r };
    HV_SUCCESS
}

pub fn vcpu_set_sys_reg(id: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_set_sys_reg") else { return HV_BAD_ARGUMENT };
    let mut e = engine(v);
    match reg {
        HV_SYS_REG_SP_EL0 => write(v.uc, R_SP, value),
        HV_SYS_REG_TPIDR_EL0 => write(v.uc, R_TPIDR_EL0, value),
        HV_SYS_REG_ESR_EL1 => e.esr = value,
        HV_SYS_REG_ELR_EL1 => e.elr = value,
        HV_SYS_REG_SPSR_EL1 => e.spsr = value,
        HV_SYS_REG_FAR_EL1 => e.far = value,
        r => {
            if r == HV_SYS_REG_TTBR0_EL1 {
                v.ttbr0.store(value, SeqCst);
            }
            if r == HV_SYS_REG_SCTLR_EL1 {
                let now = cp_read(v.uc, r);
                cp_write(v.uc, r, (now & !SCTLR_PASSED) | (value & SCTLR_PASSED));
            }
            if HV_SYS_REG_PAC_KEYS.contains(&r) {
                // The emulated CPU signs and authenticates with them.
                cp_write(v.uc, r, value);
            }
            e.sys.insert(r, value);
        }
    }
    HV_SUCCESS
}

pub fn vcpu_get_simd_fp_reg(id: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_get_simd_fp_reg") else { return HV_BAD_ARGUMENT };
    if reg > 31 {
        return HV_BAD_ARGUMENT;
    }
    let _e = engine(v);
    // SAFETY: a 16-byte register into the caller's 16 bytes.
    unsafe { (api().reg_read)(v.uc, R_Q0 + reg as c_int, value.cast()) };
    HV_SUCCESS
}

pub fn vcpu_set_simd_fp_reg(id: hv_vcpu_t, reg: u32, value: *const u128) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_set_simd_fp_reg") else { return HV_BAD_ARGUMENT };
    if reg > 31 {
        return HV_BAD_ARGUMENT;
    }
    let _e = engine(v);
    // SAFETY: 16 bytes of the caller's into a 16-byte register.
    unsafe { (api().reg_write)(v.uc, R_Q0 + reg as c_int, value.cast()) };
    HV_SUCCESS
}

pub fn vcpu_get_vtimer_offset(id: hv_vcpu_t, offset: *mut u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_get_vtimer_offset") else { return HV_BAD_ARGUMENT };
    // SAFETY: the caller's out-parameter.
    unsafe { *offset = v.vtimer_offset.load(SeqCst) };
    HV_SUCCESS
}

pub fn vcpu_set_vtimer_offset(id: hv_vcpu_t, offset: u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_set_vtimer_offset") else { return HV_BAD_ARGUMENT };
    v.vtimer_offset.store(offset, SeqCst);
    HV_SUCCESS
}

/// fwe wrote guest code through the host (where the hardware needs the
/// instruction cache invalidated): emulated CPUs drop their translated code
/// before they next run.
pub fn code_written() {
    if VM_LIVE.load(SeqCst) {
        apply(vec![Op::Flush]);
    }
}

// --- The watcher ----------------------------------------------------------------

/// Start `fwe --hv-standin-watch <pid>` with the read end of a pipe as its
/// standard input; ours stays close-on-exec, out of the guest's range.
fn start_watcher() {
    // A unit test's process has no fwe to start.
    if WATCH_FD.load(SeqCst) >= 0 || cfg!(test) {
        return;
    }
    let Some(fwe) = crate::FWE_EXE.get() else {
        violation("fwe's own path is unknown, so no watcher checks the VM's end");
        return;
    };
    let mut fds = [0; 2];
    // SAFETY: plain host calls on descriptors made here.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            violation("no pipe for the watcher");
            return;
        }
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(fwe.as_os_str().as_bytes()).unwrap();
    // SAFETY: plain host call.
    let pid = std::ffi::CString::new(unsafe { libc::getpid() }.to_string()).unwrap();
    let flag = c"--hv-standin-watch";
    let argv = [path.as_ptr(), flag.as_ptr(), pid.as_ptr(), std::ptr::null()];
    let mut child = 0;
    unsafe extern "C" {
        fn posix_spawn_file_actions_addinherit_np(
            fa: *mut libc::posix_spawn_file_actions_t,
            fd: c_int,
        ) -> c_int;
    }
    // SAFETY: spawn attributes and file actions initialized, used and
    // destroyed here; the argument array lives across the call.
    let rc = unsafe {
        let mut fa: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        libc::posix_spawn_file_actions_init(&mut fa);
        libc::posix_spawn_file_actions_adddup2(&mut fa, fds[0], 0);
        // Only its standard input and error: it must hold none of the
        // guest's descriptors (a pipe it held open would never see EOF).
        posix_spawn_file_actions_addinherit_np(&mut fa, 2);
        let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
        libc::posix_spawnattr_init(&mut attr);
        // Its own process group, so a test's group is only the VM's.
        libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_CLOEXEC_DEFAULT) as libc::c_short,
        );
        libc::posix_spawnattr_setpgroup(&mut attr, 0);
        let env: [*const c_char; 1] = [std::ptr::null()];
        let rc = libc::posix_spawn(
            &mut child,
            path.as_ptr(),
            &fa,
            &attr,
            argv.as_ptr() as _,
            env.as_ptr() as _,
        );
        libc::posix_spawn_file_actions_destroy(&mut fa);
        libc::posix_spawnattr_destroy(&mut attr);
        libc::close(fds[0]);
        rc
    };
    if rc != 0 {
        violation("the watcher could not be started");
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(fds[1]) };
        return;
    }
    match fwe_kernel::fdtable::reserve(fds[1]) {
        Ok(fd) => WATCH_FD.store(fd, SeqCst),
        Err(_) => violation("the watcher's descriptor could not be kept"),
    }
}

/// The stand-in's own descriptor, which a fork child must not be given.
pub fn own_fd() -> i32 {
    WATCH_FD.load(SeqCst)
}

fn tell_watcher(b: u8) {
    let fd = WATCH_FD.load(SeqCst);
    if fd >= 0 {
        // SAFETY: writing one byte to our pipe.
        unsafe { libc::write(fd, (&b as *const u8).cast(), 1) };
    }
}

/// `fwe --hv-standin-watch <pid>`: read the VM's life from standard input
/// and report a process that ended with its VM alive.
pub fn watch(pid: &str) -> ! {
    let mut alive = false;
    let mut b = 0u8;
    loop {
        // SAFETY: reading one byte from standard input.
        let n = unsafe { libc::read(0, (&mut b as *mut u8).cast(), 1) };
        if n == 1 {
            alive = b == b'C';
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    if alive {
        violation(&format!("process {pid} ended or exec'd with its VM alive"));
    }
    // SAFETY: ending the watcher.
    unsafe { libc::_exit(0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(len: usize, prot: c_int, flags: c_int, fd: c_int) -> *mut c_void {
        // SAFETY: a fresh mapping for the test.
        let p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        p
    }

    /// The rules the stand-in holds the backend to, which no guest program
    /// reaches while the backend keeps them. One test, as the VM is one per
    /// process.
    #[test]
    fn standin_holds_the_framework_rules() {
        if load().is_err() {
            eprintln!("skipped: no Unicorn");
            return;
        }
        enable();
        let cfg = vm_config_create();
        assert_eq!(vm_config_set_ipa_size(cfg, 40), HV_SUCCESS);
        assert_eq!(vm_create(cfg), HV_SUCCESS);
        assert_eq!(vm_create(cfg), HV_BUSY, "one VM per process");

        let rw =
            map(0x8000, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1);
        let all = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        assert_eq!(vm_map(rw, 0x10_0000, 0x4000, all), HV_SUCCESS, "RW host memory maps as RWX");
        assert_eq!(vm_map(rw, 0x10_0000, 0x4000, all), HV_BAD_ARGUMENT, "no overlap");
        // SAFETY: an address inside the mapping above.
        let off = unsafe { rw.cast::<u8>().add(0x1000) }.cast();
        assert_eq!(vm_map(off, 0x20_0000, 0x4000, all), HV_BAD_ARGUMENT, "16 KiB alignment");

        // Memory that can only ever be read: a read-only file, shared.
        let path = std::env::temp_dir().join(format!("fwe-standin-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 0x4000]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        use std::os::fd::AsRawFd;
        let ro = map(0x4000, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd());
        let rx = HV_MEMORY_READ | HV_MEMORY_EXEC;
        assert_eq!(vm_map(ro, 0x30_0000, 0x4000, rx), HV_BAD_ARGUMENT, "the vfork child's case");
        let _ = std::fs::remove_file(&path);

        // SAFETY: unmapping a host range this test owns.
        unsafe { libc::munmap(rw.cast::<u8>().add(0x4000).cast(), 0x4000) };
        // SAFETY: an address inside the (shrunk) mapping above.
        let gone = unsafe { rw.cast::<u8>().add(0x4000) }.cast();
        assert_eq!(
            vm_map(gone, 0x40_0000, 0x4000, all),
            HV_BAD_ARGUMENT,
            "host memory must be mapped"
        );

        assert_eq!(vm_unmap(0x10_0000, 0x8000), HV_BAD_ARGUMENT, "unmap only what is mapped");
        assert_eq!(vm_unmap(0x10_0000, 0x4000), HV_SUCCESS);

        let (mut id, mut exit) = (0, std::ptr::null_mut());
        assert_eq!(vcpu_create(&mut id, &mut exit, std::ptr::null_mut()), HV_SUCCESS);
        let other = std::thread::spawn(move || {
            let mut x = 0;
            (vcpu_get_reg(id, HV_REG_PC, &mut x), vcpu_destroy(id))
        });
        assert_eq!(
            other.join().unwrap(),
            (HV_BAD_ARGUMENT, HV_BAD_ARGUMENT),
            "vCPUs are per thread"
        );
        assert_eq!(vcpu_run(id), HV_ERROR, "no run before the translation regime is set");
        assert_eq!(vm_destroy(), HV_BUSY, "vCPUs go before the VM");
        let mut one = id;
        assert_eq!(vcpus_exit(&mut one, 1), HV_SUCCESS);
        assert_eq!(vcpu_destroy(id), HV_SUCCESS);
        assert_eq!(vm_destroy(), HV_SUCCESS);

        rules_of_a_running_vm();
    }

    /// Page tables for the small VMs below, in their own guest memory.
    struct TestPool {
        host: u64,
        ipa: u64,
        next: u64,
    }

    impl crate::hv::pagetables::Pool for TestPool {
        fn alloc(&mut self) -> Option<(u64, *mut u64)> {
            self.next += 0x1000;
            let ipa = self.ipa + self.next - 0x1000;
            let h = self.host(ipa);
            // SAFETY: a page of the test's own memory.
            unsafe { std::ptr::write_bytes(h, 0, 512) };
            Some((ipa, h))
        }
        fn free(&mut self, _ipa: u64) {}
        fn host(&self, ipa: u64) -> *mut u64 {
            (self.host + (ipa - self.ipa)) as *mut u64
        }
    }

    const CODE_VA: u64 = 0x40_0000;
    const VECTORS_VA: u64 = crate::hv::pagetables::VA_LIMIT - 0x1000;
    const LEN: u64 = 2 << 20;

    /// A VM as fwe sets one up, small: 2 MiB of guest memory at IPA 0 —
    /// guest code (`svc #0; b .`) at IPA 0, mapped at `CODE_VA`; a vector
    /// whose entries are `entry; b .` and the TLB stub at IPA 0x4000,
    /// mapped for EL1 at the top; the tables from IPA 1 MiB — and a vCPU
    /// set to run the guest code. Its host memory and vCPU.
    fn small_vm(entry: u32, memory: *mut c_void) -> (u64, hv_vcpu_t) {
        use crate::hv::pagetables::{PageTables, Perms};
        assert_eq!(vm_create(std::ptr::null_mut()), HV_SUCCESS);
        let host = memory as u64;
        // SAFETY: writing the test's own memory.
        unsafe {
            (host as *mut u32).write(0xd400_0001); // svc #0
            ((host + 4) as *mut u32).write(0x1400_0000); // b .
            for e in 0..16u64 {
                ((host + 0x4000 + e * 0x80) as *mut u32).write(entry);
                ((host + 0x4000 + e * 0x80 + 4) as *mut u32).write(0x1400_0000);
            }
            for (i, w) in TLB_STUB.iter().enumerate() {
                ((host + 0x4800 + 4 * i as u64) as *mut u32).write(*w);
            }
        }
        let all = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        assert_eq!(vm_map(memory, 0, LEN as usize, all), HV_SUCCESS);
        let pool = TestPool { host: host + (1 << 20), ipa: 1 << 20, next: 0 };
        let mut t = PageTables::new(pool).unwrap();
        let rx = Perms { read: true, write: false, exec: true, guarded: false };
        let _ = t.map(CODE_VA, 0x1000, 0, rx).unwrap();
        t.map_el1_code(VECTORS_VA, 0x4000).unwrap();
        let (mut id, mut exit) = (0, std::ptr::null_mut());
        assert_eq!(vcpu_create(&mut id, &mut exit, std::ptr::null_mut()), HV_SUCCESS);
        for (reg, value) in [
            (HV_SYS_REG_TTBR0_EL1, t.root()),
            (HV_SYS_REG_TCR_EL1, crate::hv::pagetables::tcr()),
            (HV_SYS_REG_VBAR_EL1, VECTORS_VA),
            (HV_SYS_REG_SCTLR_EL1, 1),
            (HV_SYS_REG_CPACR_EL1, 0b11 << 20),
        ] {
            assert_eq!(vcpu_set_sys_reg(id, reg, value), HV_SUCCESS);
        }
        assert_eq!(vcpu_set_reg(id, HV_REG_PC, CODE_VA), HV_SUCCESS);
        assert_eq!(vcpu_set_reg(id, HV_REG_CPSR, 0), HV_SUCCESS);
        (host, id)
    }

    fn fresh_memory() -> *mut c_void {
        map(
            LEN as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
        )
    }

    fn end(id: hv_vcpu_t) {
        assert_eq!(vcpu_destroy(id), HV_SUCCESS);
        assert_eq!(vm_destroy(), HV_SUCCESS);
    }

    /// Each rule a running VM must keep, broken on purpose: the stand-in
    /// reports it. (A VM is one per process: one after the other.)
    fn rules_of_a_running_vm() {
        let broken = || VIOLATIONS.load(SeqCst);

        // As fwe runs it: the guest's `svc` reaches the backend through the
        // vector's `hvc #2`, with ESR_EL1 telling it was an `svc`.
        let (_, id) = small_vm(0xd400_0042, fresh_memory());
        let before = broken();
        assert_eq!(vcpu_run(id), HV_SUCCESS);
        let mut esr = 0;
        let _ = vcpu_get_sys_reg(id, HV_SYS_REG_ESR_EL1, &mut esr);
        assert_eq!(esr >> 26, 0x15, "an svc");
        assert_eq!(broken(), before, "nothing broken");
        // Stage 2 may not change once the VM has run.
        assert_eq!(vm_unmap(0, LEN as usize), HV_SUCCESS);
        assert_eq!(broken(), before + 1, "the VM's stage 2 changed while it ran");
        end(id);

        // `hvc #0` in the vector: refused.
        let (_, id) = small_vm(0xd400_0002, fresh_memory());
        let before = broken();
        assert_eq!(vcpu_run(id), HV_ERROR);
        assert_eq!(broken(), before + 1, "a vector of hvc #0");
        end(id);

        // EL1 anywhere but fwe's TLB stub: refused.
        let (_, id) = small_vm(0xd400_0042, fresh_memory());
        assert_eq!(vcpu_set_reg(id, HV_REG_CPSR, 0x3c5), HV_SUCCESS);
        let before = broken();
        assert_eq!(vcpu_run(id), HV_ERROR);
        assert_eq!(broken(), before + 1, "EL1 outside the stub");
        end(id);

        // Host memory behind stage 2 replaced: reported.
        let memory = fresh_memory();
        let (host, id) = small_vm(0xd400_0042, memory);
        assert_eq!(vcpu_run(id), HV_SUCCESS);
        let before = broken();
        // SAFETY: the test's own memory, replaced at the same address.
        let p = unsafe {
            libc::mmap(
                (host + 0x8000) as *mut c_void,
                0x4000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(p as u64, host + 0x8000);
        // SAFETY: touching the new page, so it has an object of its own.
        unsafe { ((host + 0x8000) as *mut u8).write_volatile(1) };
        check_objects(vm().as_mut().unwrap());
        assert!(broken() > before, "host memory behind stage 2 replaced");
        end(id);

        // Anonymous memory behind stage 2 also mapped elsewhere (as a
        // vfork child's VM once shared its parent's): reported at the run.
        let shared = map(
            LEN as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_SHARED,
            -1,
        );
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_make_memory_entry_64(
                t: u32,
                size: *mut u64,
                off: u64,
                perm: i32,
                h: *mut u32,
                p: u32,
            ) -> i32;
            fn mach_vm_map(
                t: u32,
                a: *mut u64,
                s: u64,
                m: u64,
                f: i32,
                o: u32,
                off: u64,
                c: i32,
                cur: i32,
                max: i32,
                inh: u32,
            ) -> i32;
        }
        let (mut size, mut entry, mut alias) = (LEN, 0u32, 0u64);
        // SAFETY: a share of the test's own memory, mapped a second time.
        unsafe {
            assert_eq!(
                mach_make_memory_entry_64(
                    mach_task_self_,
                    &mut size,
                    shared as u64,
                    0x40_0000 | 3,
                    &mut entry,
                    0
                ),
                0
            );
            assert_eq!(
                mach_vm_map(mach_task_self_, &mut alias, LEN, 0, 1, entry, 0, 0, 3, 3, 0),
                0
            );
            (shared as *mut u8).write_volatile(1);
        }
        let (_, id) = small_vm(0xd400_0042, shared);
        let before = broken();
        assert_eq!(vcpu_run(id), HV_SUCCESS);
        assert!(broken() > before, "anonymous memory behind stage 2 shared");
        end(id);
    }
}
