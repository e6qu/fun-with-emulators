//! A software stand-in for Hypervisor.framework (`fwe --hv-standin`): the
//! calls the backend makes ([`super::ffi`]) carried out by Unicorn, QEMU's
//! CPU emulator as a library, loaded with `dlopen` only in this mode.
//!
//! It exists so the VM backend can be developed and tested without a real
//! VM: the development Mac went down four times while the backend was built
//! (see `docs/hypervisor.md`). It can never prove the real backend works —
//! only the real framework on real hardware can — so VM changes still run
//! there now and then.
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
//! - **Stage 1 is fwe's own tables**, read from guest memory at the first
//!   run: they must map identity blocks, and only what they let EL0 touch is
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
//! CPUs, and running one at a time keeps the guest's atomics atomic. Each
//! Unicorn engine is driven only by its own thread — mapping changes are
//! logged and applied by each vCPU before it next emulates, and a stop is
//! a flag its block hook acts on — as an engine stopped or changed from
//! another thread sometimes resumed with its registers and pc out of step. Not modelled: the virtual
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
const UC_CTL_TB_REMOVE_CACHE_W: u32 = 0x4800_0009;
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
const UC_PROT_ALL: u32 = 7;

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
type MemReadFn = unsafe extern "C" fn(Uc, u64, *mut c_void, u64) -> c_int;
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
    mem_read: MemReadFn,
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
            mem_read: std::mem::transmute::<*mut c_void, MemReadFn>(sym("uc_mem_read")?),
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
    say("VIOLATION: ", msg);
}

/// A note that is not a broken rule. Async-signal-safe.
fn note(msg: &str) {
    say("", msg);
}

fn say(kind: &str, msg: &str) {
    let mut buf = [0u8; 512];
    let mut n = 0;
    for part in ["fwe hv stand-in: ", kind, msg, "\n"] {
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
    /// EL0's view of stage 1, `(start, end, Unicorn permissions)` runs of
    /// fwe's blocks, once read (at the first run).
    stage1: Option<Vec<(u64, u64, u32)>>,
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
    *g = Some(Vm { ipa_bits, maps: BTreeMap::new(), stage1: None });
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
    if host % PAGE != 0 || ipa % PAGE != 0 || len % PAGE != 0 || len == 0 {
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
    let pieces = el0_pieces(v, ipa, end, host, flags);
    let mut ops: Vec<Op> = pieces.iter().map(|&(lo, hi, h, p)| Op::Map(lo, hi, h, p)).collect();
    ops.push(Op::Flush(ipa, end));
    apply(ops);
    HV_SUCCESS
}

pub fn vm_unmap(ipa: u64, size: usize) -> hv_return_t {
    let Some(end) = ipa.checked_add(size as u64) else { return HV_BAD_ARGUMENT };
    if !VM_LIVE.load(SeqCst) {
        violation("hv_vm_unmap without a VM");
        return HV_ERROR;
    }
    if ipa % PAGE != 0 || size as u64 % PAGE != 0 {
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
        gone.extend(
            el0_pieces(v, lo, hi, m.host + (lo - s), m.flags).into_iter().map(|p| (p.0, p.1)),
        );
    }
    let mut ops: Vec<Op> = gone.iter().map(|&(lo, hi)| Op::Unmap(lo, hi)).collect();
    ops.push(Op::Flush(ipa, end));
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
    /// Discard translations of `[lo, hi)`.
    Flush(u64, u64),
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
    let mut e = engine(v);
    let start = e.applied.max(l.base) - l.base;
    for &op in &l.ops[start..] {
        apply_op(v.uc, op);
    }
    e.applied = l.base + l.ops.len();
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
        Op::Flush(lo, hi) => flush(uc, lo, hi),
    }
}

/// Discard translations and translated code for `[lo, hi)`.
fn flush(uc: Uc, lo: u64, hi: u64) {
    // SAFETY: control calls on an engine not emulating.
    unsafe {
        (api().ctl)(uc, UC_CTL_TLB_FLUSH_W);
        (api().ctl)(uc, UC_CTL_TB_REMOVE_CACHE_W, lo, hi);
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

/// `[lo, hi)` (host `host`, framework `flags`) cut along stage-1 blocks,
/// with the Unicorn permissions EL0 ends up with: `(lo, hi, host, perms)`.
/// Before stage 1 is known (no run yet) nothing is mapped for the CPU.
fn el0_pieces(v: &Vm, lo: u64, hi: u64, host: u64, flags: u64) -> Vec<(u64, u64, u64, u32)> {
    let Some(s1) = &v.stage1 else { return Vec::new() };
    let stage2 = (if flags & HV_MEMORY_READ != 0 { UC_PROT_READ } else { 0 })
        | (if flags & HV_MEMORY_WRITE != 0 { UC_PROT_WRITE } else { 0 })
        | (if flags & HV_MEMORY_EXEC != 0 { UC_PROT_EXEC } else { 0 });
    let mut out: Vec<(u64, u64, u64, u32)> = Vec::new();
    for &(bs, be, perms) in s1 {
        let (a, b) = (bs.max(lo), be.min(hi));
        if a >= b {
            continue;
        }
        let p = perms & stage2;
        if p == 0 {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.1 == a && last.3 == p => last.1 = b,
            _ => out.push((a, b, host + (a - lo), p)),
        }
    }
    out
}

/// Read fwe's stage-1 tables from guest memory: identity blocks of 32 MiB
/// under a 16 KiB granule and a 40-bit space, the only regime the backend
/// sets up. Returns the EL0-accessible blocks merged into runs.
fn read_stage1(v: &Vm, ttbr0: u64, tcr: u64) -> Result<Vec<(u64, u64, u32)>, String> {
    if tcr & 0x3f != 24 || (tcr >> 14) & 3 != 0b10 {
        return Err(format!("TCR_EL1 {tcr:#x} is not the 40-bit, 16 KiB-granule regime"));
    }
    let word = |ipa: u64| -> Result<u64, String> {
        let (_, m) = v
            .maps
            .range(..=ipa)
            .next_back()
            .filter(|(_, m)| m.end > ipa + 7)
            .ok_or_else(|| format!("page table at {ipa:#x} is not in guest memory"))?;
        let s = v.maps.range(..=ipa).next_back().map(|(&s, _)| s).unwrap();
        // SAFETY: reading mapped host memory behind guest-physical `ipa`.
        Ok(unsafe { ((m.host + (ipa - s)) as *const u64).read_unaligned() })
    };
    const BLOCK: u64 = 32 << 20;
    let mut runs: Vec<(u64, u64, u32)> = Vec::new();
    let base = ttbr0 & 0x0000_ffff_ffff_c000;
    for i in 0..16u64 {
        let l1 = word(base + i * 8)?;
        if l1 & 3 != 3 {
            continue;
        }
        let l2 = l1 & 0x0000_ffff_ffff_c000;
        for j in 0..(PAGE / 8) {
            let va = i * (64 << 30) + j * BLOCK;
            let d = word(l2 + j * 8)?;
            if d & 3 != 1 {
                continue;
            }
            if d & 0x0000_ffff_fe00_0000 != va {
                return Err(format!(
                    "stage 1 maps {va:#x} to {:#x}, not to itself",
                    d & 0x0000_ffff_fe00_0000
                ));
            }
            if d & (1 << 10) == 0 {
                return Err(format!("stage 1 block at {va:#x} has no access flag"));
            }
            let ap = (d >> 6) & 3;
            let uxn = d & (1 << 54) != 0;
            let perms = match ap {
                0b01 => UC_PROT_READ | UC_PROT_WRITE,
                0b11 => UC_PROT_READ,
                _ => 0, // EL1 only
            } | if !uxn && ap & 1 == 1 { UC_PROT_EXEC } else { 0 };
            if perms == 0 {
                continue;
            }
            match runs.last_mut() {
                Some(last) if last.1 == va && last.2 == perms => last.1 = va + BLOCK,
                _ => runs.push((va, va + BLOCK, perms)),
            }
        }
    }
    Ok(runs)
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
        }),
        exit: exit_rec,
        // SAFETY: plain host call.
        owner: unsafe { libc::pthread_self() },
        cancel: AtomicBool::new(false),
        yield_now: AtomicBool::new(false),
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
        if !engine(v).synced {
            if let Err(e) = sync(v) {
                violation(&e);
                return HV_ERROR;
            }
        }
        if take_turn(me, &cancelled).is_none() {
            continue;
        }
        catch_up(v);
        let mut e = engine(v);
        e.event = None;
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
                // `hvc #0` (ESR_EL2: EC 0x16, IL).
                exit.exception = hv_vcpu_exit_exception_t {
                    syndrome: (0x16 << 26) | (1 << 25),
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
            exit.reason = HV_EXIT_REASON_EXCEPTION;
            exit.exception = hv_vcpu_exit_exception_t {
                syndrome: (0x20 << 26) | (1 << 25) | 0x07,
                virtual_address: 0,
                physical_address: 0,
            };
            return HV_SUCCESS;
        }
        // `wfi`/`wfe` halt the emulated CPU past the instruction; the
        // framework exits at it.
        if let Some(insn) = fetch(v.uc, now.wrapping_sub(4)) {
            if (insn == 0xd503_207f || insn == 0xd503_205f) && !v.cancel.load(SeqCst) && now != pc {
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
        if vmr.stage1.is_none() {
            vmr.stage1 =
                Some(read_stage1(vmr, get(HV_SYS_REG_TTBR0_EL1), get(HV_SYS_REG_TCR_EL1))?);
        }
    }
    let pieces: Vec<(u64, u64, u64, u32)> =
        vmr.maps.iter().flat_map(|(&s, m)| el0_pieces(vmr, s, m.end, m.host, m.flags)).collect();
    take_turn(MAPPER, &|| false);
    // Everything logged so far is in `maps` (the VM lock, held, keeps new
    // changes out meanwhile).
    let l = log();
    let mut e = engine(v);
    e.applied = l.base + l.ops.len();
    drop(l);
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
    e.synced = true;
    drop(e);
    end_turn();
    Ok(())
}

/// The instruction at guest address `pc`, if the CPU has it mapped.
fn fetch(uc: Uc, pc: u64) -> Option<u32> {
    let mut insn = 0u32;
    // SAFETY: reading 4 bytes of the engine's memory into a u32.
    let rc = unsafe { (api().mem_read)(uc, pc, (&mut insn as *mut u32).cast(), 4) };
    (rc == 0).then_some(insn)
}

// --- Hooks ----------------------------------------------------------------------

/// At each block: stop if `hv_vcpus_exit` or another vCPU's turn asks.
extern "C" fn on_block(uc: Uc, _addr: u64, _size: u32, d: *mut c_void) {
    // SAFETY: the hook's data is its vCPU.
    let v = unsafe { &*d.cast::<Vcpu>() };
    if v.cancel.load(SeqCst) || v.yield_now.swap(false, SeqCst) {
        // SAFETY: stopping the engine whose hook this is, on its thread.
        unsafe { (api().emu_stop)(uc) };
    }
}

/// Stage 1 is the identity over the 40-bit space (checked at the first
/// run), with the top byte ignored as TCR_EL1.TBI0 makes it; stage 2 is the
/// emulated memory map, whose permissions Unicorn enforces. An address
/// beyond the space is a level-0 translation fault at EL1.
extern "C" fn on_tlb_fill(uc: Uc, va: u64, t: c_int, out: *mut TlbEntry, d: *mut c_void) -> bool {
    let addr = va & 0x00ff_ffff_ffff_ffff;
    if addr >= 1 << 40 {
        const UC_MEM_FETCH: c_int = 18;
        let pc = read(uc, R_PC);
        let ec = if t == UC_MEM_FETCH { 0x20 } else { 0x24 };
        let wnr = if t == 17 { 1 << 6 } else { 0 };
        record(d, Event::El1 { esr: (ec << 26) | (1 << 25) | wnr | 0x04, elr: pc, far: va });
        return false;
    }
    // SAFETY: Unicorn passes an entry to fill.
    unsafe { *out = TlbEntry { paddr: addr, perms: UC_PROT_ALL } };
    true
}

fn record(d: *mut c_void, ev: Event) {
    // SAFETY: the hook's data is its vCPU, on whose thread hooks run.
    let v = unsafe { &*d.cast::<Vcpu>() };
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
            let imm = fetch(uc, pc - 4).map_or(0, |i| u64::from((i >> 5) & 0xffff));
            Event::El1 { esr: (0x15 << 26) | il | imm, elr: pc, far: 0 }
        }
        EXCP_BKPT => {
            let imm = fetch(uc, pc).map_or(0, |i| u64::from((i >> 5) & 0xffff));
            Event::El1 { esr: (0x3c << 26) | il | imm, elr: pc, far: 0 }
        }
        EXCP_UDEF => Event::El1 { esr: il, elr: pc, far: 0 },
        EXCP_PREFETCH_ABORT if pc & 3 != 0 => {
            Event::El1 { esr: (0x22 << 26) | il, elr: pc, far: pc }
        }
        EXCP_DATA_ABORT => {
            // Alignment (stage 1 never faults otherwise, and stage 2 faults
            // come through the memory hooks): DFSC 0x21.
            let far = fetch(uc, pc).map_or(0, |i| exclusive_or_atomic_base(uc, i));
            let wnr = fetch(uc, pc).map_or(0, |i| u64::from(i & (1 << 22) == 0) << 6);
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
    let insn = fetch(uc, pc).unwrap_or(0);
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

pub fn vcpu_get_reg(id: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_get_reg") else { return HV_BAD_ARGUMENT };
    let _e = engine(v);
    let r = match reg {
        0..=30 => read(v.uc, xreg(reg)),
        HV_REG_PC => read(v.uc, R_PC),
        HV_REG_FPCR => read(v.uc, R_FPCR),
        HV_REG_FPSR => read(v.uc, R_FPSR),
        HV_REG_CPSR => read(v.uc, R_PSTATE),
        _ => return HV_BAD_ARGUMENT,
    };
    // SAFETY: the caller's out-parameter.
    unsafe { *value = r };
    HV_SUCCESS
}

pub fn vcpu_set_reg(id: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t {
    let Some(v) = own(id, "hv_vcpu_set_reg") else { return HV_BAD_ARGUMENT };
    let _e = engine(v);
    match reg {
        0..=30 => write(v.uc, xreg(reg), value),
        HV_REG_PC => write(v.uc, R_PC, value),
        HV_REG_FPCR => write(v.uc, R_FPCR, value),
        HV_REG_FPSR => write(v.uc, R_FPSR, value),
        HV_REG_CPSR => {
            if value & 0xf != 0 {
                violation(&format!(
                    "CPSR {value:#x} leaves EL0, which only the vector may run above"
                ));
                return HV_BAD_ARGUMENT;
            }
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
    WATCH_FD.store(fwe_kernel::fdtable::reserve(fds[1]), SeqCst);
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
    }
}
