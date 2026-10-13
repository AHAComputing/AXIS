//! A C ABI for the lifter, so a compiled consumer can link it.
//!
//! The lifter is a Rust library and was reachable only through the `axis`
//! command, which meant every consumer spawned a process, re-parsed the whole
//! description, and read the result back as text. That is fine for a person at
//! a terminal and wrong for a program: the sweep in `lift_region_check.py`
//! spent most of its time re-parsing a nine-hundred-instruction description,
//! once per instruction.
//!
//! So the description is parsed once into a handle, and the handle answers
//! questions. The shape is the one `emit-decode-abi-c` already established for
//! decode: plain integers and buffers, no ownership crossing the boundary.
//!
//! Every entry point takes an output buffer and a capacity and returns **the
//! number of bytes the answer needs** -- so a caller sizes the buffer by asking
//! with a capacity of zero, then asks again. A negative return is an error and
//! `axis_lift_last_error` describes it. Nothing here allocates on the caller's
//! behalf and nothing but the handle outlives a call.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::sync::Mutex;

use crate::ast::Document;
use crate::lifter::{
    decode_region, describe_region, describe_support, lift_blocks, lift_preamble,
    lift_region, DecodeTable,
};

/// A parsed description, ready to lift with.
pub struct AxisLifter {
    document: Document,
    table: DecodeTable,
}

static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

fn set_error(message: &str) {
    let text = CString::new(message).unwrap_or_else(|_| CString::new("error").unwrap());
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(text);
    }
}

/// The last error, or an empty string. Valid until the next failing call.
///
/// # Safety
/// The returned pointer is owned by the library and must not be freed.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_last_error() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    match LAST_ERROR.lock() {
        Ok(slot) => match slot.as_ref() {
            Some(text) => text.as_ptr(),
            None => EMPTY.as_ptr() as *const c_char,
        },
        Err(_) => EMPTY.as_ptr() as *const c_char,
    }
}

/// Copy `text` into `out`, returning the length it needs.
///
/// The length is returned whether or not it fitted, which is what lets a caller
/// ask with no buffer and then allocate exactly once.
fn deliver(text: &str, out: *mut c_char, capacity: isize) -> isize {
    let needed = text.len() as isize;
    if out.is_null() || capacity <= 0 {
        return needed;
    }
    let room = (capacity as usize - 1).min(text.len());
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), out as *mut u8, room);
        *out.add(room) = 0;
    }
    needed
}

/// Parse a description. Returns null on failure; see `axis_lift_last_error`.
///
/// # Safety
/// `path` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_open(path: *const c_char) -> *mut AxisLifter {
    if path.is_null() {
        set_error("axis_lift_open: null path");
        return std::ptr::null_mut();
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(text) => text,
        Err(_) => {
            set_error("axis_lift_open: path is not UTF-8");
            return std::ptr::null_mut();
        }
    };
    let source = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            set_error(&format!("axis_lift_open: {path}: {err}"));
            return std::ptr::null_mut();
        }
    };
    let document = match crate::parse_document(&source) {
        Ok(document) => document,
        Err(err) => {
            set_error(&format!("axis_lift_open: {err}"));
            return std::ptr::null_mut();
        }
    };
    let table = DecodeTable::new(&document);
    Box::into_raw(Box::new(AxisLifter { document, table }))
}

/// Release a handle.
///
/// # Safety
/// `handle` must come from `axis_lift_open` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_close(handle: *mut AxisLifter) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Common shape for the three queries: borrow the handle, run, deliver text.
///
/// The closure runs inside `catch_unwind` because a panic crossing a C frame is
/// undefined behaviour, and the lowering does still panic on shapes it has not
/// met -- a caller gets an error return instead of a corrupted process.
unsafe fn answer<F>(
    handle: *const AxisLifter,
    out: *mut c_char,
    capacity: isize,
    what: &str,
    body: F,
) -> isize
where
    F: FnOnce(&AxisLifter) -> Result<String, String> + std::panic::UnwindSafe,
{
    if handle.is_null() {
        set_error(&format!("{what}: null handle"));
        return -1;
    }
    let lifter = &*handle;
    let guarded = std::panic::AssertUnwindSafe(|| body(lifter));
    match std::panic::catch_unwind(guarded) {
        Ok(Ok(text)) => deliver(&text, out, capacity),
        Ok(Err(message)) => {
            set_error(&format!("{what}: {message}"));
            -1
        }
        Err(_) => {
            set_error(&format!("{what}: the lowering panicked"));
            -2
        }
    }
}

unsafe fn borrow_isa(isa: *const c_char) -> Option<String> {
    if isa.is_null() {
        return None;
    }
    CStr::from_ptr(isa).to_str().ok().map(str::to_owned)
}

unsafe fn borrow_bytes<'a>(bytes: *const c_uchar, count: isize) -> &'a [u8] {
    if bytes.is_null() || count <= 0 {
        &[]
    } else {
        std::slice::from_raw_parts(bytes, count as usize)
    }
}

/// Where this region's basic blocks are, as text: one line per instruction and
/// a line naming each block's exit. The same report `axis lift-blocks` prints.
///
/// # Safety
/// `handle` must be live; `bytes` must hold `byte_count` readable bytes; `out`
/// must hold `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_blocks(
    handle: *const AxisLifter,
    bytes: *const c_uchar,
    byte_count: isize,
    address: u64,
    isa: *const c_char,
    out: *mut c_char,
    capacity: isize,
) -> isize {
    let image = borrow_bytes(bytes, byte_count).to_vec();
    let isa = borrow_isa(isa);
    answer(handle, out, capacity, "axis_lift_blocks", move |lifter| {
        let region = decode_region(&lifter.table, &image, address, isa.as_deref());
        Ok(describe_region(&region))
    })
}

/// Lift a region to an LLVM module: one function per basic block, with the
/// semantics helpers it calls, so the module needs nothing linked to it.
///
/// # Safety
/// As `axis_lift_blocks`.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_llvm(
    handle: *const AxisLifter,
    bytes: *const c_uchar,
    byte_count: isize,
    address: u64,
    isa: *const c_char,
    out: *mut c_char,
    capacity: isize,
) -> isize {
    let image = borrow_bytes(bytes, byte_count).to_vec();
    let isa = borrow_isa(isa);
    answer(handle, out, capacity, "axis_lift_llvm", move |lifter| {
        let region = decode_region(&lifter.table, &image, address, isa.as_deref());
        lift_region(&lifter.document, &region, isa.as_deref()).map_err(|err| err.message)
    })
}

/// The part of a lifted module that does not depend on the bytes: the semantics
/// helpers the lowered arithmetic calls.
///
/// Thirty thousand lines for AArch64, and the same for every region. A consumer
/// lifting a binary asks for this once, then appends each region's blocks --
/// which is what `axis_lift_llvm_blocks` returns. `axis_lift_llvm` is the two
/// together, for a caller that wants one self-contained module.
///
/// # Safety
/// `handle` must be live; `out` must hold `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_preamble(
    handle: *const AxisLifter,
    out: *mut c_char,
    capacity: isize,
) -> isize {
    answer(handle, out, capacity, "axis_lift_preamble", |lifter| {
        Ok(lift_preamble(&lifter.document))
    })
}

/// A region's block functions, without the preamble.
///
/// # Safety
/// As `axis_lift_blocks`.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_llvm_blocks(
    handle: *const AxisLifter,
    bytes: *const c_uchar,
    byte_count: isize,
    address: u64,
    isa: *const c_char,
    out: *mut c_char,
    capacity: isize,
) -> isize {
    let image = borrow_bytes(bytes, byte_count).to_vec();
    let isa = borrow_isa(isa);
    answer(handle, out, capacity, "axis_lift_llvm_blocks", move |lifter| {
        let region = decode_region(&lifter.table, &image, address, isa.as_deref());
        lift_blocks(&lifter.document, &region, isa.as_deref()).map_err(|err| err.message)
    })
}

/// What this description's instructions lift to, one `mnemonic\tverdict` line
/// each: `ok`, or the reason the lowering refuses it.
///
/// Acceptance is a statement about the rules, not a promise about the result --
/// see `docs/lifter_design.md`.
///
/// # Safety
/// `handle` must be live; `out` must hold `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_support(
    handle: *const AxisLifter,
    out: *mut c_char,
    capacity: isize,
) -> isize {
    answer(handle, out, capacity, "axis_lift_support", |lifter| {
        Ok(describe_support(&lifter.document))
    })
}

/// How many instruction encodings this description has, which is a cheap way
/// for a caller to check the handle opened the file it meant.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn axis_lift_instruction_count(handle: *const AxisLifter) -> c_int {
    if handle.is_null() {
        return -1;
    }
    (*handle).table.rows.len() as c_int
}
