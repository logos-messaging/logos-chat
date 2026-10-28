//! Raw FFI declarations for liblogosdelivery's typed call surface.
//!
//! The library exposes its calls as `static inline` helpers in its generated
//! header (CBOR on the wire underneath), so `csrc/shim.c` re-exports the ones
//! used here as linkable `lcshim_*` symbols. The event registry stays on the
//! raw callback shape. No `#[link]` attribute — build.rs compiles the shim and
//! links liblogosdelivery.
#![allow(unused)]

use std::os::raw::{c_char, c_int, c_void};
use std::slice;

pub const RET_OK: i32 = 0;
/// A non-terminal progress tick; a terminal code always follows it.
pub const RET_STALE_WARN: i32 = 3;

/// The node handle the typed helpers hand out and take back. Opaque here: only
/// the shim reads the raw pointer inside it.
#[repr(C)]
pub struct LogosDeliveryCtx {
    _private: [u8; 0],
}

/// Reply to [`lcshim_create`]: the new context on success, else an error message.
pub type CreateFn = unsafe extern "C" fn(c_int, *mut LogosDeliveryCtx, *const c_char, *mut c_void);

/// Reply shape shared by every other typed call: on success `reply` points at
/// the reply string, on failure `err_msg` holds the error. Both are borrowed.
pub type ReplyFn = unsafe extern "C" fn(c_int, *const *const c_char, *const c_char, *mut c_void);

/// Raw event callback: `buffer` is `buffer_len` bytes of JSON, not NUL-terminated.
pub type FFICallBack = unsafe extern "C" fn(c_int, *const c_char, usize, *const c_void);

unsafe extern "C" {
    pub fn lcshim_create(config_json: *const c_char, cb: CreateFn, user_data: *mut c_void)
    -> c_int;

    pub fn lcshim_destroy(ctx: *mut LogosDeliveryCtx) -> c_int;

    pub fn lcshim_start_node(
        ctx: *const LogosDeliveryCtx,
        cb: ReplyFn,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn lcshim_stop_node(
        ctx: *const LogosDeliveryCtx,
        cb: ReplyFn,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn lcshim_subscribe(
        ctx: *const LogosDeliveryCtx,
        content_topic: *const c_char,
        cb: ReplyFn,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn lcshim_unsubscribe(
        ctx: *const LogosDeliveryCtx,
        content_topic: *const c_char,
        cb: ReplyFn,
        user_data: *mut c_void,
    ) -> c_int;

    /// `message_json`: `{"contentTopic": "...", "payload": "<base64>", "ephemeral": false}`
    pub fn lcshim_send(
        ctx: *const LogosDeliveryCtx,
        message_json: *const c_char,
        cb: ReplyFn,
        user_data: *mut c_void,
    ) -> c_int;

    /// Registers `cb` for the named event (e.g. `onMessageReceived`). Returns a
    /// non-zero listener id, or 0 on an invalid context.
    pub fn lcshim_add_event_listener(
        ctx: *const LogosDeliveryCtx,
        event_name: *const c_char,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> u64;
}

// ── Trampoline ───────────────────────────────────────────────────────────────

pub unsafe extern "C" fn trampoline<C>(
    return_val: c_int,
    buffer: *const c_char,
    buffer_len: usize,
    data: *const c_void,
) where
    C: FnMut(i32, &str),
{
    if data.is_null() || return_val == RET_STALE_WARN {
        return;
    }
    let closure = unsafe { &mut *(data as *mut C) };
    if buffer.is_null() || buffer_len == 0 {
        closure(return_val, "");
        return;
    }
    let bytes = unsafe { slice::from_raw_parts(buffer as *const u8, buffer_len) };
    let s = String::from_utf8_lossy(bytes);
    closure(return_val, &s);
}

pub fn get_trampoline<C>(_: &C) -> FFICallBack
where
    C: FnMut(i32, &str),
{
    trampoline::<C>
}
