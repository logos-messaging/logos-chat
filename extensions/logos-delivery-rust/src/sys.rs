//! Raw FFI declarations matching liblogosdelivery.h (trampoline pattern).
//!
//! No `#[link]` attribute — build.rs handles linking to liblogosdelivery.
#![allow(unused)]

use std::os::raw::{c_char, c_int, c_void};
use std::slice;

pub const RET_OK: i32 = 0;
/// Non-terminal progress tick; the terminal reply follows on the same callback.
pub const RET_STALE_WARN: i32 = 3;

pub type FFICallBack = unsafe extern "C" fn(c_int, *const c_char, usize, *const c_void);

unsafe extern "C" {
    pub fn logosdelivery_create_node(
        req_cbor: *const u8,
        req_cbor_len: usize,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> *mut c_void;

    pub fn logosdelivery_start_node(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;

    pub fn logosdelivery_stop_node(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;

    pub fn logosdelivery_destroy(ctx: *mut c_void) -> c_int;

    pub fn logosdelivery_subscribe(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;

    pub fn logosdelivery_unsubscribe(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;

    /// Request: CBOR `{"messageJson": <json>}`, where the JSON is
    /// `{"contentTopic": "...", "payload": "<base64>", "ephemeral": false}`.
    pub fn logosdelivery_send(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;

    /// Returns a non-zero listener id, or 0 on an invalid context.
    pub fn logosdelivery_add_event_listener(
        ctx: *mut c_void,
        event_name: *const c_char,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> u64;

    pub fn logosdelivery_get_node_info(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        req_cbor: *const u8,
        req_cbor_len: usize,
    ) -> c_int;
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
    if data.is_null() {
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

/// Trampoline for request replies: skips progress ticks and CBOR-decodes the
/// success payload to a string. Error payloads are plain text.
pub unsafe extern "C" fn reply_trampoline<C>(
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
    let bytes = if buffer.is_null() {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(buffer as *const u8, buffer_len) }
    };
    if return_val != RET_OK {
        closure(return_val, &String::from_utf8_lossy(bytes));
        return;
    }
    match ciborium::from_reader::<String, _>(bytes) {
        Ok(s) => closure(return_val, &s),
        Err(e) => closure(1, &format!("reply decode failed: {e}")),
    }
}

pub fn get_reply_trampoline<C>(_: &C) -> FFICallBack
where
    C: FnMut(i32, &str),
{
    reply_trampoline::<C>
}
