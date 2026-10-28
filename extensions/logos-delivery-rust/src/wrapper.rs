//! Safe synchronous wrapper around the liblogosdelivery typed FFI.
//!
//! # Why Box::into_raw for one-shot replies?
//!
//! The typed helpers return as soon as the request is handed to the FFI thread;
//! the reply callback fires later, from the Nim async event loop, after the
//! Rust call frame has returned and its stack variables are gone. Passing a
//! stack address as `user_data` would therefore dangle by the time the reply
//! arrives.
//!
//! Fix: heap-allocate the reply sender with `Box::into_raw` and block on its
//! channel. Each helper calls its reply callback exactly once — including when
//! it fails before submitting — so the trampoline takes the box back and frees
//! it there.
//!
//! # Why store the event callback inside LogosNodeCtx?
//!
//! Rust drops locals in reverse declaration order. If the event-callback box
//! were held by the caller (outside the node), it would be freed before the
//! node's Drop runs stop+destroy. During stop/destroy the Nim async event
//! loop can still fire the event callback, which would access freed memory.
//!
//! By storing the box as `_event_cb` inside `LogosNodeCtx`, Rust's field-drop
//! order guarantees it is freed *after* Drop::drop returns (i.e. after
//! stop+destroy complete), so the pointer is always valid when Nim calls it.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc;

use super::sys::{self as ffi, LogosDeliveryCtx, RET_OK, ReplyFn, get_trampoline};

type Reply = Result<String, String>;

/// Opaque handle to a logos-delivery node context.
pub struct LogosNodeCtx {
    ctx: *mut LogosDeliveryCtx,
    /// Keeps the event-callback closure alive for the lifetime of the node.
    _event_cb: Option<Box<dyn std::any::Any + Send>>,
}

// The logos-delivery ctx pointer is thread-safe (serialized calls inside C/Nim).
unsafe impl Send for LogosNodeCtx {}
unsafe impl Sync for LogosNodeCtx {}

/// Copies a borrowed C string, treating null as empty.
fn copy_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

unsafe extern "C" fn reply_trampoline(
    err_code: c_int,
    reply: *const *const c_char,
    err_msg: *const c_char,
    user_data: *mut c_void,
) {
    let tx = unsafe { Box::from_raw(user_data as *mut mpsc::SyncSender<Reply>) };
    let result = if err_code == RET_OK {
        Ok(if reply.is_null() {
            String::new()
        } else {
            copy_cstr(unsafe { *reply })
        })
    } else {
        Err(copy_cstr(err_msg))
    };
    let _ = tx.send(result);
}

/// Makes one typed call and blocks until its reply arrives.
fn call(op: &str, f: impl FnOnce(ReplyFn, *mut c_void) -> c_int) -> Reply {
    let (tx, rx) = mpsc::sync_channel::<Reply>(1);
    let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;
    // A non-zero return still delivers its error through the reply callback.
    let _ = f(reply_trampoline, user_data);
    rx.recv()
        .unwrap_or_else(|_| Err(format!("{op}: callback channel disconnected")))
}

/// Where a created context is reported; `usize` because a raw pointer is not `Send`.
type Created = Result<usize, String>;

unsafe extern "C" fn create_trampoline(
    err_code: c_int,
    ctx: *mut LogosDeliveryCtx,
    err_msg: *const c_char,
    user_data: *mut c_void,
) {
    let tx = unsafe { Box::from_raw(user_data as *mut mpsc::SyncSender<Created>) };
    let result = if err_code == RET_OK && !ctx.is_null() {
        Ok(ctx as usize)
    } else {
        Err(copy_cstr(err_msg))
    };
    let _ = tx.send(result);
}

impl LogosNodeCtx {
    pub fn new(config_json: &str) -> Result<Self, String> {
        let config_cstr = CString::new(config_json).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Created>(1);
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;
        let _ = unsafe { ffi::lcshim_create(config_cstr.as_ptr(), create_trampoline, user_data) };
        let ctx = rx
            .recv()
            .unwrap_or_else(|_| Err("create: callback channel disconnected".into()))?;

        Ok(Self {
            ctx: ctx as *mut LogosDeliveryCtx,
            _event_cb: None,
        })
    }

    pub fn start(&self) -> Result<(), String> {
        call("start_node", |cb, ud| unsafe {
            ffi::lcshim_start_node(self.ctx, cb, ud)
        })
        .map(|_| ())
    }

    pub fn subscribe(&self, content_topic: &str) -> Result<(), String> {
        let topic_cstr = CString::new(content_topic).map_err(|e| e.to_string())?;
        call("subscribe", |cb, ud| unsafe {
            ffi::lcshim_subscribe(self.ctx, topic_cstr.as_ptr(), cb, ud)
        })
        .map(|_| ())
    }

    pub fn unsubscribe(&self, content_topic: &str) -> Result<(), String> {
        let topic_cstr = CString::new(content_topic).map_err(|e| e.to_string())?;
        call("unsubscribe", |cb, ud| unsafe {
            ffi::lcshim_unsubscribe(self.ctx, topic_cstr.as_ptr(), cb, ud)
        })
        .map(|_| ())
    }

    /// Returns the request ID on success.
    pub fn send(&self, message_json: &str) -> Result<String, String> {
        let msg_cstr = CString::new(message_json).map_err(|e| e.to_string())?;
        call("send", |cb, ud| unsafe {
            ffi::lcshim_send(self.ctx, msg_cstr.as_ptr(), cb, ud)
        })
    }

    /// Registers the event callback for `event_name` (e.g. `onMessageReceived`)
    /// and stores it inside the node so it is dropped *after* stop+destroy in
    /// Drop, keeping the pointer valid for the node's lifetime.
    pub fn set_event_callback<C>(&mut self, event_name: &str, closure: C) -> Result<(), String>
    where
        C: FnMut(i32, &str) + Send + 'static,
    {
        let name_cstr = CString::new(event_name).map_err(|e| e.to_string())?;
        let mut boxed = Box::new(closure);
        let cb = get_trampoline(&*boxed);
        let user_data = &mut *boxed as *mut C as *const c_void;
        let listener_id =
            unsafe { ffi::lcshim_add_event_listener(self.ctx, name_cstr.as_ptr(), cb, user_data) };
        if listener_id == 0 {
            return Err(format!(
                "add_event_listener({event_name}) rejected the context"
            ));
        }
        // Move the box into self; the heap address (user_data) is unaffected.
        self._event_cb = Some(boxed);
        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        call("stop_node", |cb, ud| unsafe {
            ffi::lcshim_stop_node(self.ctx, cb, ud)
        })
        .map(|_| ())
    }
}

impl Drop for LogosNodeCtx {
    fn drop(&mut self) {
        // stop+destroy must complete before _event_cb is freed.
        // Rust drops fields after Drop::drop returns, so _event_cb outlives
        // everything below — the event callback pointer stays valid throughout.
        if let Err(e) = self.stop() {
            tracing::warn!("logosdelivery stop_node failed during drop: {e}");
        }
        // Synchronous; also releases the context allocated at create.
        unsafe { ffi::lcshim_destroy(self.ctx) };
    }
}
