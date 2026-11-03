//! Safe synchronous wrapper around the raw liblogosdelivery FFI.
//!
//! # Why Box::into_raw for one-shot callbacks?
//!
//! `sendRequestToFFIThread` (nim-ffi) signals the caller as soon as the FFI
//! thread *receives* the request, before it processes it. The actual result
//! callback fires later, from the Nim async event loop, after the Rust call
//! frame has returned and its stack variables are gone. Passing `&mut closure`
//! as `user_data` therefore produces a dangling pointer by the time the
//! callback fires — a use-after-free that manifests as a SIGSEGV when the
//! operation fails and the callback tries to write an error into captured
//! stack memory.
//!
//! Fix: heap-allocate each one-shot closure with `Box::into_raw`, synchronise
//! via an `mpsc` channel (blocking until the callback fires), then drop the
//! box. The pointer is valid for the entire async lifetime of the request.
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

use std::collections::BTreeMap;
use std::os::raw::c_void;
use std::sync::mpsc;

use super::sys::{self as ffi, RET_OK, get_reply_trampoline, get_trampoline};

/// Encodes a request envelope: a CBOR map of string fields.
fn cbor_req(fields: &[(&str, &str)]) -> Vec<u8> {
    let map: BTreeMap<_, _> = fields.iter().copied().collect();
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("CBOR encoding into a Vec cannot fail");
    buf
}

/// Opaque handle to a logos-delivery node context.
pub struct LogosNodeCtx {
    ctx: *mut c_void,
    /// Keeps the event-callback closure alive for the lifetime of the node.
    _event_cb: Option<Box<dyn std::any::Any + Send>>,
}

// The logos-delivery ctx pointer is thread-safe (serialized calls inside C/Nim).
unsafe impl Send for LogosNodeCtx {}
unsafe impl Sync for LogosNodeCtx {}

impl LogosNodeCtx {
    pub fn new(config_json: &str) -> Result<Self, String> {
        let req = cbor_req(&[("configJson", config_json)]);

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let ctx = unsafe {
            ffi::logosdelivery_create_node(req.as_ptr(), req.len(), cb, raw as *const c_void)
        };

        // create_node may call the callback synchronously (try_recv) or
        // asynchronously (recv). Handle both.
        let callback_result: Result<(), String> = if ctx.is_null() {
            rx.try_recv()
                .unwrap_or(Err("logosdelivery_create_node returned null".into()))
        } else {
            rx.recv()
                .unwrap_or(Err("callback channel disconnected".into()))
        };
        drop(unsafe { Box::from_raw(raw) });

        // A failed create still hands back a live (empty) handle.
        if callback_result.is_err() && !ctx.is_null() {
            unsafe { ffi::logosdelivery_destroy(ctx) };
        }

        callback_result.map(|_| Self {
            ctx,
            _event_cb: None,
        })
    }

    pub fn start(&self) -> Result<(), String> {
        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let req = cbor_req(&[]);
        let ret = unsafe {
            ffi::logosdelivery_start_node(self.ctx, cb, raw as *const c_void, req.as_ptr(), req.len())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_start_node returned {ret}"));
        }
        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }

    pub fn subscribe(&self, content_topic: &str) -> Result<(), String> {
        let req = cbor_req(&[("contentTopicStr", content_topic)]);

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_subscribe(self.ctx, cb, raw as *const c_void, req.as_ptr(), req.len())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_subscribe returned {ret}"));
        }

        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }

    pub fn unsubscribe(&self, content_topic: &str) -> Result<(), String> {
        let req = cbor_req(&[("contentTopicStr", content_topic)]);

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_unsubscribe(self.ctx, cb, raw as *const c_void, req.as_ptr(), req.len())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_unsubscribe returned {ret}"));
        }
        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }

    /// Returns the request ID on success.
    pub fn send(&self, message_json: &str) -> Result<String, String> {
        let req = cbor_req(&[("messageJson", message_json)]);

        let (tx, rx) = mpsc::sync_channel::<Result<String, String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(data.to_string())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_send(self.ctx, cb, raw as *const c_void, req.as_ptr(), req.len())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_send returned {ret}"));
        }
        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }

    /// Registers `closure` for `onMessageReceived` events. Stores it inside the
    /// node so it is dropped *after* stop+destroy in Drop, keeping the pointer
    /// valid for the node's lifetime.
    pub fn set_event_callback<C>(&mut self, closure: C)
    where
        C: FnMut(i32, &str) + Send + 'static,
    {
        let mut boxed = Box::new(closure);
        let cb = get_trampoline(&*boxed);
        let user_data = &mut *boxed as *mut C as *const c_void;
        unsafe {
            ffi::logosdelivery_add_event_listener(
                self.ctx,
                c"onMessageReceived".as_ptr(),
                cb,
                user_data,
            );
        }
        // Move the box into self; the heap address (user_data) is unaffected.
        self._event_cb = Some(boxed);
    }

    pub fn stop(&self) -> Result<(), String> {
        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_reply_trampoline(unsafe { &*raw });

        let req = cbor_req(&[]);
        let ret = unsafe {
            ffi::logosdelivery_stop_node(self.ctx, cb, raw as *const c_void, req.as_ptr(), req.len())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_stop_node returned {ret}"));
        }
        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }
}

impl Drop for LogosNodeCtx {
    fn drop(&mut self) {
        // stop+destroy must complete before _event_cb is freed.
        // Rust drops fields after Drop::drop returns, so _event_cb outlives
        // everything below — the event callback pointer stays valid throughout.
        if let Err(e) = self.stop() {
            tracing::warn!("logosdelivery_stop_node failed during drop: {e}");
        }

        unsafe { ffi::logosdelivery_destroy(self.ctx) };
    }
}
