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

use std::ffi::CString;
use std::os::raw::c_void;
use std::sync::mpsc;

use super::sys::{self as ffi, RET_OK, get_trampoline};

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
        let config_cstr = CString::new(config_json).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });

        let ctx = unsafe {
            ffi::logosdelivery_create_node(config_cstr.as_ptr(), cb, raw as *const c_void)
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
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe { ffi::logosdelivery_start_node(self.ctx, cb, raw as *const c_void) };

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
        let topic_cstr = CString::new(content_topic).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_subscribe(self.ctx, cb, raw as *const c_void, topic_cstr.as_ptr())
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
        let topic_cstr = CString::new(content_topic).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_unsubscribe(self.ctx, cb, raw as *const c_void, topic_cstr.as_ptr())
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
        let msg_cstr = CString::new(message_json).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Result<String, String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(data.to_string())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_send(self.ctx, cb, raw as *const c_void, msg_cstr.as_ptr())
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

    /// Returns what the node says of itself under `node_info_id`, one of the
    /// ids the library lists: `MyPeerId`, `MyBoundPorts`, `Metrics` and others.
    pub fn node_info(&self, node_info_id: &str) -> Result<String, String> {
        let id_cstr = CString::new(node_info_id).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::sync_channel::<Result<String, String>>(1);
        let closure = move |ret: i32, data: &str| {
            let _ = tx.send(if ret == RET_OK {
                Ok(data.to_string())
            } else {
                Err(data.to_string())
            });
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe {
            ffi::logosdelivery_get_node_info(self.ctx, cb, raw as *const c_void, id_cstr.as_ptr())
        };

        if ret != RET_OK {
            drop(unsafe { Box::from_raw(raw) });
            return Err(format!("logosdelivery_get_node_info returned {ret}"));
        }
        let result = rx
            .recv()
            .unwrap_or(Err("callback channel disconnected".into()));
        drop(unsafe { Box::from_raw(raw) });
        result
    }

    /// Stores the event callback inside the node so it is dropped *after*
    /// stop+destroy in Drop, keeping the pointer valid for the node's lifetime.
    pub fn set_event_callback<C>(&mut self, closure: C)
    where
        C: FnMut(i32, &str) + Send + 'static,
    {
        let mut boxed = Box::new(closure);
        let cb = get_trampoline(&*boxed);
        let user_data = &mut *boxed as *mut C as *const c_void;
        unsafe {
            ffi::logosdelivery_set_event_callback(self.ctx, cb, user_data);
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
        let cb = get_trampoline(unsafe { &*raw });

        let ret = unsafe { ffi::logosdelivery_stop_node(self.ctx, cb, raw as *const c_void) };

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

        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let closure = move |_: i32, _: &str| {
            let _ = tx.send(());
        };
        let raw = Box::into_raw(Box::new(closure));
        let cb = get_trampoline(unsafe { &*raw });
        unsafe { ffi::logosdelivery_destroy(self.ctx, cb, raw as *const c_void) };
        let _ = rx.recv();
        drop(unsafe { Box::from_raw(raw) });
    }
}
