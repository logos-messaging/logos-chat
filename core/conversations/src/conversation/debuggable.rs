//! What a conversation reports about itself for debugging, with the `debug-data` feature. Without
//! it, every type is `Debuggable` and reports nothing.

#[cfg(feature = "debug-data")]
pub(crate) trait Debuggable {
    /// What the conversation reports about itself for debugging, under its own names.
    fn debug_data(&self) -> crate::DebugData;
}

#[cfg(not(feature = "debug-data"))]
pub(crate) trait Debuggable {}

#[cfg(not(feature = "debug-data"))]
impl<T: ?Sized> Debuggable for T {}
