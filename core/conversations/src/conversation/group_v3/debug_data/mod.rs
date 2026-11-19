//! What GroupV3 keeps for its debug data. With the `debug-data` feature, each member's group
//! state. Without it, nothing.

#[cfg(feature = "debug-data")]
mod member_states;
#[cfg(not(feature = "debug-data"))]
mod noop;

#[cfg(feature = "debug-data")]
pub(super) use member_states::DebugState;
#[cfg(not(feature = "debug-data"))]
pub(super) use noop::DebugState;
