//! GroupV3's debug state without the `debug-data` feature.

use openmls::group::MlsGroup;
use sds::SDSRecord;

use crate::conversation::group_v3::payloads::EpochData;

/// Keeps nothing.
#[derive(Debug, Default)]
pub(crate) struct DebugState {}

impl DebugState {
    pub(crate) fn hear(&mut self, _record: &SDSRecord, _group: &MlsGroup) {}
}

impl EpochData {
    /// Starts at `group`'s epoch, with an empty history.
    pub(crate) fn from_group(group: &MlsGroup) -> Self {
        Self::starting_at(group.epoch().as_u64())
    }
}
