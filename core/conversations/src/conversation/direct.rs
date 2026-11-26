/// Direct ConvoTypes allow communication between two participants.
/// Participants are determined at creation, and do not change
mod direct_v1;
mod direct_v2;

// exports these types through conversation module
pub mod convo_types {
    pub use super::direct_v1::DirectV1Convo;
    pub use super::direct_v2::DirectV2Convo;
}
