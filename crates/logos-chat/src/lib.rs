mod logos;

pub use logos::{LogosChatClient, LogosConfig, REGISTRY_ENDPOINT, open, open_with_transport};
// Facade re-exports so callers need no direct dependency on the transport
// crate.
pub use embedded_logos_delivery::{
    DEFAULT_PRESET, DeliveryConfig, EmbeddedLogosDelivery, default_delivery_config,
};

// Re-export the transport-generic client surface so callers depend on this
// crate alone.
pub use logos_generic_chat::*;
