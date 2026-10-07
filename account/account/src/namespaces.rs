pub mod chat;
pub mod profile;

pub mod prelude {
    pub use crate::namespaces::chat::{ChatRead, ChatWrite};
    pub use crate::namespaces::profile::{ProfileRead, ProfileWrite};
}
