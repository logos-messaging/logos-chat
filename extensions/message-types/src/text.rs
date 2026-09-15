use serde::{Deserialize, Serialize};

use crate::Content;

/// A plain UTF-8 text message — the baseline content type, and today's implicit
/// behavior made explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Text {
    pub body: String,
}

impl Text {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }
}

impl Content for Text {
    const CONTENT_TYPE: &'static str = "text/plain";

    fn fallback(&self) -> String {
        // Plain text is its own fallback.
        self.body.clone()
    }
}
