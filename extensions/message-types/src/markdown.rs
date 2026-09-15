use serde::{Deserialize, Serialize};

use crate::Content;

/// A Markdown message (`text/markdown`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Markdown {
    pub body: String,
}

impl Markdown {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }
}

impl Content for Markdown {
    const CONTENT_TYPE: &'static str = "text/markdown";

    fn fallback(&self) -> String {
        // The raw markdown source is a reasonable plain-text fallback.
        self.body.clone()
    }
}
