use std::fmt::Debug;

pub trait CommitValidator: Send + Debug {
    fn can_merge_commit(&self) -> bool;
    fn can_make_commit(&self) -> bool;
}

#[derive(Debug)]
pub struct YoloValidator {}

impl CommitValidator for YoloValidator {
    fn can_merge_commit(&self) -> bool {
        true
    }

    fn can_make_commit(&self) -> bool {
        true
    }
}
