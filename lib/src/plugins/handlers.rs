//! Handlers are functions that are called when a certain event happens.
//! For example, you have an `after_commit` handler which is called when a Commit has been succesfully applied.
//! This is designed to be extensible, so other developers can add functionality.

type AfterCommit = fn(crate::commit::CommitResponse);

#[derive(Default, Clone)]
pub struct Handlers {
    /// Is called after succesfully applying a Commit
    pub after_commit: Vec<AfterCommit>,
}

impl Handlers {
    /// Is called after succesfully applying a Commit
    pub fn register_after_commit(&mut self, fun: AfterCommit) {
        self.after_commit.push(fun);
    }
}
