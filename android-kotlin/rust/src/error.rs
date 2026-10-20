use std::fmt;

/// The one error Kotlin sees: a message to log or show.
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    Message { msg: String },
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let CoreError::Message { msg } = self;
        f.write_str(msg)
    }
}

impl std::error::Error for CoreError {}

impl From<String> for CoreError {
    fn from(msg: String) -> Self {
        CoreError::Message { msg }
    }
}

impl From<&str> for CoreError {
    fn from(msg: &str) -> Self {
        CoreError::Message { msg: msg.into() }
    }
}

impl From<atomic_lib::AtomicError> for CoreError {
    fn from(e: atomic_lib::AtomicError) -> Self {
        CoreError::Message { msg: e.to_string() }
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
