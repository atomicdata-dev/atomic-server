//! The typed error of the generic resource API (`api::resources`).
//!
//! The older bridge functions return `String` errors; new ones return this, so
//! Dart can `switch` on what went wrong instead of matching message text.

use atomic_lib::errors::AtomicErrorType;

/// What kind of failure it was; the part a caller decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The resource (or something it needs) is not in the local store.
    NotFound,
    /// This agent may not read or write that.
    Unauthorized,
    /// A server or peer could not be reached.
    Network,
    /// The input was not valid: a malformed value, subject or request.
    Invalid,
    /// The local store is not open or failed.
    Storage,
    /// Anything else.
    Other,
}

/// Why a bridge call failed: a [`kind`](ErrorKind) to `switch` on and the
/// library's message for the log. (A struct and a unit enum, not an enum with
/// fields: flutter_rust_bridge generates those with `freezed`, which this app
/// does not use.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicError {
    pub kind: ErrorKind,
    pub message: String,
}

impl AtomicError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        AtomicError {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, message)
    }

    pub(crate) fn storage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Storage, message)
    }
}

impl std::fmt::Display for AtomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AtomicError {}

impl From<atomic_lib::AtomicError> for AtomicError {
    fn from(e: atomic_lib::AtomicError) -> Self {
        let kind = match e.error_type {
            AtomicErrorType::NotFoundError => ErrorKind::NotFound,
            AtomicErrorType::UnauthorizedError | AtomicErrorType::MethodNotAllowed => {
                ErrorKind::Unauthorized
            }
            AtomicErrorType::UpstreamUnreachable => ErrorKind::Network,
            AtomicErrorType::ParseError => ErrorKind::Invalid,
            AtomicErrorType::OtherError => ErrorKind::Other,
        };
        AtomicError::new(kind, e.message)
    }
}

/// The store the bridge writes to, or [`AtomicError::Storage`] when `open_db`
/// has not run.
pub(crate) fn open_store() -> Result<&'static std::sync::Arc<atomic_lib::Db>, AtomicError> {
    super::simple::state::db().map_err(AtomicError::storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lib_err(error_type: AtomicErrorType) -> atomic_lib::AtomicError {
        atomic_lib::AtomicError {
            message: "m".into(),
            error_type,
            subject: None,
        }
    }

    #[test]
    fn library_errors_map_to_the_kind_a_caller_decides_on() {
        use AtomicErrorType::*;
        let kinds = [
            (NotFoundError, ErrorKind::NotFound),
            (UnauthorizedError, ErrorKind::Unauthorized),
            (MethodNotAllowed, ErrorKind::Unauthorized),
            (UpstreamUnreachable, ErrorKind::Network),
            (ParseError, ErrorKind::Invalid),
            (OtherError, ErrorKind::Other),
        ];
        for (from, kind) in kinds {
            let e = AtomicError::from(lib_err(from));
            assert_eq!((e.kind, e.message.as_str()), (kind, "m"));
        }
    }
}
