//! The Error type that you can expect when using this library

use std::{
    convert::Infallible,
    num::{ParseFloatError, ParseIntError},
    str::ParseBoolError,
};

use base64::DecodeError;

/// The default Error type for all Atomic Lib Errors.
pub type AtomicResult<T> = std::result::Result<T, AtomicError>;

#[derive(Debug)]
pub struct AtomicError {
    pub message: String,
    pub error_type: AtomicErrorType,
}

#[derive(Debug)]
pub enum AtomicErrorType {
    NotFoundError,
    UnauthorizedError,
    OtherError,
}

impl std::error::Error for AtomicError {
    // fn description(&self) -> &str {
    //     // Both underlying errors already impl `Error`, so we defer to their
    //     // implementations.
    //     match *self {
    //         CliError::Io(ref err) => err.description(),
    //         // Normally we can just write `err.description()`, but the error
    //         // type has a concrete method called `description`, which conflicts
    //         // with the trait method. For now, we must explicitly call
    //         // `description` through the `Error` trait.
    //         CliError::Parse(ref err) => error::Error::description(err),
    //     }
    // }

    // fn cause(&self) -> Option<&dyn std::error::Error> {
    //     match *self {
    //         // N.B. Both of these implicitly cast `err` from their concrete
    //         // types (either `&io::Error` or `&num::ParseIntError`)
    //         // to a trait object `&Error`. This works because both error types
    //         // implement `Error`.
    //         CliError::Io(ref err) => Some(err),
    //         CliError::Parse(ref err) => Some(err),
    //     }
    // }
}

impl AtomicError {
    #[allow(dead_code)]
    pub fn not_found(message: String) -> AtomicError {
        AtomicError {
            message: format!("Resource not found. {}", message),
            error_type: AtomicErrorType::NotFoundError,
        }
    }

    pub fn unauthorized(message: String) -> AtomicError {
        AtomicError {
            message: format!("Unauthorized. {}", message),
            error_type: AtomicErrorType::UnauthorizedError,
        }
    }

    pub fn other_error(message: String) -> AtomicError {
        AtomicError {
            message,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl std::fmt::Display for AtomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

// Error conversions
impl From<&str> for AtomicError {
    fn from(message: &str) -> Self {
        AtomicError {
            message: message.into(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<String> for AtomicError {
    fn from(message: String) -> Self {
        AtomicError {
            message,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

// The following feel very redundant. Can this be simplified?

impl From<std::boxed::Box<dyn std::error::Error>> for AtomicError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for AtomicError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<std::io::Error> for AtomicError {
    fn from(error: std::io::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<url::ParseError> for AtomicError {
    fn from(error: url::ParseError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<serde_json::Error> for AtomicError {
    fn from(error: serde_json::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<std::string::FromUtf8Error> for AtomicError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<ParseFloatError> for AtomicError {
    fn from(error: ParseFloatError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<ParseIntError> for AtomicError {
    fn from(error: ParseIntError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<DecodeError> for AtomicError {
    fn from(error: DecodeError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<ParseBoolError> for AtomicError {
    fn from(error: ParseBoolError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<Infallible> for AtomicError {
    fn from(error: Infallible) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

// LIBRARY ERRORS

#[cfg(feature = "db")]
impl From<sled::Error> for AtomicError {
    fn from(error: sled::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

#[cfg(feature = "db")]
impl From<Box<bincode::ErrorKind>> for AtomicError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

// WASMER ERRORS

#[cfg(feature = "db")]
impl From<wasmer::RuntimeError> for AtomicError {
    fn from(error: wasmer::RuntimeError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}

#[cfg(feature = "db")]
impl From<wasmer::InstantiationError> for AtomicError {
    fn from(error: wasmer::InstantiationError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}
#[cfg(feature = "db")]
impl From<wasmer::ExportError> for AtomicError {
    fn from(error: wasmer::ExportError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
        }
    }
}
