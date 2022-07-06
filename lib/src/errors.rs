/*!
Mostly contains implementations for Error types.

The [AtomicError] type should be returned from any function that may fail, although it is not returned everywhere at this moment.
*/

use std::{
    convert::Infallible,
    num::{ParseFloatError, ParseIntError},
    str::ParseBoolError,
};

use base64::DecodeError;

use crate::{urls, Resource, Value};

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
    ParseErrror,
    OtherError,
}

impl std::error::Error for AtomicError {}

impl AtomicError {
    #[allow(dead_code)]
    /// A server will probably return a 404.
    pub fn not_found(message: String) -> AtomicError {
        AtomicError {
            message: format!("Resource not found. {}", message),
            error_type: AtomicErrorType::NotFoundError,
        }
    }

    /// A server will probably return this error as a 403.
    pub fn unauthorized(message: String) -> AtomicError {
        AtomicError {
            message: format!("Unauthorized. {}", message),
            error_type: AtomicErrorType::UnauthorizedError,
        }
    }

    /// A server will probably return a 500.
    pub fn other_error(message: String) -> AtomicError {
        AtomicError {
            message,
            error_type: AtomicErrorType::OtherError,
        }
    }

    pub fn parse_error(
        message: &str,
        subject: Option<&str>,
        property: Option<&str>,
    ) -> AtomicError {
        let mut msg = "Error parsing JSON-AD".to_string();
        if let Some(prop) = property {
            msg.push_str(&format!(" with property {prop}"));
        }
        if let Some(subject) = subject {
            msg.push_str(&format!(" of subject {subject}"));
        }
        msg.push_str(message);

        AtomicError {
            message: msg,
            error_type: AtomicErrorType::ParseErrror,
        }
    }

    /// Converts the Error into a Resource. This helps clients to handle errors, such as show error messages in the right Form input fields.
    pub fn into_resource(self, subject: String) -> Resource {
        let mut r = Resource::new(subject);
        r.set_class(urls::ERROR);
        r.set_propval_unsafe(urls::DESCRIPTION.into(), Value::String(self.message));
        r
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
