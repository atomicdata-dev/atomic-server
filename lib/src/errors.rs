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

#[derive(Clone, Debug)]
pub struct AtomicError {
    pub message: String,
    pub error_type: AtomicErrorType,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AtomicErrorType {
    NotFoundError,
    UnauthorizedError,
    ParseError,
    OtherError,
    MethodNotAllowed,
}

impl std::error::Error for AtomicError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl AtomicError {
    pub fn method_not_allowed(message: &str) -> AtomicError {
        AtomicError {
            message: message.into(),
            error_type: AtomicErrorType::MethodNotAllowed,
            subject: None,
        }
    }

    #[allow(dead_code)]
    /// A server will probably return a 404.
    pub fn not_found(message: String) -> AtomicError {
        AtomicError {
            message: format!("Resource not found. {}", message),
            error_type: AtomicErrorType::NotFoundError,
            subject: None,
        }
    }

    /// A server will probably return this error as a 403.
    pub fn unauthorized(message: String) -> AtomicError {
        AtomicError {
            message: format!("Unauthorized. {}", message),
            error_type: AtomicErrorType::UnauthorizedError,
            subject: None,
        }
    }

    /// This error, typed as an authentication or authorization failure (a
    /// server answers 401), unless it already is one. For the paths that
    /// decide who a caller is, where every failure means "not you": a
    /// signature that does not verify, a key that does not match the
    /// subject, an agent this store does not know. The message is kept.
    pub fn into_unauthorized(self) -> AtomicError {
        match self.error_type {
            AtomicErrorType::UnauthorizedError => self,
            _ => AtomicError {
                message: format!("Unauthorized. {}", self.message),
                error_type: AtomicErrorType::UnauthorizedError,
                subject: self.subject,
            },
        }
    }

    /// A server will probably return a 500.
    pub fn other_error(message: String) -> AtomicError {
        AtomicError {
            message,
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }

    pub fn parse_error(
        message: &str,
        subject: Option<&str>,
        property: Option<&str>,
    ) -> AtomicError {
        use std::fmt::Write;
        let mut msg = "Error parsing JSON-AD ".to_string();
        if let Some(prop) = property {
            let _ = write!(msg, "with property {prop} ");
        }
        if let Some(subject) = subject {
            let _ = write!(msg, "of subject {subject} ");
        }
        // remove last space
        msg.pop();
        msg.push_str(". ");
        msg.push_str(message);

        AtomicError {
            message: msg,
            subject: None,
            error_type: AtomicErrorType::ParseError,
        }
    }

    /// Converts the Error into a Resource. This helps clients to handle errors, such as show error messages in the right Form input fields.
    pub fn into_resource(self, subject: String) -> AtomicResult<Resource> {
        let mut r = Resource::new(subject);
        r.set_class(urls::ERROR)?;
        r.set_unsafe(urls::DESCRIPTION.into(), Value::String(self.message))?;
        Ok(r)
    }

    pub fn set_subject(mut self, subject: &str) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

impl std::fmt::Display for AtomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// Error conversions
impl From<&str> for AtomicError {
    fn from(message: &str) -> Self {
        AtomicError {
            message: message.into(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<String> for AtomicError {
    fn from(message: String) -> Self {
        AtomicError {
            message,
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

/// Implements `From<$source> for AtomicError` as an `OtherError` carrying the
/// source's `Display` text.
macro_rules! other_error_from_display {
    ($($(#[$meta:meta])* $source:ty),+ $(,)?) => {
        $(
            $(#[$meta])*
            impl From<$source> for AtomicError {
                fn from(error: $source) -> Self {
                    AtomicError {
                        message: error.to_string(),
                        subject: None,
                        error_type: AtomicErrorType::OtherError,
                    }
                }
            }
        )+
    };
}

other_error_from_display!(
    std::boxed::Box<dyn std::error::Error>,
    std::io::Error,
    url::ParseError,
    serde_json::Error,
    std::string::FromUtf8Error,
    ParseFloatError,
    ParseIntError,
    DecodeError,
    ParseBoolError,
    Infallible,
    #[cfg(feature = "db-sled")]
    sled::Error,
);

// Generic over the guard type, which the macro above does not cover.
impl<T> From<std::sync::PoisonError<T>> for AtomicError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}
