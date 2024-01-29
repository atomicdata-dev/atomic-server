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

#[derive(Debug, Clone)]
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
    pub fn into_resource(self, subject: String) -> Resource {
        let mut r = Resource::new(subject);
        r.set_class(urls::ERROR);
        r.set_unsafe(urls::DESCRIPTION.into(), Value::String(self.message));
        r
    }

    pub fn set_subject(mut self, subject: &str) -> Self {
        self.subject = Some(subject.into());
        self
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

impl From<std::boxed::Box<dyn std::error::Error>> for AtomicError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AtomicError {
            message: error.to_string(),
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

// The following feel very redundant. Can this be simplified?
impl<T> From<std::sync::PoisonError<T>> for AtomicError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<std::io::Error> for AtomicError {
    fn from(error: std::io::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<url::ParseError> for AtomicError {
    fn from(error: url::ParseError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<serde_json::Error> for AtomicError {
    fn from(error: serde_json::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<std::string::FromUtf8Error> for AtomicError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<ParseFloatError> for AtomicError {
    fn from(error: ParseFloatError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<ParseIntError> for AtomicError {
    fn from(error: ParseIntError) -> Self {
        AtomicError {
            message: error.to_string(),
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<DecodeError> for AtomicError {
    fn from(error: DecodeError) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

impl From<ParseBoolError> for AtomicError {
    fn from(error: ParseBoolError) -> Self {
        AtomicError {
            message: error.to_string(),
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}

impl From<Infallible> for AtomicError {
    fn from(error: Infallible) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

#[cfg(feature = "db")]
impl From<sled::Error> for AtomicError {
    fn from(error: sled::Error) -> Self {
        AtomicError {
            message: error.to_string(),
            error_type: AtomicErrorType::OtherError,
            subject: None,
        }
    }
}

#[cfg(feature = "db")]
impl From<Box<bincode::ErrorKind>> for AtomicError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        AtomicError {
            message: error.to_string(),
            subject: None,
            error_type: AtomicErrorType::OtherError,
        }
    }
}
