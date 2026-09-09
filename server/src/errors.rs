use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use atomic_lib::{parse::JSON_AD_MIME, urls, Resource, Value};
use std::error::Error;

// More strict Result type
pub type AtomicServerResult<T> = std::result::Result<T, AtomicServerError>;

#[derive(Debug)]
pub enum AppErrorType {
    NotFound,
    Unauthorized,
    MethodNotAllowed,
    /// The request was understood and refused on its merits — a precondition
    /// the caller can satisfy, not a fault on this side. Without this, a
    /// refusal reports itself as a crash, and a caller cannot tell "you may
    /// not do that yet" from "something here is broken".
    BadRequest,
    Other,
}

// More strict error type, supports HTTP responses
pub struct AtomicServerError {
    pub message: String,
    pub error_type: AppErrorType,
    /// If the error comes from Atomic-Lib, it can contain its own properties + values set in a Resource.
    pub error_resource: Option<Box<Resource>>,
}

impl AtomicServerError {
    /// A refusal the caller can act on, answered as 400 rather than 500.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_type: AppErrorType::BadRequest,
            error_resource: None,
        }
    }
}

impl std::fmt::Debug for AtomicServerError {
    // The derive impl is too verbose, as it includes the full `error_resource`.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for AtomicServerError {}

impl ResponseError for AtomicServerError {
    fn status_code(&self) -> StatusCode {
        match self.error_type {
            AppErrorType::NotFound => StatusCode::NOT_FOUND,
            AppErrorType::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            AppErrorType::BadRequest => StatusCode::BAD_REQUEST,
            AppErrorType::Other => StatusCode::INTERNAL_SERVER_ERROR,
            AppErrorType::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }
    fn error_response(&self) -> HttpResponse {
        // Creates a JSON-AD resource representing the Error.
        let mut r = match &self.error_resource {
            Some(res) => res.as_ref().clone(),
            None => {
                let mut res = Resource::new("subject".into());
                let _ = res.set_class(urls::ERROR);
                let _ = res.set_unsafe(
                    urls::DESCRIPTION.into(),
                    Value::String(self.message.clone()),
                );
                res
            }
        };

        // Error class requires description; ensure it is always set so clients get valid JSON-AD.
        if r.get(urls::DESCRIPTION).is_err() {
            let _ = r.set_unsafe(
                urls::DESCRIPTION.into(),
                Value::String(self.message.clone()),
            );
        }

        // F5 (planning/unified-sync.md): classify against the same
        // patterns the WS `ERROR` frame uses, so the outbox's drain error
        // handling gets one structured code regardless of which transport
        // posted the commit. Harmless (comes back UNKNOWN/0) for the vast
        // majority of errors here that aren't commit-related at all — this
        // handler serves every `AtomicServerError` in the server, not just
        // `/commit`.
        if r.get(urls::ERROR_CODE).is_err() {
            let code = atomic_lib::sync::protocol::classify_commit_error(&self.message);
            let _ = r.set_unsafe(urls::ERROR_CODE.into(), Value::Integer(code as i64));
        }

        let body = r.to_json_ad_with_url("").unwrap();
        tracing::info!("Error response: {}", self.message);
        HttpResponse::build(self.status_code())
            .content_type(JSON_AD_MIME)
            .body(body)
    }
}

impl std::fmt::Display for AtomicServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

// Error conversions

// This is probably the most common and most important type of error
impl From<atomic_lib::errors::AtomicError> for AtomicServerError {
    fn from(error: atomic_lib::errors::AtomicError) -> Self {
        let error_type = match error.error_type {
            atomic_lib::AtomicErrorType::NotFoundError => AppErrorType::NotFound,
            atomic_lib::AtomicErrorType::UnauthorizedError => AppErrorType::Unauthorized,
            atomic_lib::AtomicErrorType::MethodNotAllowed => AppErrorType::MethodNotAllowed,
            atomic_lib::AtomicErrorType::ParseError => AppErrorType::Other,
            atomic_lib::AtomicErrorType::OtherError => AppErrorType::Other,
        };
        let subject = error
            .subject
            .clone()
            .unwrap_or_else(|| "unknown_subject".into());
        let message = error.to_string();
        let error_resource = error.into_resource(subject).ok().map(Box::new);
        AtomicServerError {
            message,
            error_type,
            error_resource,
        }
    }
}

impl From<&str> for AtomicServerError {
    fn from(message: &str) -> Self {
        AtomicServerError {
            message: message.into(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

impl From<String> for AtomicServerError {
    fn from(message: String) -> Self {
        AtomicServerError {
            message,
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for AtomicServerError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for AtomicServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

impl From<std::io::Error> for AtomicServerError {
    fn from(error: std::io::Error) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

impl From<actix_web::Error> for AtomicServerError {
    fn from(error: actix_web::Error) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}
