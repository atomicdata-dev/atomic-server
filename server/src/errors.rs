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
    /// A write refused by `crate::rate_limit`; rendered as `429` with `Retry-After`.
    TooManyRequests,
    /// The node is over its hard commit limit; rendered as `503` with
    /// `Retry-After`. See `crate::write_load`.
    Busy,
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
    /// The node is overloaded with writes: `503` plus `Retry-After`.
    pub fn busy(busy: crate::write_load::Busy) -> Self {
        Self {
            message: busy.message(),
            error_type: AppErrorType::Busy,
            error_resource: None,
        }
    }

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
        if atomic_lib::sync::protocol::classify_commit_error(&self.message)
            == atomic_lib::sync::protocol::error_code::CAUSALITY_CONFLICT
        {
            return StatusCode::CONFLICT;
        }
        // A managed node refusing enrollment/quota is an expected admission
        // decision, not an internal failure or a request to sign in again.
        if atomic_lib::sync::protocol::classify_commit_error(&self.message)
            == atomic_lib::sync::protocol::error_code::SYNC_REJECTED
        {
            return StatusCode::FORBIDDEN;
        }
        match self.error_type {
            AppErrorType::NotFound => StatusCode::NOT_FOUND,
            AppErrorType::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            AppErrorType::BadRequest => StatusCode::BAD_REQUEST,
            AppErrorType::Other => StatusCode::INTERNAL_SERVER_ERROR,
            AppErrorType::Unauthorized => StatusCode::UNAUTHORIZED,
            AppErrorType::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppErrorType::Busy => StatusCode::SERVICE_UNAVAILABLE,
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
        let mut response = HttpResponse::build(self.status_code());
        if let Some(ms) = atomic_lib::sync::protocol::retry_after_ms_from_message(&self.message) {
            response.insert_header(("Retry-After", ms.div_ceil(1000).max(1).to_string()));
            response.insert_header((crate::write_load::RETRY_AFTER_MS_HEADER, ms.to_string()));
        } else if let Some(secs) = crate::rate_limit::retry_after_from_message(&self.message) {
            response.insert_header(("Retry-After", secs.to_string()));
        }
        response.content_type(JSON_AD_MIME).body(body)
    }
}

impl std::fmt::Display for AtomicServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
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
            // A body the lib could not parse is the client's mistake, not a
            // fault here: 400, so it neither reads as a crash to the caller
            // nor reaches Sentry as one.
            atomic_lib::AtomicErrorType::ParseError => AppErrorType::BadRequest,
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

/// Implements `From<$source> for AtomicServerError` as an `Other` error
/// carrying the source's `Display` text.
macro_rules! other_error_from_display {
    ($($source:ty),+ $(,)?) => {
        $(
            impl From<$source> for AtomicServerError {
                fn from(error: $source) -> Self {
                    AtomicServerError {
                        message: error.to_string(),
                        error_type: AppErrorType::Other,
                        error_resource: None,
                    }
                }
            }
        )+
    };
}

other_error_from_display!(
    std::boxed::Box<dyn std::error::Error>,
    std::io::Error,
    actix_web::Error,
);

// Generic over the guard type, which the macro above does not cover.
impl<T> From<std::sync::PoisonError<T>> for AtomicServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
            error_resource: None,
        }
    }
}

#[cfg(test)]
mod admission_error_tests {
    use super::*;

    #[test]
    fn managed_commit_errors_carry_a_blocking_code() {
        for message in [
            "Drive did:ad:private is not enrolled for sync on this node.",
            "Drive did:ad:private has reached its storage quota on this node.",
        ] {
            let error: AtomicServerError = message.into();
            assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
            assert_eq!(
                atomic_lib::sync::protocol::classify_commit_error(&error.message),
                atomic_lib::sync::protocol::error_code::SYNC_REJECTED
            );
        }
    }

    #[test]
    fn causality_refusal_is_a_conflict() {
        let error: AtomicServerError = "Commit's Loro update produced no state changes".into();
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert_eq!(
            atomic_lib::sync::protocol::classify_commit_error(&error.message),
            atomic_lib::sync::protocol::error_code::CAUSALITY_CONFLICT
        );
    }
}
