use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::Serialize;
use std::error::Error;

// More strict Result type
pub type AtomicServerResult<T> = std::result::Result<T, AtomicServerError>;

#[derive(Debug)]
pub enum AppErrorType {
    NotFound,
    Unauthorized,
    Other,
}

// More strict error type, supports HTTP responses
// Needs a lot of work, though
#[derive(Debug)]
pub struct AtomicServerError {
    pub message: String,
    pub error_type: AppErrorType,
}

impl AtomicServerError {}

#[derive(Serialize)]
pub struct AppErrorResponse {
    pub error: String,
}

impl Error for AtomicServerError {}

impl ResponseError for AtomicServerError {
    fn status_code(&self) -> StatusCode {
        match self.error_type {
            AppErrorType::NotFound => StatusCode::NOT_FOUND,
            AppErrorType::Other => StatusCode::INTERNAL_SERVER_ERROR,
            AppErrorType::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let body = self.message.clone();
        tracing::info!("Error reponse {}: {}", self.status_code(), self.message);
        HttpResponse::build(self.status_code()).body(body)
    }
}

impl std::fmt::Display for AtomicServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

// Error conversions
impl From<&str> for AtomicServerError {
    fn from(message: &str) -> Self {
        AtomicServerError {
            message: message.into(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<String> for AtomicServerError {
    fn from(message: String) -> Self {
        AtomicServerError {
            message,
            error_type: AppErrorType::Other,
        }
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for AtomicServerError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for AtomicServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<std::io::Error> for AtomicServerError {
    fn from(error: std::io::Error) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<tantivy::directory::error::OpenDirectoryError> for AtomicServerError {
    fn from(error: tantivy::directory::error::OpenDirectoryError) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<tantivy::TantivyError> for AtomicServerError {
    fn from(error: tantivy::TantivyError) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

#[cfg(feature = "https")]
impl From<acme_lib::Error> for AtomicServerError {
    fn from(error: acme_lib::Error) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<actix_web::Error> for AtomicServerError {
    fn from(error: actix_web::Error) -> Self {
        AtomicServerError {
            message: error.to_string(),
            error_type: AppErrorType::Other,
        }
    }
}

impl From<atomic_lib::errors::AtomicError> for AtomicServerError {
    fn from(error: atomic_lib::errors::AtomicError) -> Self {
        let error_type = match error.error_type {
            atomic_lib::errors::AtomicErrorType::NotFoundError => AppErrorType::NotFound,
            atomic_lib::errors::AtomicErrorType::UnauthorizedError => AppErrorType::Unauthorized,
            _ => AppErrorType::Other,
        };
        AtomicServerError {
            message: error.to_string(),
            error_type,
        }
    }
}
