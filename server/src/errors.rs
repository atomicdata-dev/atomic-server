use actix_web::{HttpResponse, error::ResponseError, http::StatusCode};
use serde::Serialize;
use std::error::Error;

// More strict Result type
pub type BetterResult<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppErrorType {
    NotFoundError,
    OtherError,
    // NotImplementedError,
}

// More strict error type, supports HTTP responses
// Needs a lot of work, though
#[derive(Debug)]
pub struct AppError {
    pub message: String,
    pub error_type: AppErrorType,
}

impl AppError {
    pub fn not_found(message: String) -> AppError {
        AppError {
            message: format!("Resource not found. {}", message),
            error_type: AppErrorType::NotFoundError
        }
    }
}

#[derive(Serialize)]
pub struct AppErrorResponse {
    pub error: String,
}

impl Error for AppError {}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self.error_type {
            AppErrorType::NotFoundError => StatusCode::NOT_FOUND,
            AppErrorType::OtherError => StatusCode::INTERNAL_SERVER_ERROR,
            // AppErrorType::NotImplementedError => StatusCode::NOT_IMPLEMENTED
        }
    }
    fn error_response(&self) -> HttpResponse {
        let body = self.message.clone();
        log::info!("Error reponse {}: {}", self.status_code(), self.message);
        HttpResponse::build(self.status_code()).body(body)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

// Error conversions
impl From<&str> for AppError {
    fn from(message: &str) -> Self {
        AppError {
          message: message.into(),
          error_type: AppErrorType::OtherError,
        }
    }
}

impl From<String> for AppError {
    fn from(message: String) -> Self {
        AppError {
          message,
          error_type: AppErrorType::OtherError,
        }
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for AppError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AppError {
          message: error.to_string(),
          error_type: AppErrorType::OtherError,
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for AppError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AppError {
          message: error.to_string(),
          error_type: AppErrorType::OtherError,
        }
    }
}
