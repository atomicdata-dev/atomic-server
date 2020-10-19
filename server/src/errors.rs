use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::Serialize;
use std::error::Error;

// More strict Result type
pub type BetterResult<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppErrorType {
    // NotFoundError,
    OtherError,
    // NotImplementedError,
}

// More strict error type, supports HTTP responses
// Needs a lot of work, though
#[derive(Debug)]
pub struct AppError {
    pub message: Option<String>,
    pub cause: Option<String>,
    pub error_type: AppErrorType,
}

#[derive(Serialize)]
pub struct AppErrorResponse {
    pub error: String,
}

impl Error for AppError {}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self.error_type {
            // AppErrorType::NotFoundError => StatusCode::NOT_FOUND,
            AppErrorType::OtherError => StatusCode::INTERNAL_SERVER_ERROR,
            // AppErrorType::NotImplementedError => StatusCode::NOT_IMPLEMENTED
        }
    }
    fn error_response(&self) -> HttpResponse {
        let body = format!("Error: {:?}. {:?}", self.message, self.cause);
        log::info!("Error reponse: {}", body);
        HttpResponse::build(self.status_code()).body(body)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SuperError is here!")
    }
}

// Error conversions
impl From<&str> for AppError {
    fn from(message: &str) -> Self {
        AppError {
          message: Some(message.into()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}


impl From<std::boxed::Box<dyn std::error::Error>> for AppError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AppError {
          message: Some(error.to_string()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}

impl From<tera::Error> for AppError {
    fn from(error: tera::Error) -> Self {
        AppError {
          message: Some(error.to_string()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for AppError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        AppError {
          message: Some(error.to_string()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}
