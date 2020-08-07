use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::Serialize;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// More strict error type, supports HTTP responses
pub type BetterResult<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
pub enum AppErrorType {
    NotFoundError,
    OtherError,
}

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

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self.error_type {
            AppErrorType::NotFoundError => StatusCode::NOT_FOUND,
            AppErrorType::OtherError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let body = format!("Error: {:?}. {:?}", self.message, self.cause);
        HttpResponse::build(self.status_code()).body(body)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SuperError is here!")
    }
}

impl std::convert::From<&str> for AppError {
    fn from(message: &str) -> Self {
        AppError {
          message: Some(message.into()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}

impl std::convert::From<std::boxed::Box<dyn std::error::Error>> for AppError {
    fn from(error: std::boxed::Box<dyn std::error::Error>) -> Self {
        AppError {
          message: Some(error.to_string()),
          cause: None,
          error_type: AppErrorType::OtherError,
        }
    }
}
