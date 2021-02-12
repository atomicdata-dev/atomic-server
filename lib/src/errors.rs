//! The Error type that you can expect when using this library

use std::error::Error;
use std::fmt;

/// The default Error type for all Atomic Lib Errors.
// TODO: specify & limit error types
// https://github.com/joepio/atomic/issues/11
pub type AtomicResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct AtomicError(String);

impl fmt::Display for AtomicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}

impl Error for AtomicError {}
