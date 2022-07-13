//! Monitor performance using HTTP headers
use std::time::Instant;

/// Timer used to share performance metrics to the client using the HTTP Server-Timing header
/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing
pub struct Timer {
    last: Instant,
    timings: Vec<Timing>,
}

struct Timing {
    name: String,
    /// Time in milliseconds
    duration: u128,
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            last: Instant::now(),
            timings: Vec::new(),
        }
    }

    /// Adds a named measurement, counting from the last one
    pub fn add(&mut self, name: &str) {
        let now = Instant::now();
        let duration = now.duration_since(self.last).as_millis();
        self.last = now;
        self.timings.push(Timing {
            name: name.into(),
            duration,
        });
    }

    /// Returns the value for a Server-Timings header.
    /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing
    pub fn to_header(&self) -> String {
        let mut out = String::new();
        use std::fmt::Write;
        for timing in self.timings.iter() {
            _ = write!(out, "{};dur={}, ", timing.name, timing.duration);
        }
        out
    }
}
