/// Returns the current UNIX timestamp in milliseconds
pub fn now() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("You're a time traveler")
    .as_millis() as i64
}
