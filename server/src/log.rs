/// Basic information
pub fn info (string: &String) {
  println!("{}", string);
}

/// When things go wrong
pub fn warn (string: &String) {
  eprintln!("{}", string);
}
