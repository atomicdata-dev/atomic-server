// Returns None if the string is empty.
// Useful for parsing form inputs.
pub fn empty_to_nothing(string: Option<String>) -> Option<String> {
  match string.as_ref() {
      Some(st) => {
        if st.len() == 0 {
          return None
        } else {
          return string
        }
      }
      None => return None
  }
}
