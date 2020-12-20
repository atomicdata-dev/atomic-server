//! The versioning module is a Plugin that calculates Versions of Resources by using their Commits.
//! It adds an endpoint `/versions` which can be easily queried for

use atomic_lib::plugin::*;

pub fn handle(request: Request) -> PluginResult {
  println!("Jo, params: {}", request.parameters)
}
