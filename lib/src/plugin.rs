//! Defines how plugins work and interact with an Atomic Server.
//! The actual plugins live in the plugins module.

/// A single executable application that extends Atomic Server functionality
pub struct Plugin {
  /// A slug for the plugin, used as main endpoint
  name: String,
  /// A markdown description
  description: String,
  base_endpoint: Endpoint,
  endpoints: Vec<Endpoint>,
}

pub struct Endpoint {
  /// Slug name of the endpoint
  path: String,
  /// Required query parameters
  required: Vec<Parameter>,
  /// Optional query parameters
  optional: Vec<Parameter>,
}

pub struct Request {
  /// Set of query parameters, parsed from the URL
  pub parameters: Vec<(String, String)>
}

//! The Error type that Plugins can throw
pub type PluginResult<T> = std::result::Result<T, PluginError>;

#[derive(Debug)]
struct PluginError(String);

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "There is an error: {}", self.0)
    }
}

impl Error for PluginError {}
