/// An Atomic Mutation describes a change in data
#[derive(Clone)]
pub struct Mutation {
  subject: String,
  property: String,
  value: String,
  /// The method describes how the Atom should be interpreted
  method: String,
  /// Who created the Mutation
  actor: String,
  /// When the Mutation was created
  created_at: String,
  /// URL of the resource
  id: String,
}

/// A list of all the Mutations that have occurered
pub type Log = Vec<Mutation>;
