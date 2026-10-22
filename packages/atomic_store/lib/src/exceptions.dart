/// What went wrong, the part a caller decides on. Mirrors the bridge's
/// `ErrorKind`.
enum StoreErrorKind {
  /// The resource is not in the local store.
  notFound,

  /// The agent may not read or write that.
  unauthorized,

  /// A server or peer could not be reached.
  network,

  /// The input was not valid (a malformed value or subject).
  invalid,

  /// The local store is not open or failed.
  storage,

  /// Anything else.
  other,
}

/// Thrown by [Store] and [Resource] (and by every backend) on failure.
class StoreException implements Exception {
  const StoreException(this.kind, this.message, {this.subject});

  final StoreErrorKind kind;
  final String message;

  /// The resource it was about, when known.
  final String? subject;

  @override
  String toString() => 'StoreException(${kind.name}): $message';
}
