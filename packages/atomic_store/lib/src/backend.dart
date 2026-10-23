import 'value.dart';

/// A resource as the backend holds it.
class ResourceSnapshot {
  const ResourceSnapshot(this.subject, this.props);
  final String subject;
  final Map<String, Value> props;
}

/// One full-text search hit.
class SearchResult {
  const SearchResult({
    required this.subject,
    required this.title,
    this.className = '',
    this.drive = '',
    this.score = 0,
  });
  final String subject;
  final String title;
  final String className;

  /// The drive the hit lives in, empty when unknown.
  final String drive;
  final double score;
}

/// What happened to a resource a backend was asked to wait for.
enum ResourceEventKind { changed, destroyed, timeout }

/// One change or destroy somewhere in the store, from
/// [StoreBackend.waitForStoreEvent]. [subject] is empty for a timeout.
class StoreEvent {
  const StoreEvent(this.kind, this.subject);
  final ResourceEventKind kind;
  final String subject;

  @override
  String toString() => 'StoreEvent(${kind.name} $subject)';
}

/// Everything [Store] needs from a store of Atomic Data. The Flutter app
/// implements it over its Rust bridge; [InMemoryBackend] (in
/// `package:atomic_store/testing.dart`) implements it for tests.
///
/// Implementations throw [StoreException] (never their own error types).
abstract interface class StoreBackend {
  /// The resource [subject]; [StoreErrorKind.notFound] when it is not there.
  Future<ResourceSnapshot> getResource(String subject);

  /// Apply [set] and [remove] to the existing resource [subject], as one
  /// signed commit.
  Future<void> saveChanges(
      String subject, Map<String, Value> set, List<String> remove);

  /// Create a resource holding [values] under a new subject; returns it.
  Future<String> createResource(Map<String, Value> values);

  /// Full-text search, best first; in [drive] only when given.
  Future<List<SearchResult>> search(String query,
      {String? drive, int limit = 20});

  /// The subjects under [parent], in display order.
  Future<List<String>> childSubjects(String parent, {int limit = 1000});

  /// Create a drive; returns its subject.
  Future<String> createDrive(String name);

  /// Wait until [subject] changes or is destroyed, or [timeout] passes.
  Future<ResourceEventKind> waitForEvent(String subject, Duration timeout);

  /// Destroy [subject] and, recursively, its children, as one signed destroy
  /// commit. [StoreErrorKind.notFound] when the store does not have it.
  Future<void> destroyResource(String subject);

  /// Wait until any resource changes or is destroyed, or [timeout] passes.
  /// What [Store.watchChildren] is built on.
  Future<StoreEvent> waitForStoreEvent(Duration timeout);
}
