/// Fakes of the node's peers, server sync, drives and identity, for testing an
/// app without the native library. Together with `InMemoryBackend` of
/// `package:atomic_store/testing.dart` a whole app runs in `flutter test`.
///
/// Depend on the interfaces (`Peers`, `ServerSync`, `Drives`, `Identity`,
/// `Sharing`) in your widgets and pass `node.peers` in production and a fake
/// in tests.
library;

export 'src/fakes.dart';
