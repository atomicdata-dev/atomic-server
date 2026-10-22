/// A `Store` and `Resource` for Atomic Data that rhyme with `@tomic/lib`.
///
/// Pure Dart: everything goes through a [StoreBackend], which the Flutter app
/// implements over its Rust bridge and tests replace with [InMemoryBackend]
/// (`package:atomic_store/testing.dart`).
library;

export 'src/backend.dart';
export 'src/exceptions.dart';
export 'src/resource.dart';
export 'src/store.dart';
export 'src/urls.dart';
export 'src/value.dart';
