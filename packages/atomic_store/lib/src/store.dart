import 'dart:async';

import 'backend.dart';
import 'exceptions.dart';
import 'resource.dart';
import 'urls.dart';
import 'value.dart';

/// The entry point, mirroring `Store` of `@tomic/lib`: get, search, create and
/// watch resources through a [StoreBackend].
///
/// ```dart
/// final store = Store(backend: backend, drive: driveSubject);
/// final doc = await store.getResource(subject);
/// doc.set(Props.name, 'New title');
/// await doc.save();
/// ```
class Store {
  /// [drive] is the default parent of [newResource] and the default scope of
  /// [search]. Who signs a write is the backend's agent: the bridge still
  /// holds one active agent per process (see `flutter/README.md`).
  Store({required this.backend, this.drive});

  final StoreBackend backend;

  /// The drive this store works in; `null` searches every drive and makes
  /// [newResource] require a `parent`.
  final String? drive;

  final Map<String, Resource> _resources = {};

  /// The resource [subject]. The same subject gives the same instance, read
  /// once; [fresh] reads it again. Throws [StoreException]
  /// ([StoreErrorKind.notFound] when the store does not have it).
  Future<Resource> getResource(String subject, {bool fresh = false}) async {
    final cached = _resources[subject];
    if (cached != null && !fresh) return cached;
    final snapshot = await backend.getResource(subject);
    if (cached != null) {
      cached.applySnapshot(snapshot.props);
      return cached;
    }
    final resource =
        Resource.internal(this, snapshot.subject, snapshot.props, isNew: false);
    _resources[subject] = resource;
    return resource;
  }

  /// Like [getResource] but `null` instead of a notFound error.
  Future<Resource?> getResourceOrNull(String subject,
      {bool fresh = false}) async {
    try {
      return await getResource(subject, fresh: fresh);
    } on StoreException catch (e) {
      if (e.kind == StoreErrorKind.notFound) return null;
      rethrow;
    }
  }

  /// A new, unsaved resource with the given classes and properties, under
  /// [parent] (default: [drive]). [Resource.save] creates it.
  Resource newResource({
    String? parent,
    Iterable<String> isA = const [],
    Map<String, Object> props = const {},
  }) {
    final parentSubject = parent ?? drive;
    if (parentSubject == null) {
      throw const StoreException(StoreErrorKind.invalid,
          'newResource needs a parent: pass one or give the Store a drive');
    }
    final resource = Resource.internal(this, null, {}, isNew: true);
    final classes = isA.toList();
    if (classes.isNotEmpty) {
      resource.set(Props.isA, ArrayValue([for (final c in classes) LinkValue(c)]));
    }
    resource.set(Props.parent, LinkValue(parentSubject));
    props.forEach(resource.set);
    return resource;
  }

  /// Full-text search, best first. [drive] limits it to one drive (default:
  /// this store's [drive]; pass an empty string to search every drive).
  Future<List<SearchResult>> search(String query,
      {String? drive, int limit = 20}) {
    final scope = drive ?? this.drive;
    return backend.search(query,
        drive: (scope == null || scope.isEmpty) ? null : scope, limit: limit);
  }

  /// Create a drive named [name] and return it.
  Future<Resource> createDrive(String name) async {
    final subject = await backend.createDrive(name);
    return getResource(subject, fresh: true);
  }

  /// The resource [subject] now and again after every change, until it is
  /// destroyed (the stream then ends) or the listener cancels. Each event is
  /// the same [Resource] instance, reloaded.
  Stream<Resource> watch(String subject,
      {Duration timeout = const Duration(seconds: 60)}) {
    late final StreamController<Resource> controller;
    var cancelled = false;

    Future<void> run() async {
      try {
        final resource = await getResource(subject, fresh: true);
        if (cancelled) return;
        controller.add(resource);
        while (!cancelled) {
          switch (await backend.waitForEvent(subject, timeout)) {
            case ResourceEventKind.timeout:
              continue;
            case ResourceEventKind.changed:
              await resource.reload();
              if (!cancelled) controller.add(resource);
            case ResourceEventKind.destroyed:
              _resources.remove(subject);
              return;
          }
        }
      } catch (e, st) {
        if (!cancelled) controller.addError(e, st);
      } finally {
        if (!controller.isClosed) await controller.close();
      }
    }

    controller = StreamController<Resource>(
      onListen: () => unawaited(run()),
      onCancel: () => cancelled = true,
    );
    return controller.stream;
  }

  /// [watch] with a callback, as `store.subscribe` in `@tomic/lib`. Cancel the
  /// returned subscription to unsubscribe.
  StreamSubscription<Resource> subscribe(
          String subject, void Function(Resource resource) onChange) =>
      watch(subject).listen(onChange);

  /// Forget the resources read so far (the next [getResource] reads again).
  void clearCache() => _resources.clear();

  /// Used by [Resource.save] once a draft has its subject.
  void remember(Resource resource) {
    _resources[resource.subject] = resource;
  }
}
