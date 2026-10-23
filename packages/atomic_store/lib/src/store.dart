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
  /// [search]. Who signs a write is the backend's agent (over the bridge, the
  /// `AtomicStore` handle's, which `AtomicFlutter.open` creates).
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

  /// Full-text search, best first. [drive] limits it to that resource and
  /// everything under it, however deep (default: this store's [drive]; pass
  /// an empty string to search every drive). [isA], a class URL such as
  /// [Classes.folder], keeps only instances of that class (the backend
  /// filters before [limit], so a class with few matches is still found).
  Future<List<SearchResult>> search(String query,
      {String? drive, String? isA, int limit = 20}) {
    final scope = drive ?? this.drive;
    return backend.search(query,
        drive: (scope == null || scope.isEmpty) ? null : scope,
        isA: (isA == null || isA.isEmpty) ? null : isA,
        limit: limit);
  }

  /// Create a drive named [name] and return it.
  Future<Resource> createDrive(String name) async {
    final subject = await backend.createDrive(name);
    return getResource(subject, fresh: true);
  }

  /// The resource [subject] now and again after every change, until it is
  /// destroyed (the stream then ends) or the listener cancels. Each event is
  /// the same [Resource] instance, reloaded. The first event is the current
  /// value (read fresh), so a listener never waits for a change to see
  /// something. After that one event per [ResourceEventKind.changed] of
  /// [subject]; a quiet [timeout] (default 60 s) just waits again.
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

  /// The children of [parent] now and again whenever the list changes: a
  /// child is added, removed, moved to or from [parent], or one of the
  /// children changes. Each event is the full list, in display order
  /// ([Resource.childSubjects]), as the same [Resource] instances reloaded.
  /// Ends when [parent] is destroyed or the listener cancels.
  ///
  /// Built on [StoreBackend.waitForStoreEvent], which fires for every
  /// [ResourceEventKind.changed] (a create, an edit, a move) and
  /// [ResourceEventKind.destroyed] of any resource, local or synced. After
  /// each one the child list is read again; an event is emitted when the list
  /// differs or the event's resource is one of the children. Events in the
  /// gap between two waits are not replayed, so the list is also re-read
  /// after every [timeout] (default 60 s) and emitted if it changed then.
  ///
  /// With [isA] (a class URL) the lists hold only children of that class, and
  /// an event is emitted only when that filtered list changes (a child enters
  /// or leaves it, or one of its members changes). The filter is applied
  /// here, after [limit] children were read.
  Stream<List<Resource>> watchChildren(String parent,
      {String? isA,
      Duration timeout = const Duration(seconds: 60),
      int limit = 1000}) {
    late final StreamController<List<Resource>> controller;
    var cancelled = false;

    Future<List<Resource>> load(List<String> subjects, String? fresh) async {
      final loaded = <Resource>[];
      for (final s in subjects) {
        try {
          loaded.add(await getResource(s, fresh: s == fresh));
        } on StoreException catch (e) {
          if (e.kind != StoreErrorKind.notFound) rethrow;
        }
      }
      return loaded;
    }

    bool same(List<String> a, List<String> b) =>
        a.length == b.length && Iterable<int>.generate(a.length).every((i) => a[i] == b[i]);

    List<Resource> only(List<Resource> all) =>
        isA == null ? all : [for (final r in all) if (r.isA(isA)) r];

    Future<void> run() async {
      try {
        var known = await backend.childSubjects(parent, limit: limit);
        final first = only(await load(known, null));
        if (cancelled) return;
        var shown = [for (final r in first) r.subject];
        controller.add(first);
        while (!cancelled) {
          final event = await backend.waitForStoreEvent(timeout);
          if (cancelled) return;
          if (event.kind == ResourceEventKind.destroyed &&
              event.subject == parent) {
            _resources.remove(parent);
            return;
          }
          final now = await backend.childSubjects(parent, limit: limit);
          final touchedChild = event.kind != ResourceEventKind.timeout &&
              (known.contains(event.subject) || now.contains(event.subject));
          if (!touchedChild && same(known, now)) continue;
          known = now;
          final list =
              only(await load(now, touchedChild ? event.subject : null));
          if (cancelled) return;
          final subjects = [for (final r in list) r.subject];
          // A filtered list only changes when a member enters, leaves or is
          // edited; an edit of a child outside the filter is not news.
          if (isA != null &&
              same(shown, subjects) &&
              !(touchedChild && subjects.contains(event.subject))) {
            continue;
          }
          shown = subjects;
          controller.add(list);
        }
      } catch (e, st) {
        if (!cancelled) controller.addError(e, st);
      } finally {
        if (!controller.isClosed) await controller.close();
      }
    }

    controller = StreamController<List<Resource>>(
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

  /// Used by [Resource.destroy].
  void forget(String subject) => _resources.remove(subject);

  /// Used by [Resource.save] once a draft has its subject.
  void remember(Resource resource) {
    _resources[resource.subject] = resource;
  }
}
