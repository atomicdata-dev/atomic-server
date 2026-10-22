import 'dart:async';

import 'backend.dart';
import 'exceptions.dart';
import 'urls.dart';
import 'value.dart';

/// A [StoreBackend] that keeps resources in a map, for tests of code that uses
/// a [Store]. Subjects of created resources are `did:ad:test:1`, `…:2`, …
class InMemoryBackend implements StoreBackend {
  InMemoryBackend([Map<String, Map<String, Value>> resources = const {}]) {
    resources.forEach((subject, props) => this.resources[subject] = Map.of(props));
  }

  /// The resources by subject. Change it directly and call [touch] to act as
  /// "someone else edited this".
  final Map<String, Map<String, Value>> resources = {};

  /// Every call made, as `method subject-or-query`.
  final List<String> calls = [];

  /// Throw this from the next call (then forget it).
  StoreException? failNext;

  int _next = 0;
  final Map<String, List<Completer<ResourceEventKind>>> _waiting = {};

  void _enter(String call) {
    calls.add(call);
    final failure = failNext;
    if (failure != null) {
      failNext = null;
      throw failure;
    }
  }

  void _emit(String subject, ResourceEventKind kind) {
    final waiting = _waiting.remove(subject) ?? const [];
    for (final c in waiting) {
      if (!c.isCompleted) c.complete(kind);
    }
  }

  /// Announce a change of [subject] to everyone waiting for it.
  void touch(String subject) => _emit(subject, ResourceEventKind.changed);

  /// Remove [subject] and announce it.
  void destroy(String subject) {
    resources.remove(subject);
    _emit(subject, ResourceEventKind.destroyed);
  }

  @override
  Future<ResourceSnapshot> getResource(String subject) async {
    _enter('getResource $subject');
    final props = resources[subject];
    if (props == null) {
      throw StoreException(StoreErrorKind.notFound, 'Not found: $subject',
          subject: subject);
    }
    return ResourceSnapshot(subject, Map.of(props));
  }

  @override
  Future<void> saveChanges(
      String subject, Map<String, Value> set, List<String> remove) async {
    _enter('saveChanges $subject');
    final props = resources[subject];
    if (props == null) {
      throw StoreException(StoreErrorKind.notFound, 'Not found: $subject',
          subject: subject);
    }
    props.addAll(set);
    remove.forEach(props.remove);
    _emit(subject, ResourceEventKind.changed);
  }

  @override
  Future<String> createResource(Map<String, Value> values) async {
    _enter('createResource');
    final subject = 'did:ad:test:${++_next}';
    resources[subject] = Map.of(values);
    return subject;
  }

  @override
  Future<List<SearchResult>> search(String query,
      {String? drive, int limit = 20}) async {
    _enter('search $query');
    final needle = query.toLowerCase();
    final hits = <SearchResult>[];
    for (final e in resources.entries) {
      final name = e.value[Props.name];
      final title = name is StringValue ? name.value : '';
      if (title.toLowerCase().contains(needle)) {
        final parent = e.value[Props.parent];
        final inDrive = parent is LinkValue ? parent.subject : '';
        if (drive == null || drive == inDrive || drive == e.key) {
          hits.add(SearchResult(
              subject: e.key, title: title, drive: inDrive, score: 1));
        }
      }
    }
    return hits.take(limit).toList();
  }

  @override
  Future<List<String>> childSubjects(String parent, {int limit = 1000}) async {
    _enter('childSubjects $parent');
    return [
      for (final e in resources.entries)
        if (e.value[Props.parent] == LinkValue(parent)) e.key
    ].take(limit).toList();
  }

  @override
  Future<String> createDrive(String name) async {
    _enter('createDrive $name');
    final subject = 'did:ad:test:${++_next}';
    resources[subject] = {
      Props.isA: const ArrayValue([LinkValue(Classes.drive)]),
      Props.name: StringValue(name),
    };
    return subject;
  }

  @override
  Future<ResourceEventKind> waitForEvent(
      String subject, Duration timeout) async {
    _enter('waitForEvent $subject');
    final completer = Completer<ResourceEventKind>();
    (_waiting[subject] ??= []).add(completer);
    final timer = Timer(timeout, () {
      if (!completer.isCompleted) completer.complete(ResourceEventKind.timeout);
    });
    try {
      return await completer.future;
    } finally {
      timer.cancel();
    }
  }
}
