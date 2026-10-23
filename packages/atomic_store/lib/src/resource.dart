import 'exceptions.dart';
import 'store.dart';
import 'urls.dart';
import 'value.dart';

/// A resource: its properties, and the changes made to them since the last
/// [save]. Mirrors `Resource` of `@tomic/lib`: [get], [set], [save].
///
/// Get one from a [Store] ([Store.getResource], [Store.newResource]); it is not
/// constructed directly. The same subject always gives the same instance.
class Resource {
  Resource.internal(
    this._store,
    this._subject,
    Map<String, Value> props, {
    required bool isNew,
  })  : _saved = Map.of(props),
        _isNew = isNew;

  final Store _store;
  String? _subject;
  bool _isNew;
  Map<String, Value> _saved;
  final Map<String, Value> _changes = {};
  final Set<String> _removed = {};

  /// The resource's subject. A resource from [Store.newResource] has none
  /// until [save]: subjects are derived from the signed first commit, so they
  /// cannot be made up front (`@tomic/lib`'s `createSubject` has no
  /// counterpart). Throws [StateError] for such a draft; check [isNew].
  String get subject =>
      _subject ??
      (throw StateError('This resource has no subject until it is saved'));

  /// `true` for a draft that has not been saved yet.
  bool get isNew => _isNew;

  /// `true` when [set] or [remove] changed something that is not saved.
  bool get isDirty => _isNew || _changes.isNotEmpty || _removed.isNotEmpty;

  /// All properties as they would be after [save].
  Map<String, Value> get props => Map.unmodifiable(_merged());

  Map<String, Value> _merged() {
    final merged = {..._saved, ..._changes};
    for (final removed in _removed) {
      merged.remove(removed);
    }
    return merged;
  }

  /// The value of [property], or `null` when it has none. Sees unsaved
  /// changes.
  Value? get(String property) {
    if (_removed.contains(property)) return null;
    return _changes[property] ?? _saved[property];
  }

  /// [property] as a string, when it holds text (string, markdown, slug,
  /// date or URI).
  String? getString(String property) => switch (get(property)) {
        StringValue(:final value) ||
        MarkdownValue(:final value) ||
        SlugValue(:final value) ||
        DateValue(:final value) ||
        UriValue(:final value) =>
          value,
        _ => null,
      };

  /// The subject [property] links to, when it holds one link.
  String? getLink(String property) => switch (get(property)) {
        LinkValue(:final subject) => subject,
        _ => null,
      };

  /// The subjects [property] links to, in order.
  List<String> getLinks(String property) => switch (get(property)) {
        ArrayValue(:final links) => links,
        LinkValue(:final subject) => [subject],
        _ => const [],
      };

  /// The decoded JSON in [property] (`List`, `Map`, ...), when it holds a
  /// [JsonValue]; `null` otherwise. See [setJson].
  Object? getJson(String property) => switch (get(property)) {
        JsonValue(:final data) => data,
        _ => null,
      };

  /// The strings in the JSON array [property] holds (see [setStrings]); empty
  /// when it is not set or not a JSON array. Items that are not strings are
  /// left out.
  List<String> getStrings(String property) => switch (getJson(property)) {
        List<Object?> l => l.whereType<String>().toList(),
        _ => const [],
      };

  /// Set [property] to a JSON array of [items], for a list of plain strings
  /// such as tags (a `List<String>` given to [set] would be links). Read it
  /// back with [getStrings]. Local until [save].
  void setStrings(String property, Iterable<String> items) =>
      set(property, JsonValue.strings(items));

  /// Set [property] to [data] as JSON (see [JsonValue.encode]). Read it back
  /// with [getJson]. Local until [save].
  void setJson(String property, Object? data) =>
      set(property, JsonValue.encode(data));

  /// Set [property] to [value] (see [Value.of] for how plain Dart values are
  /// read). Local until [save].
  ///
  /// A plain `String` is a string, except for the link properties of
  /// [Props.linkProperties] (`parent`, `isA`): there it is stored as a link
  /// (`isA` as a list of one class), so `set(Props.parent, subject)` is a
  /// move. For a property of your own that holds a link pass
  /// `LinkValue(subject)` (or a `List` of subjects for several); a plain
  /// string stays text.
  void set(String property, Object value) {
    _changes[property] = _coerce(property, value);
    _removed.remove(property);
  }

  static Value _coerce(String property, Object value) {
    if (value is String && Props.linkProperties.contains(property)) {
      return property == Props.isA
          ? ArrayValue([LinkValue(value)])
          : LinkValue(value);
    }
    return Value.of(value);
  }

  /// Move the resource under [parent] (a subject): sets [Props.parent] as a
  /// link. Like [set] it is local until [save] (a move does not save itself).
  /// After the save the old parent's [Store.watchChildren]
  /// drops the resource and the new parent's lists it.
  void moveTo(String parent) => set(Props.parent, LinkValue(parent));

  /// Remove [property]. Local until [save].
  void remove(String property) {
    _changes.remove(property);
    if (_saved.containsKey(property)) _removed.add(property);
  }

  /// Write the changes as one signed commit by the active agent. A draft is
  /// created (and gets its [subject]). Throws [StoreException]; the changes
  /// stay for another try.
  Future<void> save() async {
    final backend = _store.backend;
    if (_isNew) {
      final values = _merged();
      if (values.isEmpty) {
        throw const StoreException(
            StoreErrorKind.invalid, 'A new resource needs properties');
      }
      final created = await backend.createResource(values);
      _subject = created;
      _isNew = false;
      _saved = {};
      _changes.clear();
      _removed.clear();
      _store.remember(this);
      await reload();
      return;
    }
    if (!isDirty) return;
    await backend.saveChanges(subject, Map.of(_changes), _removed.toList());
    _changes.clear();
    _removed.clear();
    await reload();
  }

  /// `true` once [destroy] has deleted this resource.
  bool get isDestroyed => _destroyed;
  bool _destroyed = false;

  /// Delete the resource and, recursively, its children, as a signed destroy
  /// commit by the active agent. Mirrors `Resource.destroy()` of
  /// `@tomic/lib`. Afterwards [isDestroyed] is `true`, the store forgets the
  /// resource, [Store.watch] streams of it end and [Store.watchChildren]
  /// lists of its parent drop it. A draft that was never saved is just
  /// discarded. Throws [StoreException] ([StoreErrorKind.notFound] when it
  /// is already gone).
  Future<void> destroy() async {
    if (_destroyed) return;
    if (!_isNew) {
      await _store.backend.destroyResource(subject);
      _store.forget(subject);
    }
    _destroyed = true;
  }

  /// Read the resource again from the store, keeping unsaved changes.
  Future<void> reload() async {
    if (_isNew) return;
    final snapshot = await _store.backend.getResource(subject);
    _saved = Map.of(snapshot.props);
  }

  /// Whether the resource is an instance of [classUrl] (its `isA`).
  bool isA(String classUrl) => classes.contains(classUrl);

  /// The class URLs in `isA`.
  List<String> get classes => getLinks(Props.isA);

  /// The `parent` subject.
  String? get parent => getLink(Props.parent);

  /// The `name`, or `null`.
  String? get name => getString(Props.name);

  /// The subjects under this resource, in the order apps list them.
  Future<List<String>> childSubjects({int limit = 1000}) =>
      _store.backend.childSubjects(subject, limit: limit);

  /// The resources under this resource, loaded; those this store cannot read
  /// ([StoreErrorKind.notFound]) are left out.
  Future<List<Resource>> children({int limit = 1000}) async {
    final loaded = <Resource>[];
    for (final child in await childSubjects(limit: limit)) {
      try {
        loaded.add(await _store.getResource(child));
      } on StoreException catch (e) {
        if (e.kind != StoreErrorKind.notFound) rethrow;
      }
    }
    return loaded;
  }

  /// Replace the saved state, keeping unsaved changes (used by [Store]).
  void applySnapshot(Map<String, Value> props) {
    _saved = Map.of(props);
  }

  @override
  String toString() => 'Resource(${_subject ?? 'unsaved'})';
}
