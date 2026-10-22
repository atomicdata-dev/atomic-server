import 'package:atomic_store/atomic_store.dart';
import 'package:flutter/foundation.dart' show visibleForTesting;

import '../src/rust/api/error.dart' as bridge;
import '../src/rust/api/resources.dart' as bridge;

/// The typed resource calls of the bridge (`rust/src/api/resources.rs`) as one
/// interface: [AtomicStore] methods or the default store's functions.
abstract interface class BridgeResourceApi {
  Future<bridge.ResourceData> getResourceData(String subject);
  Future<void> saveResourceChanges(
      String subject, List<bridge.PropValue> changes, List<String> remove);
  Future<String> createResourceWithValues(List<bridge.PropValue> values);
  Future<List<bridge.SearchHit>> searchResources(
      String query, String? drive, int limit);
  Future<List<String>> getChildSubjects(String parent, int limit);
  Future<String> newDrive(String name);
  Future<bridge.ResourceEvent> waitForResourceEvent(
      String subject, int timeoutMs);
}

/// The default store: the one `openDb` opened, signing as the agent
/// `loadAgent` set.
class _DefaultStoreApi implements BridgeResourceApi {
  const _DefaultStoreApi();

  @override
  Future<bridge.ResourceData> getResourceData(String subject) =>
      bridge.getResourceData(subject: subject);

  @override
  Future<void> saveResourceChanges(String subject,
          List<bridge.PropValue> changes, List<String> remove) =>
      bridge.saveResourceChanges(
          subject: subject, changes: changes, remove: remove);

  @override
  Future<String> createResourceWithValues(List<bridge.PropValue> values) =>
      bridge.createResourceWithValues(values: values);

  @override
  Future<List<bridge.SearchHit>> searchResources(
          String query, String? drive, int limit) =>
      bridge.searchResources(query: query, drive: drive, limit: limit);

  @override
  Future<List<String>> getChildSubjects(String parent, int limit) =>
      bridge.getChildSubjects(parent: parent, limit: limit);

  @override
  Future<String> newDrive(String name) => bridge.newDrive(name: name);

  @override
  Future<bridge.ResourceEvent> waitForResourceEvent(
          String subject, int timeoutMs) =>
      bridge.waitForResourceEvent(subject: subject, timeoutMs: timeoutMs);
}

/// One [bridge.AtomicStore] handle: its store, agent and drive.
class _HandleApi implements BridgeResourceApi {
  const _HandleApi(this._store);

  final bridge.AtomicStore _store;

  @override
  Future<bridge.ResourceData> getResourceData(String subject) =>
      _store.getResourceData(subject: subject);

  @override
  Future<void> saveResourceChanges(String subject,
          List<bridge.PropValue> changes, List<String> remove) =>
      _store.saveResourceChanges(
          subject: subject, changes: changes, remove: remove);

  @override
  Future<String> createResourceWithValues(List<bridge.PropValue> values) =>
      _store.createResourceWithValues(values: values);

  @override
  Future<List<bridge.SearchHit>> searchResources(
          String query, String? drive, int limit) =>
      _store.searchResources(query: query, drive: drive, limit: limit);

  @override
  Future<List<String>> getChildSubjects(String parent, int limit) =>
      _store.getChildSubjects(parent: parent, limit: limit);

  @override
  Future<String> newDrive(String name) => _store.newDrive(name: name);

  @override
  Future<bridge.ResourceEvent> waitForResourceEvent(
          String subject, int timeoutMs) =>
      _store.waitForResourceEvent(subject: subject, timeoutMs: timeoutMs);
}

/// The [StoreBackend] of `package:atomic_store` over the Rust bridge: the
/// generic, typed resource functions. It works on one [bridge.AtomicStore]
/// handle, which owns the open store, the signing agent and the drive, or,
/// without one, on the default store `openDb` and `loadAgent` set.
///
/// ```dart
/// final handle = await bridge.AtomicStore.open(
///     path: dir, agentSecret: secret, drive: driveSubject);
/// final store = Store(backend: BridgeStoreBackend(handle), drive: driveSubject);
/// ```
class BridgeStoreBackend implements StoreBackend {
  /// A backend on [store], or on the default store when it is null.
  BridgeStoreBackend([bridge.AtomicStore? store])
      : _api = store == null ? const _DefaultStoreApi() : _HandleApi(store);

  /// A backend over any [BridgeResourceApi] (tests).
  @visibleForTesting
  const BridgeStoreBackend.withApi(this._api);

  final BridgeResourceApi _api;

  @override
  Future<ResourceSnapshot> getResource(String subject) => _guard(() async {
        final data = await _api.getResourceData(subject);
        return ResourceSnapshot(data.subject, propsFromBridge(data.props));
      }, subject);

  @override
  Future<void> saveChanges(
          String subject, Map<String, Value> set, List<String> remove) =>
      _guard(() => _api.saveResourceChanges(subject, propsToBridge(set), remove),
          subject);

  @override
  Future<String> createResource(Map<String, Value> values) =>
      _guard(() => _api.createResourceWithValues(propsToBridge(values)));

  @override
  Future<List<SearchResult>> search(String query,
          {String? drive, int limit = 20}) =>
      _guard(() async {
        final hits = await _api.searchResources(query, drive, limit);
        return [
          for (final h in hits)
            SearchResult(
              subject: h.subject,
              title: h.title,
              className: h.className,
              drive: h.drive,
              score: h.score,
            )
        ];
      });

  @override
  Future<List<String>> childSubjects(String parent, {int limit = 1000}) =>
      _guard(() => _api.getChildSubjects(parent, limit), parent);

  @override
  Future<String> createDrive(String name) => _guard(() => _api.newDrive(name));

  @override
  Future<ResourceEventKind> waitForEvent(String subject, Duration timeout) =>
      _guard(() async {
        final event =
            await _api.waitForResourceEvent(subject, timeout.inMilliseconds);
        return switch (event) {
          bridge.ResourceEvent.changed => ResourceEventKind.changed,
          bridge.ResourceEvent.destroyed => ResourceEventKind.destroyed,
          bridge.ResourceEvent.timeout => ResourceEventKind.timeout,
        };
      }, subject);
}

Future<T> _guard<T>(Future<T> Function() call, [String? subject]) async {
  try {
    return await call();
  } on bridge.AtomicError catch (e) {
    throw storeExceptionFromBridge(e, subject);
  }
}

/// A bridge [bridge.AtomicError] as the [StoreException] the store layer throws.
StoreException storeExceptionFromBridge(bridge.AtomicError e,
        [String? subject]) =>
    StoreException(
      switch (e.kind) {
        bridge.ErrorKind.notFound => StoreErrorKind.notFound,
        bridge.ErrorKind.unauthorized => StoreErrorKind.unauthorized,
        bridge.ErrorKind.network => StoreErrorKind.network,
        bridge.ErrorKind.invalid => StoreErrorKind.invalid,
        bridge.ErrorKind.storage => StoreErrorKind.storage,
        bridge.ErrorKind.other => StoreErrorKind.other,
      },
      e.message,
      subject: subject,
    );

/// The bridge's property list as a map of typed values.
Map<String, Value> propsFromBridge(List<bridge.PropValue> props) => {
      for (final p in props) p.property: valueFromBridge(p.value),
    };

/// A map of typed values as the bridge's property list.
List<bridge.PropValue> propsToBridge(Map<String, Value> props) => [
      for (final e in props.entries)
        bridge.PropValue(property: e.key, value: valueToBridge(e.value)),
    ];

Value valueFromBridge(bridge.AtomicValue v) {
  switch (v.datatype) {
    case bridge.Datatype.string:
      return StringValue(v.text);
    case bridge.Datatype.markdown:
      return MarkdownValue(v.text);
    case bridge.Datatype.slug:
      return SlugValue(v.text);
    case bridge.Datatype.date:
      return DateValue(v.text);
    case bridge.Datatype.uri:
      return UriValue(v.text);
    case bridge.Datatype.link:
      return LinkValue(v.text);
    case bridge.Datatype.integer:
      return IntegerValue(int.parse(v.text));
    case bridge.Datatype.float:
      return FloatValue(double.parse(v.text));
    case bridge.Datatype.timestamp:
      return TimestampValue(int.parse(v.text));
    case bridge.Datatype.boolean:
      return BooleanValue(v.text == 'true');
    case bridge.Datatype.array:
      return ArrayValue([for (final i in v.items) valueFromBridge(i)]);
    case bridge.Datatype.nested:
      return NestedValue(propsFromBridge(v.props));
    case bridge.Datatype.json:
      return JsonValue(v.text);
    case bridge.Datatype.localized:
      return LocalizedValue({for (final p in v.props) p.property: p.value.text});
    case bridge.Datatype.unsupported:
      return UnsupportedValue(v.unsupportedDatatype ?? '', v.text);
  }
}

bridge.AtomicValue valueToBridge(Value v) {
  bridge.AtomicValue scalar(bridge.Datatype datatype, String text) =>
      bridge.AtomicValue(
          datatype: datatype, text: text, items: const [], props: const []);
  return switch (v) {
    StringValue(:final value) => scalar(bridge.Datatype.string, value),
    MarkdownValue(:final value) => scalar(bridge.Datatype.markdown, value),
    SlugValue(:final value) => scalar(bridge.Datatype.slug, value),
    DateValue(:final value) => scalar(bridge.Datatype.date, value),
    UriValue(:final value) => scalar(bridge.Datatype.uri, value),
    LinkValue(:final subject) => scalar(bridge.Datatype.link, subject),
    IntegerValue(:final value) => scalar(bridge.Datatype.integer, '$value'),
    FloatValue(:final value) => scalar(bridge.Datatype.float, '$value'),
    TimestampValue(:final millis) =>
      scalar(bridge.Datatype.timestamp, '$millis'),
    BooleanValue(:final value) => scalar(bridge.Datatype.boolean, '$value'),
    JsonValue(:final json) => scalar(bridge.Datatype.json, json),
    ArrayValue(:final items) => bridge.AtomicValue(
        datatype: bridge.Datatype.array,
        text: '',
        items: [for (final i in items) valueToBridge(i)],
        props: const []),
    NestedValue(:final props) => bridge.AtomicValue(
        datatype: bridge.Datatype.nested,
        text: '',
        items: const [],
        props: propsToBridge(props)),
    LocalizedValue(:final texts) => bridge.AtomicValue(
        datatype: bridge.Datatype.localized,
        text: '',
        items: const [],
        props: [
          for (final e in texts.entries)
            bridge.PropValue(
                property: e.key,
                value: scalar(bridge.Datatype.string, e.value)),
        ]),
    UnsupportedValue(:final datatype, :final description) => bridge.AtomicValue(
        datatype: bridge.Datatype.unsupported,
        text: description,
        items: const [],
        props: const [],
        unsupportedDatatype: datatype),
  };
}
