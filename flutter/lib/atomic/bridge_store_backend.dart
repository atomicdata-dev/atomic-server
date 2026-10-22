import 'package:atomic_store/atomic_store.dart';

import '../src/rust/api/error.dart' as bridge;
import '../src/rust/api/resources.dart' as bridge;

/// The [StoreBackend] of `package:atomic_store` over the Rust bridge
/// (`rust/src/api/resources.rs`): the generic, typed resource functions. The
/// store and the signing agent are the bridge's process-wide ones.
///
/// ```dart
/// final store = Store(backend: BridgeStoreBackend(), drive: activeDrive);
/// ```
class BridgeStoreBackend implements StoreBackend {
  const BridgeStoreBackend();

  @override
  Future<ResourceSnapshot> getResource(String subject) => _guard(() async {
        final data = await bridge.getResourceData(subject: subject);
        return ResourceSnapshot(data.subject, propsFromBridge(data.props));
      }, subject);

  @override
  Future<void> saveChanges(
          String subject, Map<String, Value> set, List<String> remove) =>
      _guard(
          () => bridge.saveResourceChanges(
              subject: subject, changes: propsToBridge(set), remove: remove),
          subject);

  @override
  Future<String> createResource(Map<String, Value> values) => _guard(
      () => bridge.createResourceWithValues(values: propsToBridge(values)));

  @override
  Future<List<SearchResult>> search(String query,
          {String? drive, int limit = 20}) =>
      _guard(() async {
        final hits = await bridge.searchResources(
            query: query, drive: drive, limit: limit);
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
      _guard(() => bridge.getChildSubjects(parent: parent, limit: limit),
          parent);

  @override
  Future<String> createDrive(String name) =>
      _guard(() => bridge.newDrive(name: name));

  @override
  Future<ResourceEventKind> waitForEvent(String subject, Duration timeout) =>
      _guard(() async {
        final event = await bridge.waitForResourceEvent(
            subject: subject, timeoutMs: timeout.inMilliseconds);
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
