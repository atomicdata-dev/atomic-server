import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:atomic_store_flutter/bridge/api/error.dart' as bridge;
import 'package:atomic_store_flutter/bridge/api/resources.dart' as bridge;
import 'package:atomic_store/atomic_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('every value survives the trip to the bridge types and back', () {
    final values = <Value>[
      const StringValue('a'),
      const MarkdownValue('# a'),
      const SlugValue('a-b'),
      const DateValue('2026-10-22'),
      const UriValue('mailto:a@example.com'),
      const LinkValue('did:ad:abc'),
      const IntegerValue(-4),
      const FloatValue(1.5),
      const TimestampValue(1700000000000),
      const BooleanValue(true),
      const BooleanValue(false),
      const JsonValue('{"a":1}'),
      const LocalizedValue({'nl': 'hallo', 'en': 'hello'}),
      const ArrayValue([
        LinkValue('did:ad:abc'),
        NestedValue({Props.name: StringValue('inner')}),
      ]),
      const NestedValue({'p': IntegerValue(1)}),
      const UnsupportedValue('loroDoc', '12 bytes'),
    ];
    for (final v in values) {
      expect(valueFromBridge(valueToBridge(v)), v, reason: '$v');
    }
  });

  test('a property list becomes a map and back', () {
    final props = {Props.name: const StringValue('x'), Props.parent: const LinkValue('d')};
    expect(propsFromBridge(propsToBridge(props)), props);
  });

  test('bridge error kinds map to store error kinds', () {
    for (final kind in bridge.ErrorKind.values) {
      final e = storeExceptionFromBridge(
          bridge.AtomicError(kind: kind, message: 'm'), 'did:ad:x');
      expect(e.kind.name, kind.name);
      expect(e.message, 'm');
      expect(e.subject, 'did:ad:x');
    }
  });

  group('over a BridgeResourceApi', () {
    late _FakeApi api;
    late BridgeStoreBackend backend;
    setUp(() {
      api = _FakeApi();
      backend = BridgeStoreBackend.withApi(api);
    });

    test('a read becomes a snapshot of typed values', () async {
      api.data = bridge.ResourceData(subject: 'did:ad:a', props: [
        bridge.PropValue(
            property: Props.name, value: valueToBridge(const StringValue('A')))
      ]);
      final snap = await backend.getResource('did:ad:a');
      expect(snap.subject, 'did:ad:a');
      expect(snap.props, {Props.name: const StringValue('A')});
    });

    test('a save and a create send bridge values', () async {
      await backend.saveChanges(
          'did:ad:a', {Props.name: const StringValue('B')}, [Props.description]);
      expect(api.saved?.$1, 'did:ad:a');
      expect(api.saved?.$2.single.property, Props.name);
      expect(api.saved?.$3, [Props.description]);
      expect(await backend.createResource({Props.name: const StringValue('N')}),
          'did:ad:new');
      expect(api.created.single.value.text, 'N');
    });

    test('search, children, drive and events pass through', () async {
      api.hits = [
        const bridge.SearchHit(
            subject: 's', title: 't', className: 'c', drive: 'd', score: 2.5)
      ];
      final hits = await backend.search('q', drive: 'd', limit: 5);
      expect(hits.single.title, 't');
      expect(api.searched, ('q', 'd', 5));
      expect(await backend.childSubjects('p', limit: 3), ['x', 'y']);
      expect(await backend.createDrive('Work'), 'did:ad:drive');
      api.event = bridge.ResourceEvent.destroyed;
      expect(await backend.waitForEvent('s', const Duration(seconds: 2)),
          ResourceEventKind.destroyed);
      expect(api.waitedMs, 2000);
    });

    test('destroy and the store-wide event map to the bridge calls', () async {
      await backend.destroyResource('did:ad:gone');
      expect(api.destroyed, ['did:ad:gone']);
      api.storeEvent = const bridge.StoreEvent(
          kind: bridge.ResourceEvent.destroyed, subject: 'did:ad:gone');
      final e = await backend.waitForStoreEvent(const Duration(seconds: 3));
      expect(e.kind, ResourceEventKind.destroyed);
      expect(e.subject, 'did:ad:gone');
      expect(api.waitedStoreMs, 3000);
    });

    test('a destroy error is a StoreException with the subject', () {
      api.error = const bridge.AtomicError(
          kind: bridge.ErrorKind.notFound, message: 'gone');
      expect(
          backend.destroyResource('did:ad:z'),
          throwsA(isA<StoreException>()
              .having((e) => e.kind, 'kind', StoreErrorKind.notFound)
              .having((e) => e.subject, 'subject', 'did:ad:z')));
    });

    test('a resource destroyed through a Store is forgotten', () async {
      api.data = bridge.ResourceData(subject: 'did:ad:a', props: [
        bridge.PropValue(
            property: Props.name, value: valueToBridge(const StringValue('A')))
      ]);
      final store = Store(backend: backend);
      final r = await store.getResource('did:ad:a');
      await r.destroy();
      expect(api.destroyed, ['did:ad:a']);
      expect(r.isDestroyed, isTrue);
    });

    test('a bridge error is thrown as a StoreException with the subject', () {
      api.error = const bridge.AtomicError(
          kind: bridge.ErrorKind.notFound, message: 'gone');
      expect(
          backend.getResource('did:ad:z'),
          throwsA(isA<StoreException>()
              .having((e) => e.kind, 'kind', StoreErrorKind.notFound)
              .having((e) => e.subject, 'subject', 'did:ad:z')));
    });
  });
}

class _FakeApi implements BridgeResourceApi {
  bridge.ResourceData data = const bridge.ResourceData(subject: '', props: []);
  List<bridge.SearchHit> hits = [];
  bridge.ResourceEvent event = bridge.ResourceEvent.timeout;
  bridge.AtomicError? error;
  (String, List<bridge.PropValue>, List<String>)? saved;
  List<bridge.PropValue> created = [];
  (String, String?, int)? searched;
  int? waitedMs;
  final List<String> destroyed = [];
  bridge.StoreEvent storeEvent = const bridge.StoreEvent(
      kind: bridge.ResourceEvent.timeout, subject: '');
  int? waitedStoreMs;

  Future<T> _run<T>(T Function() f) async {
    final e = error;
    if (e != null) throw e;
    return f();
  }

  @override
  Future<bridge.ResourceData> getResourceData(String subject) =>
      _run(() => data);
  @override
  Future<void> saveResourceChanges(String subject,
          List<bridge.PropValue> changes, List<String> remove) =>
      _run(() => saved = (subject, changes, remove));
  @override
  Future<String> createResourceWithValues(List<bridge.PropValue> values) =>
      _run(() {
        created = values;
        return 'did:ad:new';
      });
  @override
  Future<List<bridge.SearchHit>> searchResources(
          String query, String? drive, int limit) =>
      _run(() {
        searched = (query, drive, limit);
        return hits;
      });
  @override
  Future<List<String>> getChildSubjects(String parent, int limit) =>
      _run(() => ['x', 'y']);
  @override
  Future<String> newDrive(String name) => _run(() => 'did:ad:drive');
  @override
  Future<bridge.ResourceEvent> waitForResourceEvent(
          String subject, int timeoutMs) =>
      _run(() {
        waitedMs = timeoutMs;
        return event;
      });
  @override
  Future<void> destroyResource(String subject) =>
      _run(() => destroyed.add(subject));
  @override
  Future<bridge.StoreEvent> waitForStoreEvent(int timeoutMs) => _run(() {
        waitedStoreMs = timeoutMs;
        return storeEvent;
      });
}
