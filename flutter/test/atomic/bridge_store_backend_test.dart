import 'package:atomic_app/atomic/bridge_store_backend.dart';
import 'package:atomic_app/src/rust/api/error.dart' as bridge;
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
}
