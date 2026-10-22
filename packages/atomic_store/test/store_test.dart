import 'dart:async';

import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:test/test.dart';

const drive = 'did:ad:test:drive';

InMemoryBackend backend() => InMemoryBackend({
      drive: {
        Props.isA: const ArrayValue([LinkValue(Classes.drive)]),
        Props.name: const StringValue('Home'),
      },
      'did:ad:test:a': {
        Props.isA: const ArrayValue([LinkValue(Classes.folder)]),
        Props.name: const StringValue('Pelican notes'),
        Props.parent: const LinkValue(drive),
      },
      'did:ad:test:b': {
        Props.name: const StringValue('Heron'),
        Props.parent: const LinkValue(drive),
      },
    });

void main() {
  group('getResource', () {
    test('reads once and returns the same instance', () async {
      final b = backend();
      final store = Store(backend: b);
      final r1 = await store.getResource('did:ad:test:a');
      final r2 = await store.getResource('did:ad:test:a');
      expect(identical(r1, r2), isTrue);
      expect(b.calls.where((c) => c.startsWith('getResource')), hasLength(1));
      expect(r1.name, 'Pelican notes');
      expect(r1.parent, drive);
      expect(r1.isA(Classes.folder), isTrue);
      expect(r1.isA(Classes.drive), isFalse);
    });

    test('a missing resource is a notFound StoreException', () async {
      final store = Store(backend: backend());
      await expectLater(
          store.getResource('did:ad:test:none'),
          throwsA(isA<StoreException>()
              .having((e) => e.kind, 'kind', StoreErrorKind.notFound)));
      expect(await store.getResourceOrNull('did:ad:test:none'), isNull);
    });

    test('fresh reads again and keeps unsaved changes', () async {
      final b = backend();
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:a');
      r.set(Props.description, 'mine');
      b.resources['did:ad:test:a']![Props.name] = const StringValue('Renamed');
      await store.getResource('did:ad:test:a', fresh: true);
      expect(r.name, 'Renamed');
      expect(r.getString(Props.description), 'mine');
    });
  });

  group('Resource', () {
    test('set, remove and save write one commit and reload', () async {
      final b = backend();
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:a');
      expect(r.isDirty, isFalse);
      r.set(Props.name, 'New name');
      r.remove(Props.parent);
      expect(r.isDirty, isTrue);
      expect(r.name, 'New name');
      expect(r.get(Props.parent), isNull);
      expect(b.resources['did:ad:test:a']![Props.name],
          const StringValue('Pelican notes'));

      await r.save();
      expect(r.isDirty, isFalse);
      expect(b.resources['did:ad:test:a']![Props.name],
          const StringValue('New name'));
      expect(b.resources['did:ad:test:a']!.containsKey(Props.parent), isFalse);
      expect(r.name, 'New name');
    });

    test('a failed save keeps the changes', () async {
      final b = backend();
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:a');
      r.set(Props.name, 'x');
      b.failNext =
          const StoreException(StoreErrorKind.network, 'offline');
      await expectLater(r.save(), throwsA(isA<StoreException>()));
      expect(r.isDirty, isTrue);
      await r.save();
      expect(r.isDirty, isFalse);
    });

    test('set reads plain Dart values', () async {
      final store = Store(backend: backend());
      final r = await store.getResource('did:ad:test:a');
      r.set('p/int', 3);
      r.set('p/bool', true);
      r.set('p/list', ['did:ad:test:b']);
      r.set('p/time', DateTime.utc(2026));
      expect(r.get('p/int'), const IntegerValue(3));
      expect(r.get('p/bool'), const BooleanValue(true));
      expect(r.get('p/list'), const ArrayValue([LinkValue('did:ad:test:b')]));
      expect(r.get('p/time'), TimestampValue(DateTime.utc(2026).millisecondsSinceEpoch));
      expect(() => r.set('p/x', Object()), throwsA(isA<StoreException>()));
    });

    test('children come in the backend order and skip what is missing',
        () async {
      final store = Store(backend: backend());
      final home = await store.getResource(drive);
      expect(await home.childSubjects(), ['did:ad:test:a', 'did:ad:test:b']);
      final children = await home.children();
      expect(children.map((c) => c.name), ['Pelican notes', 'Heron']);
    });
  });

  group('newResource', () {
    test('is a draft until saved, then has a subject and is cached', () async {
      final b = backend();
      final store = Store(backend: b, drive: drive);
      final r = store.newResource(
          isA: [Classes.folder], props: {Props.name: 'Fresh'});
      expect(r.isNew, isTrue);
      expect(() => r.subject, throwsStateError);
      expect(r.parent, drive);
      expect(r.isA(Classes.folder), isTrue);

      await r.save();
      expect(r.isNew, isFalse);
      expect(r.subject, startsWith('did:ad:test:'));
      expect(identical(await store.getResource(r.subject), r), isTrue);
      expect(b.resources[r.subject]![Props.name], const StringValue('Fresh'));
    });

    test('needs a parent from the call or the store', () {
      final store = Store(backend: backend());
      expect(() => store.newResource(isA: [Classes.folder]),
          throwsA(isA<StoreException>()));
      expect(store.newResource(parent: drive).parent, drive);
    });
  });

  test('search is scoped to the store drive unless told otherwise', () async {
    final store = Store(backend: backend(), drive: drive);
    expect((await store.search('pelican')).map((h) => h.subject),
        ['did:ad:test:a']);
    expect(await store.search('pelican', drive: 'did:ad:test:other'), isEmpty);
    expect(await store.search('home', drive: ''), hasLength(1));
  });

  test('createDrive returns the drive as a resource', () async {
    final store = Store(backend: backend());
    final d = await store.createDrive('Work');
    expect(d.name, 'Work');
    expect(d.isA(Classes.drive), isTrue);
  });

  group('watch', () {
    test('emits now, on every change, and ends when destroyed', () async {
      final b = backend();
      final store = Store(backend: b);
      final names = <String?>[];
      final done = Completer0();
      final sub = store.watch('did:ad:test:a').listen(
            (r) => names.add(r.name),
            onDone: done.complete,
          );
      await pump();
      expect(names, ['Pelican notes']);

      b.resources['did:ad:test:a']![Props.name] = const StringValue('One');
      b.touch('did:ad:test:a');
      await pump();
      expect(names, ['Pelican notes', 'One']);

      b.destroy('did:ad:test:a');
      await done.future;
      expect(names, hasLength(2));
      await sub.cancel();
    });

    test('keeps waiting through timeouts and stops when cancelled', () async {
      final b = backend();
      final store = Store(backend: b);
      final seen = <String?>[];
      final sub = store
          .watch('did:ad:test:a', timeout: const Duration(milliseconds: 5))
          .listen((r) => seen.add(r.name));
      await Future<void>.delayed(const Duration(milliseconds: 40));
      expect(seen, ['Pelican notes']);
      expect(b.calls.where((c) => c.startsWith('waitForEvent')).length,
          greaterThan(2));
      await sub.cancel();
      final before = b.calls.length;
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(b.calls.length - before, lessThanOrEqualTo(1));
    });

    test('a failing read is an error event', () async {
      final store = Store(backend: backend());
      await expectLater(store.watch('did:ad:test:none'),
          emitsError(isA<StoreException>()));
    });
  });

  group('Value.of', () {
    test('nested maps and equality', () {
      final v = Value.of({'a': 'x', 'b': 2});
      expect(v, const NestedValue({'a': StringValue('x'), 'b': IntegerValue(2)}));
      expect(v.hashCode,
          const NestedValue({'b': IntegerValue(2), 'a': StringValue('x')}).hashCode);
    });
  });
}

Future<void> pump() => Future<void>.delayed(const Duration(milliseconds: 10));

class Completer0 {
  final _c = Completer<void>();
  void complete() => _c.complete();
  Future<void> get future => _c.future;
}
