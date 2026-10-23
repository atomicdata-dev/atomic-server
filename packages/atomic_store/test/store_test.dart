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

  group('destroy', () {
    test('removes the resource, its children and the cache entry', () async {
      final b = backend();
      b.resources['did:ad:test:a1'] = {
        Props.name: const StringValue('Inside'),
        Props.parent: const LinkValue('did:ad:test:a'),
      };
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:a');
      await r.destroy();
      expect(r.isDestroyed, isTrue);
      expect(b.calls, contains('destroyResource did:ad:test:a'));
      expect(b.resources.keys, isNot(contains('did:ad:test:a')));
      expect(b.resources.keys, isNot(contains('did:ad:test:a1')));
      expect(await store.getResourceOrNull('did:ad:test:a'), isNull);
      await r.destroy(); // again: nothing happens
      expect(b.calls.where((c) => c.startsWith('destroyResource')), hasLength(1));
    });

    test('ends a watch with the destroyed event, without a manual touch',
        () async {
      final b = backend();
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:a');
      final done = Completer0();
      final sub = store.watch('did:ad:test:a').listen((_) {}, onDone: done.complete);
      await pump();
      await r.destroy();
      await done.future;
      await sub.cancel();
    });

    test('a missing resource is notFound; a draft is just discarded', () async {
      final b = backend();
      final store = Store(backend: b);
      final r = await store.getResource('did:ad:test:b');
      b.resources.remove('did:ad:test:b');
      await expectLater(
          r.destroy(),
          throwsA(isA<StoreException>()
              .having((e) => e.kind, 'kind', StoreErrorKind.notFound)));
      final draft = store.newResource(parent: drive);
      await draft.destroy();
      expect(draft.isDestroyed, isTrue);
      expect(b.calls.where((c) => c.startsWith('destroyResource')), hasLength(1));
    });
  });

  group('watchChildren', () {
    Future<(Store, InMemoryBackend, List<List<String?>>, StreamSubscription)>
        watching() async {
      final b = backend();
      final store = Store(backend: b, drive: drive);
      final lists = <List<String?>>[];
      final sub = store
          .watchChildren(drive)
          .listen((l) => lists.add([for (final r in l) r.name]));
      await pump();
      return (store, b, lists, sub);
    }

    test('emits the current children first', () async {
      final (_, _, lists, sub) = await watching();
      expect(lists, [
        ['Pelican notes', 'Heron']
      ]);
      await sub.cancel();
    });

    test('emits when a child is added, changed, moved away and destroyed',
        () async {
      final (store, b, lists, sub) = await watching();

      final note = store.newResource(props: {Props.name: 'Egret'});
      await note.save();
      await pump();
      expect(lists.last, ['Pelican notes', 'Heron', 'Egret']);

      note.set(Props.name, 'Great egret');
      await note.save();
      await pump();
      expect(lists.last, ['Pelican notes', 'Heron', 'Great egret']);

      final other = store.newResource(props: {Props.name: 'Elsewhere'});
      await other.save();
      await pump();
      final count = lists.length;
      note.set(Props.parent, other.subject);
      await note.save();
      await pump();
      expect(lists.length, count + 1);
      expect(lists.last, ['Pelican notes', 'Heron', 'Elsewhere']);

      await (await store.getResource('did:ad:test:b')).destroy();
      await pump();
      expect(lists.last, ['Pelican notes', 'Elsewhere']);
      await sub.cancel();
    });

    test('does not emit for unrelated changes and ends with the parent',
        () async {
      final b = backend();
      b.resources['did:ad:test:far'] = {Props.name: const StringValue('Far')};
      final store = Store(backend: b);
      var emitted = 0;
      final done = Completer0();
      final sub = store
          .watchChildren('did:ad:test:a')
          .listen((_) => emitted++, onDone: done.complete);
      await pump();
      expect(emitted, 1);
      b.touch('did:ad:test:far');
      await pump();
      expect(emitted, 1);
      b.destroy('did:ad:test:a');
      await done.future;
      await sub.cancel();
    });
  });

  test('InMemoryBackend search matches name and description, any case',
      () async {
    final b = backend();
    b.resources['did:ad:test:a']![Props.description] =
        const StringValue('Large Seabird');
    final store = Store(backend: b);
    expect((await store.search('SEABIRD')).map((h) => h.subject),
        ['did:ad:test:a']);
    expect((await store.search('eron')).map((h) => h.subject),
        ['did:ad:test:b']);
  });

  group('moveTo', () {
    test('sets the parent as a link, local until save', () async {
      final b = backend();
      final store = Store(backend: b, drive: drive);
      final folder = await store.getResource('did:ad:test:a');
      final heron = await store.getResource('did:ad:test:b');
      heron.moveTo(folder.subject);
      expect(heron.get(Props.parent), LinkValue(folder.subject));
      expect(heron.isDirty, isTrue);
      expect(b.resources['did:ad:test:b']![Props.parent], const LinkValue(drive));
      await heron.save();
      expect(b.resources['did:ad:test:b']![Props.parent],
          LinkValue(folder.subject));
      expect(await folder.childSubjects(), ['did:ad:test:b']);
    });

    test('watchChildren drops the child from the old parent and lists it in the new',
        () async {
      final b = backend();
      addTearDown(b.dispose);
      final store = Store(backend: b, drive: drive);
      final heron = await store.getResource('did:ad:test:b');
      final inDrive = <List<String>>[];
      final inFolder = <List<String>>[];
      final s1 = store
          .watchChildren(drive, timeout: const Duration(seconds: 5))
          .listen((l) => inDrive.add([for (final r in l) r.subject]));
      final s2 = store
          .watchChildren('did:ad:test:a', timeout: const Duration(seconds: 5))
          .listen((l) => inFolder.add([for (final r in l) r.subject]));
      await pumpEventQueue();
      heron.moveTo('did:ad:test:a');
      await heron.save();
      await pumpEventQueue();
      expect(inDrive.last, ['did:ad:test:a']);
      expect(inFolder.last, ['did:ad:test:b']);
      await s1.cancel();
      await s2.cancel();
    });
  });

  group('set coerces strings for link properties', () {
    test('parent and isA are links', () async {
      final store = Store(backend: backend(), drive: drive);
      final r = await store.getResource('did:ad:test:b');
      r.set(Props.parent, 'did:ad:test:a');
      r.set(Props.isA, Classes.folder);
      expect(r.get(Props.parent), const LinkValue('did:ad:test:a'));
      expect(r.parent, 'did:ad:test:a');
      expect(r.get(Props.isA), const ArrayValue([LinkValue(Classes.folder)]));
      expect(r.isA(Classes.folder), isTrue);
      await r.save();
      expect(r.parent, 'did:ad:test:a');
    });

    test('newResource props use the same rule', () {
      final store = Store(backend: backend(), drive: drive);
      final r = store.newResource(props: {Props.parent: 'did:ad:test:a'});
      expect(r.parent, 'did:ad:test:a');
    });

    test('a custom property keeps a plain string as text', () async {
      const owner = 'https://example.com/properties/owner';
      final store = Store(backend: backend(), drive: drive);
      final r = await store.getResource('did:ad:test:b');
      r.set(owner, 'did:ad:test:a');
      expect(r.get(owner), const StringValue('did:ad:test:a'));
      r.set(owner, const LinkValue('did:ad:test:a'));
      expect(r.getLink(owner), 'did:ad:test:a');
      r.set(owner, ['did:ad:test:a']);
      expect(r.getLinks(owner), ['did:ad:test:a']);
    });
  });

  group('search semantics', () {
    InMemoryBackend deep() => InMemoryBackend({
          drive: {
            Props.isA: const ArrayValue([LinkValue(Classes.drive)]),
            Props.name: const StringValue('Home'),
          },
          'did:ad:test:folder': {
            Props.isA: const ArrayValue([LinkValue(Classes.folder)]),
            Props.name: const StringValue('Boards'),
            Props.parent: const LinkValue(drive),
          },
          'did:ad:test:task': {
            Props.isA: const ArrayValue([LinkValue('https://example.com/Task')]),
            Props.name: const StringValue('Zebra task'),
            Props.parent: const LinkValue('did:ad:test:folder'),
          },
          'did:ad:test:doc': {
            Props.isA: const ArrayValue([LinkValue(Classes.documentV2)]),
            Props.shortname: const SlugValue('zebra-doc'),
            Props.parent: const LinkValue('did:ad:test:folder'),
          },
          'did:ad:test:otherdrive': {
            Props.isA: const ArrayValue([LinkValue(Classes.drive)]),
            Props.name: const StringValue('Elsewhere zebra'),
          },
          Classes.folder: {Props.name: const StringValue('Folder')},
        });

    test('a drive scope matches descendants by ancestry, not direct children',
        () async {
      final store = Store(backend: deep(), drive: drive);
      expect((await store.search('zebra')).map((h) => h.subject).toSet(),
          {'did:ad:test:task', 'did:ad:test:doc'});
      final all = await store.search('zebra', drive: '');
      expect(all.map((h) => h.subject), contains('did:ad:test:otherdrive'));
      // Any ancestor scopes, and so does the resource itself.
      final inFolder =
          await store.search('zebra', drive: 'did:ad:test:folder');
      expect(inFolder, hasLength(2));
      final self =
          await store.search('boards', drive: 'did:ad:test:folder');
      expect(self.single.subject, 'did:ad:test:folder');
    });

    test('hits carry the drive they live in, the class name and the title',
        () async {
      final store = Store(backend: deep(), drive: drive);
      final hits = {
        for (final h in await store.search('zebra', drive: ''))
          h.subject: h
      };
      final task = hits['did:ad:test:task']!;
      expect(task.drive, drive);
      expect(task.className, 'https://example.com/Task'); // class has no name
      final doc = hits['did:ad:test:doc']!;
      expect(doc.title, 'zebra-doc'); // shortname when there is no name
      expect(doc.className, Classes.documentV2);
      expect(hits['did:ad:test:otherdrive']!.drive, 'did:ad:test:otherdrive');
      final folder = (await store.search('boards')).single;
      expect(folder.className, 'Folder'); // the class's name when it has one
    });

    test('isA keeps one class', () async {
      final store = Store(backend: deep(), drive: drive);
      final hits = await store.search('zebra', isA: 'https://example.com/Task');
      expect(hits.single.subject, 'did:ad:test:task');
      expect(await store.search('zebra', isA: Classes.folder), isEmpty);
    });
  });

  group('JSON and string lists', () {
    const tags = 'https://example.com/properties/tags';

    test('setStrings and getStrings round-trip without jsonEncode', () async {
      final b = backend();
      final store = Store(backend: b, drive: drive);
      final r = await store.getResource('did:ad:test:b');
      expect(r.getStrings(tags), isEmpty);
      r.setStrings(tags, ['urgent', 'home office']);
      expect(r.get(tags), isA<JsonValue>());
      expect(r.getStrings(tags), ['urgent', 'home office']);
      await r.save();
      final again = await store.getResource('did:ad:test:b', fresh: true);
      expect(again.getStrings(tags), ['urgent', 'home office']);
    });

    test('getJson and setJson hold any JSON', () async {
      final store = Store(backend: backend(), drive: drive);
      final r = await store.getResource('did:ad:test:b');
      r.setJson(tags, {'a': [1, 2], 'b': 'x'});
      expect(r.getJson(tags), {'a': [1, 2], 'b': 'x'});
      expect(r.getStrings(tags), isEmpty); // an object is not a string list
      expect(r.getJson(Props.name), isNull); // not JSON
      expect(JsonValue.strings(['a']).json, '["a"]');
      expect(JsonValue.encode([1]).data, [1]);
    });
  });

  group('watchChildren isA', () {
    test('only children of the class are listed and news is filtered',
        () async {
      const task = 'https://example.com/Task';
      final b = backend();
      addTearDown(b.dispose);
      final store = Store(backend: b, drive: drive);
      final lists = <List<String>>[];
      final sub = store
          .watchChildren(drive, isA: task, timeout: const Duration(seconds: 5))
          .listen((l) => lists.add([for (final r in l) r.subject]));
      await pumpEventQueue();
      expect(lists, [<String>[]]); // the folder and Heron are not tasks

      await store.newResource(isA: [task], props: {Props.name: 'T1'}).save();
      await pumpEventQueue();
      expect(lists.last, ['did:ad:test:1']);
      final count = lists.length;

      // Editing a child that is not a task is not news for this list.
      final heron = await store.getResource('did:ad:test:b');
      heron.set(Props.name, 'Heron 2');
      await heron.save();
      await pumpEventQueue();
      expect(lists, hasLength(count));

      // A child that stops being a task leaves the list.
      final t1 = await store.getResource('did:ad:test:1');
      t1.set(Props.isA, Classes.folder);
      await t1.save();
      await pumpEventQueue();
      expect(lists.last, isEmpty);
      await sub.cancel();
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
