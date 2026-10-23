// The "Test recipe" of the README, compiled so it stays correct.
import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:test/test.dart';

void main() {
  test('watch emits now, then once per change, and ends on destroy', () async {
    final backend = InMemoryBackend({
      'did:ad:a': {Props.name: const StringValue('Pelican')},
    });
    addTearDown(backend.dispose); // ends pending waits, no timer outlives the test
    final store = Store(backend: backend);

    final expectation = expectLater(
      store.watch('did:ad:a').map((r) => r.name),
      emitsInOrder(['Pelican', 'Heron', emitsDone]),
    );
    await pumpEventQueue(); // let the first value and the wait start

    // A direct write to `resources` announces nothing: `touch` does.
    backend.resources['did:ad:a']![Props.name] = const StringValue('Heron');
    backend.touch('did:ad:a');
    await pumpEventQueue();

    backend.destroy('did:ad:a'); // someone else deletes it: the stream ends
    await expectation;
  });

  test('watchChildren emits the list, again when a child is added', () async {
    const drive = 'did:ad:drive';
    final backend = InMemoryBackend({
      drive: {Props.name: const StringValue('Home')},
    });
    addTearDown(backend.dispose);
    final store = Store(backend: backend, drive: drive);

    final expectation = expectLater(
      store.watchChildren(drive).map((l) => [for (final r in l) r.name]),
      emitsInOrder([
        <String?>[],
        ['Buy milk'],
      ]),
    );
    await pumpEventQueue();
    await store.newResource(props: {Props.name: 'Buy milk'}).save();
    await expectation;
  });
}
