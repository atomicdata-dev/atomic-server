// The widget test the atomic_store README shows: a StreamBuilder over
// Store.watchChildren, tested against InMemoryBackend.
import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

const drive = 'did:ad:test:drive';

class NotesList extends StatelessWidget {
  const NotesList(this.store, {super.key});
  final Store store;

  @override
  Widget build(BuildContext context) => StreamBuilder<List<Resource>>(
        stream: store.watchChildren(drive),
        builder: (context, snapshot) => Column(children: [
          for (final note in snapshot.data ?? const <Resource>[])
            Text(note.name ?? '(untitled)'),
        ]),
      );
}

void main() {
  testWidgets('a list of notes follows the store', (tester) async {
    final backend = InMemoryBackend({
      drive: {Props.name: const StringValue('Home')},
      'did:ad:test:1': {
        Props.name: const StringValue('Pelican'),
        Props.parent: const LinkValue(drive),
      },
    });
    final store = Store(backend: backend, drive: drive);

    await tester.pumpWidget(MaterialApp(home: Scaffold(body: NotesList(store))));
    // The store's futures need real async; testWidgets runs in fake async.
    await tester.runAsync(() => Future<void>.delayed(Duration.zero));
    await tester.pump();
    expect(find.text('Pelican'), findsOneWidget);

    await tester.runAsync(() async {
      final heron = store.newResource(props: {Props.name: 'Heron'});
      await heron.save(); // the backend announces it: no touch() needed
      await Future<void>.delayed(Duration.zero);
    });
    await tester.pump();
    expect(find.text('Heron'), findsOneWidget);

    await tester.pumpWidget(const SizedBox()); // cancels the watch
    backend.dispose(); // ends its pending wait, so no timer is left
    await tester.pump();
  });
}
