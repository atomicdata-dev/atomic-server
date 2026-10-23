import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

/// Open a local Atomic node, create a resource, set its name, save it, read
/// it back and watch it live. Edit the name and the watcher shows it at once.
///
/// Note: this example does not persist the agent secret, so every start is a
/// new identity in the same folder. A real app keeps `node.agentSecret` in
/// secure storage and passes it to `AtomicFlutter.open` next time.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AtomicFlutter.init(); // loads the Rust library, once
  final dir = await getApplicationSupportDirectory();
  final node = await AtomicFlutter.open(
    path: '${dir.path}/hello_atomic',
    agentName: 'Hello',
  );

  // Create a resource in the node's drive, give it a name, save it (one
  // signed commit), then read it back from the database.
  final note = node.store.newResource(
    isA: [Classes.folder],
    props: {Props.name: 'Hello Atomic'},
  );
  await note.save();
  final readBack = await node.store.getResource(note.subject);
  debugPrint('Saved ${readBack.subject} as "${readBack.name}"');

  runApp(HelloApp(store: node.store, subject: note.subject));
}

class HelloApp extends StatelessWidget {
  const HelloApp({super.key, required this.store, required this.subject});

  final Store store;
  final String subject;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Hello Atomic',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        home: Scaffold(
          appBar: AppBar(title: const Text('Hello Atomic')),
          body: Padding(
            padding: const EdgeInsets.all(16),
            // `watch` emits the resource now and after every change.
            child: StreamBuilder<Resource>(
              stream: store.watch(subject),
              builder: (context, snapshot) {
                final resource = snapshot.data;
                if (resource == null) return const CircularProgressIndicator();
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(resource.name ?? '(no name)',
                        style: Theme.of(context).textTheme.headlineMedium),
                    const SizedBox(height: 8),
                    SelectableText(subject),
                    const SizedBox(height: 16),
                    TextField(
                      decoration: const InputDecoration(labelText: 'Rename'),
                      onSubmitted: (value) async {
                        resource.set(Props.name, value);
                        await resource.save();
                      },
                    ),
                  ],
                );
              },
            ),
          ),
        ),
      );
}
