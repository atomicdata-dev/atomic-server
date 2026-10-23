# atomic_store

A `Store` and `Resource` for Atomic Data in Dart that rhyme with
[`@tomic/lib`](../../browser/lib/src/store.ts): `getResource`, `search`,
`createDrive`, `newResource`, `watch`/`subscribe`; `resource.get`, `set`,
`save`, `isA`, `children`. Pure Dart, no Flutter and no native code: every
call goes through a `StoreBackend`.

**In a Flutter app, start with
[`AtomicFlutter.open`](../atomic_store_flutter/README.md)** from
`package:atomic_store_flutter`: it opens a local node (database, signing agent,
drive) and gives you a `Store` on it, over `BridgeStoreBackend`. Tests use
`InMemoryBackend`. You only implement `StoreBackend` yourself for a new kind of
storage.

## Read, change, save

```dart
import 'package:atomic_store/atomic_store.dart';

final store = Store(backend: backend, drive: driveSubject);

final doc = await store.getResource(subject); // same subject, same instance
print(doc.name);                              // Props.name
print(doc.isA(Classes.documentV2));

doc.set(Props.name, 'New title');             // local until save()
doc.remove(Props.description);
await doc.save();                             // one signed commit
```

`set` reads plain Dart values (`String`, `int`, `double`, `bool`, `DateTime`,
`List` of subjects, `Map`) or a `Value` for more control:
`MarkdownValue`, `LinkValue(subject)`, `TimestampValue`, `LocalizedValue`, ...
`get` returns the typed `Value`; `getString`, `getLink` and `getLinks` are
shortcuts.

> **A `List<String>` becomes links.** In `Value.of` (so in `set`) every string
> in a list is a subject: `set(prop, ['a', 'b'])` stores two links, not two
> texts. Arrays in Atomic Data hold links and nested resources only. For a list
> of plain strings store one `JsonValue('["a","b"]')`, or one resource per item.

## Create

```dart
final folder = store.newResource(
  isA: [Classes.folder],
  props: {Props.name: 'Notes'},   // parent defaults to the store's drive
);
await folder.save();              // creates it and gives it a subject
print(folder.subject);
```

There is no `createSubject`: a resource's subject is a DID derived from the
signed first commit, so a draft has none until `save()` (`folder.subject`
throws `StateError` before; check `isNew`).

```dart
final drive = await store.createDrive('Work');
```

## Delete

```dart
await note.destroy();   // a signed destroy commit; children are destroyed too
note.isDestroyed;       // true
```

Mirrors `Resource.destroy()` of `@tomic/lib`. The store forgets the resource,
`watch` streams of it end, and `watchChildren` lists of its parent drop it.
Destroying something already gone throws `notFound`; a never-saved draft is
just discarded.

## Search, children, watch

```dart
final hits = await store.search('pelican');   // in store.drive; drive: '' for all
final kids = await folder.children();         // sidebar order, loaded once

final sub = store.subscribe(subject, (r) => print('now ${r.name}'));
// or: await for (final r in store.watch(subject)) { ... }  (ends on destroy)
await sub.cancel();

// A live list: the children of a parent, again whenever they change.
store.watchChildren(folder.subject).listen((List<Resource> notes) { ... });
```

**`watch(subject)`** emits the resource **now** (read fresh), then once per
change of that subject, as the same `Resource` instance reloaded; local unsaved
changes are kept. It ends (stream done) when the resource is destroyed, and
errors (stream error event) if the first read fails, for example `notFound`.

**`watchChildren(parent)`** emits the **current list** of children first (in
`childSubjects` order, loaded `Resource`s, those the store cannot read left
out), then the full list again when:

- a child is **added** (created or synced in),
- a child is **removed** (destroyed, also by a cascade),
- a child is **reparented** to or from `parent`,
- a child's **properties change**.

It ends when `parent` is destroyed. Nothing is emitted for changes elsewhere.

What the backends emit, exactly. A backend reports two events per resource,
`changed` and `destroyed` (`ResourceEventKind`), through `waitForEvent(subject)`
and, for any resource, `waitForStoreEvent`:

| Happens | Event |
| --- | --- |
| A resource is created (`save()` of a draft, `createDrive`), or arrives by sync | `changed` for its subject |
| `save()` of changes, a synced edit | `changed` for that subject |
| `destroy()`, a synced destroy, and each descendant of a destroyed resource | `destroyed` for each subject |
| Nothing for the whole wait | `timeout` |

The real backend (`BridgeStoreBackend`) takes these from the Rust node's event
stream, so local and synced writes alike are seen. `InMemoryBackend` emits the
same events from `createResource`, `createDrive`, `saveChanges` and
`destroyResource`; you only call `touch(subject)` / `destroy(subject)` to
simulate someone else's edit.

`watchChildren` re-reads the child list after each event; a change of a child
is recognised by the event's subject being one of the children. Events that
land between two waits are not replayed, so the list is also re-read after
every quiet `timeout` and emitted if it changed.

**The 60 s timeout.** Both `watch` and `watchChildren` take
`timeout:` (default 60 seconds), the longest one wait for an event lasts. A
timeout is not an error and ends nothing: the stream just waits again, so a
quiet watch stays open until you cancel it. Lower it in tests to see the loop
turn over.

## Errors

Every failure is a `StoreException` with a `kind` to switch on: `notFound`,
`unauthorized`, `network`, `invalid`, `storage`, `other`.

```dart
try {
  await store.getResource(subject);
} on StoreException catch (e) {
  if (e.kind == StoreErrorKind.notFound) { /* not synced to this device yet */ }
}
```

## Search semantics

`store.search(query)` returns `SearchResult`s (`subject`, `title`, `className`,
`drive`, `score`), best first, in `store.drive` unless you pass `drive:`
(`drive: ''` searches every drive of the local store).

**Real backend** (the `atomic_lib` full-text index, local, no network):

- Indexed: the **title** (`name`, else `shortname`, else `filename`), the
  **`description`**, and the **body text** of rich-text documents
  (`DocumentV2`). Other properties and links are not indexed.
- The query is split into words and **all** words must match (AND). Matching
  is case-insensitive; the last word matches as a **prefix** (type-ahead:
  `peli` finds Pelican), and words of three or more letters also tolerate one
  typo (`avacado` finds `avocado`). One or two letters search titles only.
- Ranked by relevance (BM25); a title hit beats a body hit, and the person's
  own resources come before built-in ontology classes and properties.
- A write is searchable once its commit is applied locally.

**`InMemoryBackend` differs on purpose:** it matches `name` and `description`
only, as a case-insensitive **substring** of the whole query, all scored 1. No
prefix-per-word, typos, ranking or document bodies. Use it to test your code
path, not your relevance.

## Testing

```dart
import 'package:atomic_store/testing.dart';

final backend = InMemoryBackend({
  'did:ad:a': {Props.name: const StringValue('A')},
});
final store = Store(backend: backend);
backend.failNext = const StoreException(StoreErrorKind.network, 'offline');
backend.touch('did:ad:a');   // simulate someone else's edit: wakes watchers
backend.destroy('did:ad:a'); // simulate someone else's delete (and children)
backend.dispose();           // end pending waits at the end of a test
```

`backend.resources` is the data, `backend.calls` the calls made. Writes
through the `Store` (`save`, `destroy`) emit their events themselves.

### Widget test

`testWidgets` runs in fake async, which the store's futures and the watch
timers do not mix with. Do anything that awaits the store inside
`tester.runAsync`, then `pump`. Dispose the backend at the end, or the watch's
60 s timer is reported as still pending. (This test is
`packages/atomic_store_flutter/test/widget_example_test.dart`.)

```dart
class NotesList extends StatelessWidget {
  const NotesList(this.store, {super.key});
  final Store store;

  @override
  Widget build(BuildContext context) => StreamBuilder<List<Resource>>(
        stream: store.watchChildren(store.drive!),
        builder: (context, snapshot) => Column(children: [
          for (final note in snapshot.data ?? const <Resource>[])
            Text(note.name ?? '(untitled)'),
        ]),
      );
}

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
  await tester.runAsync(() => Future<void>.delayed(Duration.zero));
  await tester.pump();
  expect(find.text('Pelican'), findsOneWidget);

  await tester.runAsync(() async {
    await store.newResource(props: {Props.name: 'Heron'}).save();
    await Future<void>.delayed(Duration.zero);
  });
  await tester.pump();
  expect(find.text('Heron'), findsOneWidget);

  await tester.pumpWidget(const SizedBox()); // cancels the watch
  backend.dispose();
  await tester.pump();
});
```

## Model your own data

Everything is a resource: a map of property URL to typed value, with a class
(`isA`) and a `parent` it lives under. A notebook with notes and tasks:

```dart
// A folder holds things (Classes.folder); its parent is the drive.
final notebook = store.newResource(
  isA: [Classes.folder],
  props: {Props.name: 'Trip planning'},        // parent: the store's drive
);
await notebook.save();

// A note: a DocumentV2 (the page type of the app) with a plain summary.
final note = store.newResource(
  parent: notebook.subject,
  isA: [Classes.documentV2],
  props: {
    Props.name: 'Packing list',
    Props.description: const MarkdownValue('What to bring, **short**.'),
  },
);
await note.save();

// A task: your own class and properties are just URLs you own.
const task = 'https://example.com/classes/Task';
const done = 'https://example.com/properties/done';
const dueAt = 'https://example.com/properties/dueAt';

final todo = store.newResource(
  parent: notebook.subject,
  isA: [task],
  props: {
    Props.name: 'Book flights',
    done: false,                               // BooleanValue
    dueAt: const TimestampValue(1798761600000),
  },
);
await todo.save();

todo.set(done, true);
await todo.save();

store.watchChildren(notebook.subject).listen((items) {
  for (final item in items) {
    print('${item.name} done=${item.get(done)}');
  }
});
```

Which ones to use:

| Need | Use |
| --- | --- |
| Group things | `Classes.folder`, with `Props.name`; things point at it with `Props.parent` |
| A page of rich text | `Classes.documentV2` |
| A top-level space | `Classes.drive` (`store.createDrive`) |
| Name, short text | `Props.name`; `Props.description` for plain/Markdown text |
| Uploaded file | `Classes.file` with `Props.filename`, `Props.mimetype`, `Props.downloadUrl` (the bridge has no upload call in the typed API) |
| Chat | `Classes.chatRoom`, `Classes.message` |
| Anything else | your own class and property URLs |

All constants are in `lib/src/urls.dart`, taken from the Atomic ontology
(`lib/src/urls.rs`); there is no `Classes.document` (that is the old Document
class; new documents are `DocumentV2`) and no ready-made Task or Note class.

**Custom properties and classes.** `set(url, value)` with any URL key just
writes that property with the datatype of the `Value` you pass (`String` ->
string, `bool` -> boolean, `int` -> integer, `double` -> float, `DateTime` or
`TimestampValue` -> timestamp, `LinkValue` -> link, `MarkdownValue`, ...).
The property **does not have to exist**: the local store does not look it up
or check it, and reading it back gives the same typed value. The same holds
for a class URL in `isA`. Two consequences: you get no validation (a typo in
the URL is a new property), and other apps that do not know the property may
not know how to label it. To have it described (label, datatype, "required") publish
a `Property` / `Class` resource at that URL; this is optional and not done by
this package. Use URLs under a domain you control, and keep them as constants.
Whether a given Atomic Server accepts unknown properties from a synced commit
is that server's validation; not tested here.

**`DocumentV2` versus a plain description.** A `DocumentV2` is the app's
rich-text page: its content (paragraphs, headings, lists, live-edited by
several people) lives in the resource's Loro CRDT document, under
`Props.documentContent`, not as a string property. `Store` does not read or
write it: `doc.get(Props.documentContent)` is not the text, and `set` cannot
edit it. The document's text is indexed for search. Properties like `name` and
`description` on the same resource are ordinary values you can read and set.
So: use `Props.description` (or your own string/markdown property) for small
text your app owns, and `DocumentV2` when you want a page that the atomic.place
app opens and edits as rich text.

## Implementing a backend

Implement `StoreBackend` (nine methods, see `lib/src/backend.dart`) and throw
`StoreException` only. In the Flutter app that is `BridgeStoreBackend`, over
the typed functions of `packages/atomic_store_flutter/rust/src/api/resources.rs`.

## Agent and drive

The `Store` takes its drive explicitly (`drive:`: default parent and search
scope). Who signs a write is the backend's. Without `AtomicFlutter.open`, over
the bridge, open a handle that owns the store, the signing agent and the
drive:

```dart
final handle = await AtomicStore.open(
    path: dir, agentSecret: secret, drive: driveSubject);
final store = Store(backend: BridgeStoreBackend(handle), drive: driveSubject);
```

`BridgeStoreBackend()` without a handle uses the app's default store (`open_db`,
`load_agent`). Handles on the same path share one open database (each with its
own agent and drive). A handle also has its own server session
(`handle.openWsSync(...)`), which its writes go out over; the Iroh peer stays
process-wide. `AtomicFlutter.open` does all of this for you; see
[`atomic_store_flutter`](../atomic_store_flutter/README.md) for identity, drives
and sync.
