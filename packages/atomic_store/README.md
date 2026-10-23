# atomic_store

A `Store` and `Resource` for Atomic Data in Dart that rhyme with
[`@tomic/lib`](../../browser/lib/src/store.ts): `getResource`, `search`,
`createDrive`, `newResource`, `watch`/`subscribe`; `resource.get`, `set`,
`save`, `isA`, `children`. Pure Dart, no Flutter and no native code: every
call goes through a `StoreBackend`. The atomic.place app implements it over its
Rust bridge (`BridgeStoreBackend` in
[`packages/atomic_store_flutter`](../atomic_store_flutter/README.md), which is
what a new Flutter app adds); tests use
`InMemoryBackend`.

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

## Search, children, watch

```dart
final hits = await store.search('pelican');   // in store.drive; drive: '' for all
final kids = await folder.children();         // sidebar order

final sub = store.subscribe(subject, (r) => print('now ${r.name}'));
// or: await for (final r in store.watch(subject)) { ... }  (ends on destroy)
await sub.cancel();
```

A watch emits the resource now and after every change, as the same
`Resource` instance reloaded. Local changes not yet saved are kept.

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

## Testing

```dart
import 'package:atomic_store/testing.dart';

final backend = InMemoryBackend({
  'did:ad:a': {Props.name: const StringValue('A')},
});
final store = Store(backend: backend);
backend.failNext = const StoreException(StoreErrorKind.network, 'offline');
backend.touch('did:ad:a'); // wakes watchers, as a remote edit would
```

## Implementing a backend

Implement `StoreBackend` (seven methods, see `lib/src/backend.dart`) and throw
`StoreException` only. In the Flutter app that is `BridgeStoreBackend`, over
the typed functions of `packages/atomic_store_flutter/rust/src/api/resources.rs`.

## Agent and drive

The `Store` takes its drive explicitly (`drive:`: default parent and search
scope). Who signs a write is the backend's. Over the bridge, open a handle
that owns the store, the signing agent and the drive:

```dart
final handle = await AtomicStore.open(
    path: dir, agentSecret: secret, drive: driveSubject);
final store = Store(backend: BridgeStoreBackend(handle), drive: driveSubject);
```

`BridgeStoreBackend()` without a handle uses the app's default store (`open_db`,
`load_agent`). Handles on the same path share one open database; see
`flutter/README.md`. A handle also has its own server session
(`handle.openWsSync(...)`), which its writes go out over; the Iroh peer stays
process-wide.
