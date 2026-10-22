import 'dart:io';

import 'package:atomic_app/atomic/store_location.dart';
import 'package:atomic_app/screens/store_recovery_screen.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory root;
  late String docs, support;
  setUp(() {
    root = Directory.systemTemp.createTempSync('store_loc');
    docs = '${root.path}/Documents';
    support = '${root.path}/Support';
    Directory(docs).createSync();
  });
  tearDown(() => root.deleteSync(recursive: true));

  Future<String> resolve(bool desktop) => resolveStoreDirectory(
      desktop: desktop,
      documents: () async => docs,
      support: () async => support);

  test('mobile keeps the documents directory and touches nothing', () async {
    File('$docs/atomic.redb').writeAsStringSync('x');
    expect(await resolve(false), docs);
    expect(Directory(support).existsSync(), isFalse);
  });

  test('desktop uses support, copies the legacy store, keeps the old', () async {
    File('$docs/atomic.redb').writeAsStringSync('data');
    Directory('$docs/uploads').createSync();
    File('$docs/uploads/a').writeAsStringSync('u');
    File('$docs/other.txt').writeAsStringSync('mine');
    expect(await resolve(true), support);
    expect(File('$support/atomic.redb').readAsStringSync(), 'data');
    expect(File('$support/uploads/a').readAsStringSync(), 'u');
    expect(File('$support/other.txt').existsSync(), isFalse);
    expect(File('$docs/atomic.redb').existsSync(), isTrue);
    expect(File('$support/atomic.redb.migrating').existsSync(), isFalse);
  });

  test('an existing support store is never overwritten', () async {
    File('$docs/atomic.redb').writeAsStringSync('old');
    Directory(support).createSync();
    File('$support/atomic.redb').writeAsStringSync('new');
    await resolve(true);
    expect(File('$support/atomic.redb').readAsStringSync(), 'new');
  });

  test('no legacy store is fine', () async {
    expect(await resolve(true), support);
    expect(File('$support/atomic.redb').existsSync(), isFalse);
  });

  test('advice differs for a denied write and a full disk', () {
    expect(
        storeErrorAdvice('I/O error: Operation not permitted (os error 1)'),
        contains("isn't allowed to write"));
    expect(storeErrorAdvice('Permission denied'), contains("isn't allowed"));
    expect(storeErrorAdvice('No space left on device'),
        contains('out of storage'));
  });
}
