import 'package:atomic_app/atomic/session.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

/// Secure storage as a map, with failures to order: how a Keychain or an
/// Android keystore misbehaves.
class _FakeSecureStorage {
  final Map<String, String> values = {};
  int readFailures = 0;
  int writeFailures = 0;

  /// Writes fail until everything is deleted (an Android keyset that a backup
  /// restore made unreadable).
  bool brokenUntilDeleteAll = false;
  final List<String> calls = [];

  Future<Object?> handle(MethodCall call) async {
    calls.add(call.method);
    final args = (call.arguments as Map?) ?? const {};
    final key = args['key'] as String?;
    switch (call.method) {
      case 'read':
        if (readFailures > 0) {
          readFailures--;
          throw PlatformException(code: 'Exception', message: 'keystore');
        }
        return values[key];
      case 'write':
        if (brokenUntilDeleteAll || writeFailures > 0) {
          if (writeFailures > 0) writeFailures--;
          throw PlatformException(
              code: 'Exception', message: 'AEADBadTagException');
        }
        values[key!] = args['value'] as String;
        return null;
      case 'delete':
        values.remove(key);
        return null;
      case 'deleteAll':
        values.clear();
        brokenUntilDeleteAll = false;
        return null;
    }
    return null;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _FakeSecureStorage storage;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    AtomicSession.resetForTest();
    AtomicSession.readRetryDelay = Duration.zero;
    storage = _FakeSecureStorage();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, storage.handle);
  });

  test('nobody signed in: no session and no problem', () async {
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, isNull);
  });

  test('a saved session loads', () async {
    await AtomicSession.save(serverUrl: '', secret: 'test-secret');
    AtomicSession.resetForTest();
    final session = await AtomicSession.load();
    expect(session?.secret, 'test-secret');
    expect(AtomicSession.lastLoadProblem, isNull);
  });

  test('an unreadable Keychain on a device never signed in is the welcome',
      () async {
    storage.readFailures = 2;
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, isNull);
  });

  test('a read that fails once at launch is tried again', () async {
    await AtomicSession.save(serverUrl: '', secret: 'test-secret');
    AtomicSession.resetForTest();
    storage.readFailures = 1;
    expect((await AtomicSession.load())?.secret, 'test-secret');
  });

  test('an unreadable keystore asks for the secret, it does not sign out',
      () async {
    await AtomicSession.save(serverUrl: '', secret: 'test-secret');
    AtomicSession.resetForTest();
    storage.readFailures = 2;
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, SecretProblem.unreadable);
    expect(secretProblemMessage(SecretProblem.unreadable),
        contains('Paste your secret'));
    // Nothing was deleted on the way.
    expect(storage.values, isNotEmpty);
    expect(storage.calls, isNot(contains('delete')));
  });

  test('a secret gone after a backup restore is "missing", with a reason',
      () async {
    await AtomicSession.save(serverUrl: '', secret: 'test-secret');
    AtomicSession.resetForTest();
    storage.values.clear(); // the keystore key did not travel
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, SecretProblem.missing);
    expect(secretProblemMessage(SecretProblem.missing),
        contains('restoring a backup'));
  });

  test('a write that is refused once is repaired by deleting the old entry',
      () async {
    storage.writeFailures = 1;
    expect(
        await AtomicSession.save(serverUrl: '', secret: 'test-secret'), isTrue);
    expect(storage.values.values, contains('test-secret'));
    expect(AtomicSession.lastSaveWarning, isNull);
  });

  test('a keyset broken by a restore is reset, and the secret then saves',
      () async {
    storage.brokenUntilDeleteAll = true;
    expect(
        await AtomicSession.save(serverUrl: '', secret: 'test-secret'), isTrue);
    expect(storage.calls, contains('deleteAll'));
    AtomicSession.resetForTest();
    expect((await AtomicSession.load())?.secret, 'test-secret');
  });

  test('a secret that could not be saved says so at the next start', () async {
    storage.writeFailures = 99;
    expect(await AtomicSession.save(serverUrl: '', secret: 'test-secret'),
        isFalse);
    AtomicSession.resetForTest(); // the next start: memory is gone
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, SecretProblem.notSaved);
  });

  test('a Keychain entry that outlived a reinstall signs in, with no server',
      () async {
    storage.values['atomic_agent_secret'] = 'test-secret';
    final session = await AtomicSession.load();
    expect(session?.secret, 'test-secret');
    expect(session?.serverUrl, '');
  });

  test('signing out clears the problem and the flag', () async {
    storage.writeFailures = 99;
    await AtomicSession.save(serverUrl: '', secret: 'test-secret');
    await AtomicSession.clear();
    AtomicSession.resetForTest();
    expect(await AtomicSession.load(), isNull);
    expect(AtomicSession.lastLoadProblem, isNull);
  });
}
