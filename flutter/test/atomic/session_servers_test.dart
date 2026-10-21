import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:atomic_app/atomic/session.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // AtomicSession.save() writes the agent secret through FlutterSecureStorage,
  // which has no test-time platform implementation — without this mock, the
  // real method channel call hangs on an uninitialized ServicesBinding.
  const secureStorageChannel = MethodChannel(
    'plugins.it_nomads.com/flutter_secure_storage',
  );

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(secureStorageChannel, (call) async => null);
  });

  group('known servers', () {
    test('a server typed any which way is remembered once', () async {
      await AtomicSession.addKnownServer('localhost:9883');
      await AtomicSession.addKnownServer('http://localhost:9883');
      await AtomicSession.addKnownServer('http://localhost:9883/');

      expect(await AtomicSession.knownServers(), ['http://localhost:9883']);
    });

    test('remembers in the order they were added — a list must not shuffle', () async {
      await AtomicSession.addKnownServer('localhost:9883');
      await AtomicSession.addKnownServer('my.server.com');
      await AtomicSession.addKnownServer('other.server.com');

      expect(await AtomicSession.knownServers(), [
        'http://localhost:9883',
        'https://my.server.com',
        'https://other.server.com',
      ]);
    });

    test('empty is not a server', () async {
      await AtomicSession.addKnownServer('');
      await AtomicSession.addKnownServer('   ');

      expect(await AtomicSession.knownServers(), isEmpty);
    });
  });

  group('active server', () {
    test('none by default — device-to-device is a valid setup', () async {
      expect(await AtomicSession.activeServer(), isNull);
    });

    test('switching normalizes and remembers', () async {
      await AtomicSession.setActiveServer('localhost:9883');

      expect(await AtomicSession.activeServer(), 'http://localhost:9883');
      expect(await AtomicSession.knownServers(), contains('http://localhost:9883'));
    });

    test('switching between known servers keeps them both', () async {
      await AtomicSession.setActiveServer('localhost:9883');
      await AtomicSession.setActiveServer('my.server.com');

      expect(await AtomicSession.activeServer(), 'https://my.server.com');
      expect(await AtomicSession.knownServers(), hasLength(2));
    });

    test('signing in remembers the server it signed in to', () async {
      await AtomicSession.save(serverUrl: 'localhost:9883', secret: 'abc');

      expect(await AtomicSession.knownServers(), ['http://localhost:9883']);
    });
  });

  group('removing', () {
    test('forgets the server', () async {
      await AtomicSession.setActiveServer('localhost:9883');
      await AtomicSession.addKnownServer('my.server.com');

      await AtomicSession.removeKnownServer('https://my.server.com');

      expect(await AtomicSession.knownServers(), ['http://localhost:9883']);
    });

    test('removing the active one leaves no server, not a dangling one', () async {
      await AtomicSession.setActiveServer('localhost:9883');

      await AtomicSession.removeKnownServer('localhost:9883');

      expect(await AtomicSession.knownServers(), isEmpty);
      expect(await AtomicSession.activeServer(), isNull);
    });

    test('removing an inactive one leaves the active one alone', () async {
      await AtomicSession.setActiveServer('localhost:9883');
      await AtomicSession.addKnownServer('my.server.com');

      await AtomicSession.removeKnownServer('my.server.com');

      expect(await AtomicSession.activeServer(), 'http://localhost:9883');
    });
  });
}
