import 'package:atomic_app/atomic/session.dart';
import 'package:atomic_app/screens/login_screen.dart' show signInError;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

PlatformException _missingEntitlement() => PlatformException(
      code: 'Unexpected security result code',
      message: 'Code: -34018, Message: A required entitlement isn\'t present.',
      details: -34018,
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    AtomicSession.resetForTest();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (call) async {
      throw _missingEntitlement();
    });
  });

  test('save still succeeds for this run when the Keychain refuses', () async {
    final stored = await AtomicSession.save(
        serverUrl: 'https://atomic.place', secret: 'abc', drive: null);

    expect(stored, isFalse);
    expect(AtomicSession.lastSaveWarning, 'Couldn’t access the Keychain');
    final session = await AtomicSession.load();
    expect(session?.secret, 'abc');
  });

  test('an unreadable Keychain at startup is "nothing saved", not a crash',
      () async {
    expect(await AtomicSession.load(), isNull);
  });

  test('clear does not throw when the Keychain refuses', () async {
    await AtomicSession.clear();
  });

  test('keychain errors read as sentences', () {
    expect(keychainErrorMessage(_missingEntitlement()),
        'Couldn’t access the Keychain');
    expect(signInError(_missingEntitlement()),
        'Couldn’t access the Keychain');
    expect(keychainErrorMessage(PlatformException(code: 'x')),
        'Couldn’t access secure storage');
  });
}
