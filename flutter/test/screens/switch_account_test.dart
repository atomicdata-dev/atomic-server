import 'package:atomic_app/atomic/session.dart';
import 'package:atomic_app/atomic/switch_account.dart';
import 'package:atomic_app/screens/login_screen.dart';
import 'package:atomic_app/screens/sync_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:atomic_chat/atomic_chat.dart' show ToastController, ToastScope;
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:atomic_store_flutter/testing.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _Backend extends shared.AtomicSettingsBackend {
  @override
  Future<shared.AtomicIdentity?> getActiveAgent() async =>
      const shared.AtomicIdentity(subject: 'did:ad:agent', name: 'Joep');
  @override
  Future<String> exportSecret() async => 'secret';
  @override
  String? getActiveDrive() => 'did:ad:a';
  @override
  Future<List<String>> listDrives() async => ['did:ad:a'];
  @override
  Future<String> getDriveName(String drive) async => 'Private';
  @override
  Future<void> createDrive(String name) async {}
  @override
  Future<void> switchDrive(String drive) async {}
  @override
  Future<String?> getPeerId() async => 'a1b2c3d4e5f6a7b8c9d0e1f2';
  @override
  Future<String> getDeviceName() async => 'Pixel';
  @override
  Future<void> setDeviceName(String name) async {}
  @override
  Future<List<Map<String, String>>> getKnownPeers() async => [];
  @override
  Future<Set<String>> livePeerIds() async => {};
  @override
  Future<void> removeKnownPeer(String nodeId) async {}
  @override
  Future<void> pair(BuildContext context) async {}
  @override
  Future<void> Function()? get signOut => () async {};
}

const _entry = 'Sign in to another account';
const _brought = 'Your notes from before are in your account now.';

void main() {
  late Map<String, String> secure;
  late FakeIdentity identity;
  late ToastController toasts;
  late int loggedIn;

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    AtomicSession.resetForTest();
    secure = {};
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
            const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
            (call) async {
      final args = (call.arguments as Map).cast<String, Object?>();
      switch (call.method) {
        case 'write':
          secure['${args['key']}'] = '${args['value']}';
          return null;
        case 'read':
          return secure['${args['key']}'];
        default:
          return null;
      }
    });
    identity = FakeIdentity(Store(backend: InMemoryBackend()), secret: 'A')
      ..known['A'] = (drive: 'did:ad:a', needsSync: false)
      ..known['B'] = (drive: 'did:ad:b', needsSync: false);
    toasts = ToastController();
    loggedIn = 0;
  });

  tearDown(() => toasts.dispose());

  Future<void> open(WidgetTester tester) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(ToastScope(
      controller: toasts,
      child: MaterialApp(
        theme: ThemeData(extensions: const [AppColors.light]),
        home: SyncScreen(
          backend: _Backend(),
          loadAccount: (_) async => null,
          onSignedInAsOther: () => loggedIn++,
          signInPage: (onLoggedIn) => LoginScreen(
            switchAccount: true,
            onLoggedIn: onLoggedIn,
            switchAccountFn: (secret) async {
              final same = identity.secret == secret;
              final found = await identity.signIn(secret);
              return AccountSwitch(
                  same: same,
                  broughtAlong: found.broughtAlong,
                  previousSecret: found.previousSecret);
            },
            activate: (_, __, ___) async => true,
          ),
        ),
      ),
    ));
    await tester.pumpAndSettle();
  }

  Future<void> signInWith(WidgetTester tester, String secret) async {
    await tester.tap(find.text(_entry));
    await tester.pumpAndSettle();
    await tester.tap(find.text('I have a secret — Sign In'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('signin-secret')), secret);
    await tester.tap(find.text('Sign In'));
    await tester.pumpAndSettle();
  }

  testWidgets('the entry is next to Sign out while signed in', (tester) async {
    await open(tester);
    expect(find.text(_entry), findsOneWidget);
    expect(find.text('Sign out'), findsOneWidget);

    // It opens the login options, without making a new account.
    await tester.tap(find.text(_entry));
    await tester.pumpAndSettle();
    expect(find.text('I have a secret — Sign In'), findsOneWidget);
    expect(find.text('Sign in with atomic.place'), findsOneWidget);
    expect(find.text('Get Started'), findsNothing);
  });

  testWidgets(
      'signing in as another account brings the work along, says so and '
      'keeps the old secret', (tester) async {
    identity.work = ['did:ad:a', 'did:ad:shared'];
    await open(tester);
    await signInWith(tester, 'B');

    expect(toasts.toasts.map((t) => t.message), [_brought]);
    expect(identity.secret, 'B');
    expect(secure['atomic_previous_secrets'], '["A"]');
    expect(loggedIn, 1);
    // Back on the settings screen.
    expect(find.text(_entry), findsOneWidget);
  });

  testWidgets('an older secret is added to the list, never replaced',
      (tester) async {
    secure['atomic_previous_secrets'] = '["Z"]';
    await open(tester);
    await signInWith(tester, 'B');

    expect(secure['atomic_previous_secrets'], '["Z","A"]');
  });

  testWidgets('with nothing to bring there is no extra line', (tester) async {
    await open(tester);
    await signInWith(tester, 'B');

    expect(toasts.toasts, isEmpty);
    expect(identity.secret, 'B');
    expect(loggedIn, 1);
    // Still kept, so that account can be signed in as again.
    expect(secure['atomic_previous_secrets'], '["A"]');
  });

  testWidgets('signing in as the same account does nothing', (tester) async {
    identity.work = ['did:ad:a'];
    await open(tester);
    await signInWith(tester, 'A');

    expect(toasts.toasts, isEmpty);
    expect(loggedIn, 0);
    expect(secure.containsKey('atomic_previous_secrets'), isFalse);
    expect(identity.work, ['did:ad:a']);
    expect(find.text(_entry), findsOneWidget);
  });
}
