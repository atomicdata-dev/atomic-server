import 'dart:convert';

import 'package:atomic_app/screens/login_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';

typedef AccountSignIn = Future<shared.AtomicRecoveredIdentity?> Function(
    BuildContext);

Widget _app({AccountSignIn? accountSignIn}) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: LoginScreen(onLoggedIn: () {}, accountSignIn: accountSignIn),
    );

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
            const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
            (call) async => null);
  });

  testWidgets('the welcome screen shows the wordmark, not the brush icon',
      (tester) async {
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('atomic-wordmark')), findsOneWidget);
    expect(find.byIcon(Icons.brush), findsNothing);
    expect(tester.getSize(find.byKey(const Key('atomic-wordmark'))).height, 40);
  });

  testWidgets('the secret field is autofill-friendly', (tester) async {
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    await tester.tap(find.text('I have a secret — Sign In'));
    await tester.pumpAndSettle();

    expect(find.byType(AutofillGroup), findsOneWidget);
    final secret =
        tester.widget<TextField>(find.byKey(const ValueKey('signin-secret')));
    expect(secret.autofillHints, [AutofillHints.password]);
    expect(secret.obscureText, isTrue);
    expect(secret.enableSuggestions, isFalse);
    expect(secret.autocorrect, isFalse);
    final user =
        tester.widget<TextField>(find.byKey(const ValueKey('signin-username')));
    expect(user.autofillHints, [AutofillHints.username]);

    // The reveal toggle still works.
    await tester.tap(find.byTooltip('Show'));
    await tester.pump();
    expect(
        tester
            .widget<TextField>(find.byKey(const ValueKey('signin-secret')))
            .obscureText,
        isFalse);
  });

  testWidgets('system back on the sign-in step goes to the welcome screen',
      (tester) async {
    await tester.pumpWidget(_app());
    await tester.pumpAndSettle();
    await tester.tap(find.text('I have a secret — Sign In'));
    await tester.pumpAndSettle();
    expect(find.text('Get Started'), findsNothing);
    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    expect(find.text('Get Started'), findsOneWidget);
  });

  testWidgets('Sign in with atomic.place runs the account flow',
      (tester) async {
    var calls = 0;
    await tester.pumpWidget(_app(accountSignIn: (_) async {
      calls++;
      return null; // cancelled
    }));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign in with atomic.place'));
    await tester.pumpAndSettle();
    expect(calls, 1);
    // Cancelling leaves the welcome screen as it was.
    expect(find.text('Get Started'), findsOneWidget);
  });

  testWidgets('an account failure is shown, not swallowed', (tester) async {
    await tester.pumpWidget(_app(
        accountSignIn: (_) async => throw StateError(
            'Finish setting up your workspace in the browser first')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign in with atomic.place'));
    await tester.pumpAndSettle();
    expect(find.text('Finish setting up your workspace in the browser first'),
        findsOneWidget);
  });

  testWidgets('a backup the app cannot open leads to the secret field',
      (tester) async {
    await tester.pumpWidget(_app(
        accountSignIn: (_) async =>
            throw const shared.AtomicNoAssistedRecovery()));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign in with atomic.place'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Paste your Atomic secret'), findsOneWidget);
    expect(find.byType(TextField), findsWidgets);
    expect(find.text('Get Started'), findsNothing);
  });

  testWidgets(
      'Sign in with atomic.place opens the send-identity page and signs in '
      'with the identity the browser sealed to the app', (tester) async {
    final seed = Uint8List.fromList(List.filled(32, 5));
    final pub = ed.public(ed.newKeyFromSeed(seed)).bytes;
    String b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');
    final subject = 'did:ad:agent:${b64u(pub)}';
    final secret = base64.encode(utf8
        .encode(jsonEncode({'privateKey': b64u(seed), 'subject': subject})));
    final stored = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
            const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
            (call) async {
      if (call.method == 'write') stored.add('${call.arguments}');
      return null;
    });

    String? appKey;
    var recovered = false;
    final client = shared.AtomicAccountClient('https://atomic.place',
        client: MockClient((request) async {
      switch (request.url.path) {
        case '/api/device-link':
          appKey = (jsonDecode(request.body) as Map)['app_key'] as String?;
          return http.Response(
              jsonEncode({
                'device_code': 'dc',
                'user_code': 'ABCD-1234',
                'expires_in': 600,
                'interval': 1,
              }),
              200);
        case '/api/device-link/dc':
          return http.Response(
              jsonEncode({
                'state': 'approved',
                'token': 'bearer',
                'sealed_identity': await shared.AtomicIdentityHandback.seal(
                    appKey!,
                    {'secret': secret, 'subject': subject, 'drive': null}),
              }),
              200);
        case '/api/me':
          return http.Response('{"email":"e","address":"me@example"}', 200);
        default:
          recovered = request.url.path == '/api/recovery-secret';
          return http.Response('no', 404);
      }
    }));
    final opened = <Uri>[];

    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: LoginScreen(
          onLoggedIn: () {},
          accountClient: () => client,
          openBrowser: (url) async => opened.add(url)),
    ));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign in with atomic.place'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('ABCD-1234'), findsOneWidget);
    expect(find.textContaining('shows this code'), findsOneWidget);

    await tester.tap(find.text('Open in your browser'));
    expect(opened.single.toString(),
        'https://app.atomic.place/app/send-identity?code=ABCD-1234');

    await tester.pump(const Duration(seconds: 3));
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(seconds: 1));

    // The sealed secret is what the app stored; the backup was not asked for.
    expect(stored.any((w) => w.contains(secret)), isTrue);
    expect(recovered, isFalse);
  });

  testWidgets(
      'an older portal without a sealed identity falls back to the '
      'assisted backup', (tester) async {
    var recoveryAsked = false;
    final client = shared.AtomicAccountClient('https://atomic.place',
        client: MockClient((request) async {
      switch (request.url.path) {
        case '/api/device-link':
          return http.Response(
              jsonEncode({
                'device_code': 'dc',
                'user_code': 'ABCD-1234',
                'expires_in': 600,
                'interval': 1,
              }),
              200);
        case '/api/device-link/dc':
          return http.Response('{"state":"approved","token":"bearer"}', 200);
        case '/api/me':
          return http.Response('{"email":"e"}', 200);
        case '/api/recovery-secret':
          recoveryAsked = true;
          return http.Response('', 204);
        default:
          return http.Response('no', 404);
      }
    }));
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: LoginScreen(
          onLoggedIn: () {},
          accountClient: () => client,
          openBrowser: (_) async {}),
    ));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sign in with atomic.place'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pump(const Duration(seconds: 3));
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(seconds: 1));

    expect(recoveryAsked, isTrue);
    // No assisted wrapper: the paste field is the way on.
    expect(find.textContaining('Paste your Atomic secret'), findsOneWidget);
  });

  test('a secret that is not one gets a sentence, not a decoder error', () {
    expect(
        signInError(
            'Invalid key. Not valid Base64. Invalid last symbol 116, offset 9.'),
        startsWith('That is not a secret.'));
    expect(signInError(StateError('No connection')), 'No connection');
  });
}
