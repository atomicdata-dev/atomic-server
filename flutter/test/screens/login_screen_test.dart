import 'package:atomic_app/screens/login_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
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

  test('a secret that is not one gets a sentence, not a decoder error', () {
    expect(
        signInError(
            'Invalid key. Not valid Base64. Invalid last symbol 116, offset 9.'),
        startsWith('That is not a secret.'));
    expect(signInError(StateError('No connection')), 'No connection');
  });
}
