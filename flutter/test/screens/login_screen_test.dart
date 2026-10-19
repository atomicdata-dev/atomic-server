import 'package:atomic_app/screens/login_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

Widget _app() => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: LoginScreen(onLoggedIn: () {}),
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
}
