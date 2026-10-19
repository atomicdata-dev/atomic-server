import 'dart:convert';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomiccanvas_flutter/screens/account_link_dialog.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('shows the code, then saves the session once approved',
      (tester) async {
    var polls = 0;
    final client = shared.AtomicAccountClient('https://portal.example',
        client: MockClient((request) async {
      if (request.method == 'POST' && request.url.path == '/api/device-link') {
        return http.Response(
            jsonEncode({
              'device_code': 'device-secret',
              'user_code': 'ABCD-1234',
              'interval': 1,
              'expires_in': 600,
            }),
            200);
      }
      polls++;
      return http.Response(
          polls < 2
              ? jsonEncode({'state': 'pending'})
              : jsonEncode({'state': 'approved', 'token': 'bearer-token'}),
          200);
    }));
    String? saved;
    bool? result;

    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (context) => TextButton(
          onPressed: () async => result = await showDialog<bool>(
            context: context,
            builder: (_) => AccountLinkDialog(
              client: client,
              deviceName: 'Phone',
              save: (session) async => saved = session,
            ),
          ),
          child: const Text('go'),
        ),
      ),
    ));
    await tester.tap(find.text('go'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.text('ABCD-1234'), findsOneWidget);
    expect(find.textContaining('portal.example/link'), findsOneWidget);
    expect(find.text('Waiting for approval…'), findsOneWidget);

    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(seconds: 1));
    await tester.pumpAndSettle();

    expect(result, isTrue);
    expect(jsonDecode(saved!)['token'], 'bearer-token');
    expect(jsonDecode(saved!)['origin'], 'https://portal.example');
  });

  testWidgets('a refused request says so and can be retried', (tester) async {
    final client = shared.AtomicAccountClient('https://portal.example',
        client: MockClient((_) async => http.Response('no', 500)));
    await tester.pumpWidget(MaterialApp(
      home: AccountLinkDialog(
        client: client,
        deviceName: 'Phone',
        save: (_) async {},
      ),
    ));
    await tester.pumpAndSettle();
    expect(find.textContaining('Account request failed'), findsOneWidget);
    expect(find.text('Try again'), findsOneWidget);
  });
}
