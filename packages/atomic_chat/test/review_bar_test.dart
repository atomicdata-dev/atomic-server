import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

Map<String, dynamic> _text(String t) => {
      'choices': [
        {
          'delta': {'content': t}
        }
      ]
    };

/// A bridge whose page holds [held]; keeping or undoing removes them.
class _ReviewBridge implements WebToolBridge, ReviewableBridge {
  _ReviewBridge(this.held);
  List<PendingChange> held;
  final decided = <String>[];

  @override
  Future<List<ToolDef>> listTools() async => const [];
  @override
  Future<String> systemPrompt() async => 'WEB PROMPT';
  @override
  Future<String> run(String name, Map<String, dynamic> args) async => '{}';

  @override
  Future<List<PendingChange>> pendingChanges() async => held;

  List<PendingChange> _drop(String verb, String? subject) {
    decided.add('$verb ${subject ?? 'all'}');
    held = [
      if (subject != null) ...held.where((c) => c.subject != subject),
    ];
    return held;
  }

  @override
  Future<List<PendingChange>> acceptChanges([String? subject]) async =>
      _drop('keep', subject);
  @override
  Future<List<PendingChange>> revertChanges([String? subject]) async =>
      _drop('undo', subject);
}

class _Api extends UnimplementedApi {
  _Api(this.ai);
  final HostedAi ai;
  @override
  Future<HostedAi?> hostedAi() async => ai;
  @override
  Future<List<ChatMessage>> messages(String chat) async => const [];
  @override
  Future<String> newChat(String name) async => 'did:ad:chat';
  @override
  Future<void> addMessage(String chat, String role, String text) async {}
  @override
  Future<void> addEntry(String chat, String role, List<ChatPart> parts) async {}
}

HostedAi _ai() => HostedAi(
      status: {'enabled': true, 'consent': true, 'model': 'm'},
      completions: (messages, model, tools) => Stream.value(_text('Done.')),
      enable: () async => {},
    );

const _two = [
  PendingChange(subject: 'did:ad:a', title: 'Plan', summary: 'Changed name'),
  PendingChange(subject: 'did:ad:b', title: 'Notes', summary: 'Changed text'),
];

Future<_ReviewBridge> _open(WidgetTester tester) async {
  final bridge = _ReviewBridge(List.of(_two));
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(extensions: [AppColors.light]),
    home: ChatScreen(api: _Api(_ai()), toolBridge: bridge),
  ));
  await tester.pumpAndSettle();
  // An answer ends: the screen asks the page what it holds.
  await tester.enterText(find.byType(TextField), 'Edit it');
  await tester.pump();
  await tester.tap(find.byTooltip('Send'));
  await tester.pumpAndSettle();
  return bridge;
}

void main() {
  testWidgets('no bar without pending changes', (tester) async {
    final bridge = _ReviewBridge([]);
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: [AppColors.light]),
      home: ChatScreen(api: _Api(_ai()), toolBridge: bridge),
    ));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Hi');
    await tester.pump();
    await tester.tap(find.byTooltip('Send'));
    await tester.pumpAndSettle();
    expect(find.textContaining('by AI'), findsNothing);
  });

  testWidgets('the bar counts the changes; the sheet keeps or undoes one',
      (tester) async {
    final bridge = await _open(tester);
    expect(find.text('2 changes by AI'), findsOneWidget);

    await tester.tap(find.text('Review'));
    await tester.pumpAndSettle();
    expect(find.text('Plan'), findsOneWidget);
    expect(find.text('Changed text'), findsOneWidget);

    await tester.tap(find.text('Keep').first);
    await tester.pumpAndSettle();
    expect(bridge.decided, ['keep did:ad:a']);
    expect(find.text('Plan'), findsNothing);
  });

  testWidgets('Undo all empties the list and closes the sheet', (tester) async {
    final bridge = await _open(tester);
    await tester.tap(find.text('Review'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Undo all'));
    await tester.pumpAndSettle();
    expect(bridge.decided, ['undo all']);
    expect(find.textContaining('by AI'), findsNothing);
    expect(find.text('Keep all'), findsNothing);
  });

  testWidgets('leaving with changes pending asks first', (tester) async {
    final bridge = await _open(tester);
    final navigator = tester.state<NavigatorState>(find.byType(Navigator));
    await navigator.maybePop();
    await tester.pumpAndSettle();
    expect(find.text('Keep all'), findsOneWidget);
    await tester.tap(find.text('Stay'));
    await tester.pumpAndSettle();
    expect(bridge.decided, isEmpty);
    expect(find.text('2 changes by AI'), findsOneWidget);
  });
}
