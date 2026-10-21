import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The cursor the mouse shows after hovering [at].
Future<MouseCursor> cursorAt(WidgetTester tester, Offset at) async {
  final mouse =
      await tester.createGesture(kind: PointerDeviceKind.mouse, pointer: 1);
  await mouse.addPointer(location: const Offset(1, 1));
  await tester.pump();
  await mouse.moveTo(at);
  await tester.pump();
  final cursor = tester.binding.mouseTracker.debugDeviceActiveCursor(1)!;
  await mouse.removePointer();
  await tester.pump();
  return cursor;
}

Future<MouseCursor> cursorOver(WidgetTester tester, Finder f) =>
    cursorAt(tester, tester.getCenter(f.first));

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('a markdown link points', (tester) async {
    await tester.pumpWidget(app(Scaffold(
      body: MarkdownView('Open [the doc](did:ad:doc1)', onLink: (_) {}),
    )));
    final para = tester.renderObject<RenderParagraph>(find.byType(RichText));
    Offset on(int a, int b) {
      final box = para
          .getBoxesForSelection(TextSelection(baseOffset: a, extentOffset: b))
          .first;
      return para.localToGlobal(box.toRect().center);
    }

    // "Open the doc": the link is "the doc".
    expect(await cursorAt(tester, on(6, 9)), SystemMouseCursors.click);
    expect(await cursorAt(tester, on(0, 3)), isNot(SystemMouseCursors.click));
  });

  testWidgets('the toast action points', (tester) async {
    final c = ToastController();
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(
        body: ToastHost(controller: c, child: const SizedBox.expand()),
      ),
    ));
    c.show('sync:error', 'Sync timed out', actionLabel: 'Retry');
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
    expect(
        await cursorOver(tester, find.text('Retry')), SystemMouseCursors.click);
  });

  testWidgets('section headings and the bottom bar buttons point',
      (tester) async {
    tester.view.physicalSize = const Size(400, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final api = FakeApi(favoriteList: [
      (
        subject: 'did:ad:doc',
        title: 'Plain doc',
        className: 'document-v2',
        openedAt: 0,
        emoji: null,
        picture: null
      )
    ]);
    await tester.pumpWidget(app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    )));
    await tester.pumpAndSettle();
    expect(
        await cursorOver(
            tester, find.byKey(const ValueKey('section-heading-favorites'))),
        SystemMouseCursors.click);
    expect(await cursorOver(tester, find.byIcon(Icons.search).first),
        SystemMouseCursors.click);
    expect(await cursorOver(tester, find.text('Plain doc')),
        SystemMouseCursors.click);
  });
}
