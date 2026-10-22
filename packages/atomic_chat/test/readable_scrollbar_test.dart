import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

class _Api extends UnimplementedApi {
  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String s) async => [
        for (var i = 0; i < 60; i++)
          (
            id: 'm$i',
            kind: ChatRoomKind.text,
            author: 'did:ad:agent:a',
            authorName: 'Alice',
            mine: false,
            text: 'Message number $i',
            createdAt: 1700000000000 + i * 1000,
            about: null,
            aboutTitle: '',
          ),
      ];
}

Future<void> _open(WidgetTester tester, double width) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = Size(width, 900);
  await tester.pumpWidget(MaterialApp(
    theme: ThemeData(extensions: const [AppColors.light]),
    home: ChatRoomScreen(
        api: _Api(),
        drive: 'did:ad:drive',
        subject: 'did:ad:room',
        title: 'Standup'),
  ));
  await tester.pumpAndSettle();
}

void main() {
  for (final width in [1400.0, 1000.0]) {
    testWidgets('chat at $width: scrollbar at the pane edge, content centred',
        (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      try {
        await _open(tester, width);
        final bar = find.byType(Scrollbar).first;
        expect(tester.getRect(bar).right, width);
        expect(tester.getRect(bar).left, 0);
        final row = tester.getRect(find.text('Message number 59'));
        expect(row.left, greaterThan((width - 720) / 2));
        expect(row.right, lessThanOrEqualTo((width + 720) / 2));
        // Centred column: the margins of the column are equal.
        final composer = tester.getRect(find.byType(TextField));
        expect(composer.left, greaterThanOrEqualTo((width - 720) / 2));
        expect(composer.width, lessThanOrEqualTo(720));

        // The wheel over the empty side margin scrolls the list.
        final scrollable = tester.state<ScrollableState>(find
            .descendant(
                of: find.byType(ListView), matching: find.byType(Scrollable))
            .first);
        final before = scrollable.position.pixels;
        final mouse = TestPointer(1, PointerDeviceKind.mouse);
        await tester.sendEventToBinding(mouse.hover(const Offset(40, 400)));
        await tester.sendEventToBinding(mouse.scroll(const Offset(0, -300)));
        await tester.pump();
        expect(scrollable.position.pixels, isNot(before));
      } finally {
        debugDefaultTargetPlatformOverride = null;
        tester.view.reset();
      }
    });
  }

  testWidgets('chat on a phone: full width minus gutters', (tester) async {
    await _open(tester, 400);
    final row = tester.getRect(find.text('Message number 59'));
    expect(row.left, lessThan(80));
    final bar = find.byType(Scrollbar);
    if (bar.evaluate().isNotEmpty) {
      expect(tester.getRect(bar.first).right, 400);
    }
    tester.view.reset();
  });
}
