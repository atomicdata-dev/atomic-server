import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'unimplemented_api.dart';

class _Api extends UnimplementedApi {
  const _Api();
  @override
  void noteOpened(String drive, String subject) {}
}

/// A page that behaves like the platform view: it wins the gesture arena at
/// once (so the route's own drag never sees a touch) and counts the pointer
/// events it gets.
class _WebLikePage implements EmbedPage {
  final void Function(String message) send;
  int moves = 0;
  _WebLikePage(this.send);

  @override
  Future<void> runJavaScript(String script) async {
    final flush = RegExp(r'flush:(\d+)').firstMatch(script);
    if (script.contains('atomicEmbed.flush(') && flush != null) {
      send(jsonEncode({'method': 'flushed', 'flush': int.parse(flush[1]!)}));
    }
  }

  @override
  Future<Object> runJavaScriptReturningResult(String script) async => false;

  @override
  Widget build() => RawGestureDetector(
        behavior: HitTestBehavior.opaque,
        gestures: {
          EagerGestureRecognizer:
              GestureRecognizerFactoryWithHandlers<EagerGestureRecognizer>(
                  EagerGestureRecognizer.new, (_) {}),
        },
        child: Listener(
          behavior: HitTestBehavior.opaque,
          onPointerMove: (_) => moves++,
          child: const Center(child: Text('the page')),
        ),
      );
}

void main() {
  late _WebLikePage page;

  setUp(() => ResourceView.pageFactory = (send) => page = _WebLikePage(send));
  tearDown(() => ResourceView.pageFactory = null);

  Future<void> open(WidgetTester tester,
      {EdgeInsets gestureInsets = EdgeInsets.zero}) async {
    tester.view.physicalSize = const Size(400, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(systemGestureInsets: gestureInsets),
          child: child!),
      home: const Scaffold(body: Text('home')),
    ));
    tester.state<NavigatorState>(find.byType(Navigator)).push(
        SlideBackRoute<void>(
            builder: (_) => const ResourceView(
                api: _Api(), drive: 'd', subject: 's')));
    await tester.pumpAndSettle();
  }

  double pageLeft(WidgetTester tester) =>
      tester.getTopLeft(find.byType(ResourceView)).dx;

  Future<void> swipe(WidgetTester tester, Offset from, Offset by) async {
    final g = await tester.startGesture(from);
    for (var i = 0; i < 8; i++) {
      await g.moveBy(by / 8);
      await tester.pump(const Duration(milliseconds: 10));
    }
    await g.up();
  }

  testWidgets('a rightward swipe anywhere over the page follows the finger '
      'and leaves; the page still gets the touches', (tester) async {
    await open(tester);
    final g = await tester.startGesture(const Offset(200, 400));
    await g.moveBy(const Offset(60, 0));
    await tester.pump();
    await g.moveBy(const Offset(100, 0));
    await tester.pump();
    expect(pageLeft(tester), greaterThan(50));
    expect(page.moves, greaterThan(0));
    await g.moveBy(const Offset(150, 0));
    await g.up();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
    expect(find.byType(ResourceView), findsNothing);
  });

  testWidgets('a slow short swipe springs back', (tester) async {
    await open(tester);
    final g = await tester.startGesture(const Offset(200, 400));
    await g.moveBy(const Offset(60, 0));
    await g.moveBy(const Offset(20, 0));
    await tester.pump(const Duration(seconds: 1));
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);
    expect(pageLeft(tester), closeTo(0, 0.5));
  });

  testWidgets('a vertical drag does not leave', (tester) async {
    await open(tester);
    await swipe(tester, const Offset(200, 400), const Offset(30, 300));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);
  });

  testWidgets('a leftward drag does not leave', (tester) async {
    await open(tester);
    await swipe(tester, const Offset(300, 400), const Offset(-250, 0));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);
  });

  testWidgets('a page that declared horizontal drags keeps them',
      (tester) async {
    await open(tester);
    // The page posts it at touchstart, before the drag passes the slop.
    final g = await tester.startGesture(const Offset(200, 400));
    page.send(jsonEncode({'method': 'gestures', 'mode': 'horizontal'}));
    await g.moveBy(const Offset(300, 0));
    await g.up();
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);

    // And back to the default at touchend: the next swipe leaves.
    page.send(jsonEncode({'method': 'gestures', 'mode': 'default'}));
    await swipe(tester, const Offset(100, 400), const Offset(300, 0));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsNothing);
  });

  testWidgets('a start inside the system back gesture zone is left to it',
      (tester) async {
    await open(tester, gestureInsets: const EdgeInsets.only(left: 24));
    await swipe(tester, const Offset(10, 400), const Offset(300, 0));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsOneWidget);

    await swipe(tester, const Offset(30, 400), const Offset(300, 0));
    await tester.pumpAndSettle();
    expect(find.byType(ResourceView), findsNothing);
  });
}
