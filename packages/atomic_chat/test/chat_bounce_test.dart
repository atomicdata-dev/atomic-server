import 'package:atomic_chat/atomic_chat.dart';
import 'package:atomic_flutter/atomic_flutter.dart' show AppScrollBehavior;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets(
      'bouncing at the bottom of a reversed chat list keeps "at bottom"',
      (tester) async {
    final window = ChatWindow<int>(
        readPage: (before, size) async => ChatPage.empty<int>(),
        readAfter: null,
        idOf: (i) => '$i');
    final keeper = ChatScrollKeeper(window);
    await tester.pumpWidget(MaterialApp(
      scrollBehavior: const AppScrollBehavior(),
      home: Scaffold(
        body: ListView.builder(
          reverse: true,
          controller: keeper.controller,
          physics: chatScrollPhysics,
          itemCount: 40,
          itemBuilder: (_, i) => SizedBox(height: 100, child: Text('$i')),
        ),
      ),
    ));
    final g = await tester.startGesture(const Offset(200, 300));
    for (var i = 0; i < 30; i++) {
      await g.moveBy(const Offset(0, -10));
    }
    await tester.pump();
    expect(keeper.controller.position.pixels, lessThan(0));
    expect(keeper.atBottom, isTrue);
    expect(keeper.farFromBottom, isFalse);
    await g.up();
    await tester.pumpAndSettle();
    expect(keeper.controller.position.pixels, 0);
    expect(keeper.atBottom, isTrue);
  });
}
