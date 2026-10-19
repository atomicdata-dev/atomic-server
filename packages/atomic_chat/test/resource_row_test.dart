import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _host(Widget child) => MaterialApp(
      theme: ThemeData(extensions: const [AppColors.light]),
      home: Scaffold(body: child),
    );

void main() {
  testWidgets('shows the emoji instead of the icon when given', (tester) async {
    await tester.pumpWidget(_host(const ResourceRow(
      icon: Icons.table_chart_outlined,
      emoji: '🦊',
      title: 'Fox',
    )));
    expect(find.text('🦊'), findsOneWidget);
    expect(find.byIcon(Icons.table_chart_outlined), findsNothing);
  });

  testWidgets('shows the class icon without an emoji', (tester) async {
    for (final emoji in [null, '']) {
      await tester.pumpWidget(_host(ResourceRow(
        icon: Icons.table_chart_outlined,
        emoji: emoji,
        title: 'Plain',
      )));
      expect(find.byIcon(Icons.table_chart_outlined), findsOneWidget);
    }
  });

  test('class names map to icons, anything else to a document', () {
    const expected = {
      'Folder': Icons.folder_outlined,
      'Drive': Icons.folder_outlined,
      'Table': Icons.table_chart_outlined,
      'Canvas': Icons.draw_outlined,
      'AI chat': Icons.chat_bubble_outline,
      'ai-chat': Icons.chat_bubble_outline,
      'Conversation': Icons.chat_bubble_outline,
      'Class': Icons.data_object,
      'property': Icons.data_object,
      'form-field': Icons.input,
      'Document': Icons.description_outlined,
      'document-v2': Icons.description_outlined,
      'row': Icons.description_outlined,
      '': Icons.description_outlined,
      'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat':
          Icons.chat_bubble_outline,
    };
    for (final e in expected.entries) {
      expect(iconForClass(e.key), e.value, reason: e.key);
    }
  });

  test('classLabel gives class shortnames and URLs a human label', () {
    expect(classLabel('document-v2'), 'Document');
    expect(classLabel('https://atomicdata.dev/classes/DocumentV2'), 'Document');
    expect(classLabel('table'), 'Table');
    expect(classLabel('Folder'), 'Folder');
    expect(classLabel('drive'), 'Drive');
    expect(classLabel('chatroom'), 'Chat');
    expect(classLabel('meeting'), 'Meeting');
    expect(classLabel('ai-chat'), 'AI chat');
    expect(classLabel('chatlog'), 'AI chat');
    expect(classLabel('canvas'), 'Canvas');
    expect(classLabel('web-page-v3'), 'Web page');
    expect(classLabel('some_thing'), 'Some thing');
    expect(classLabel(''), '');
  });
}
