import 'package:atomic_chat/src/markdown.dart';
import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _app(Widget child, {AppColors colors = AppColors.light}) => MaterialApp(
      theme: ThemeData(extensions: [colors]),
      home: Scaffold(body: SingleChildScrollView(child: child)),
    );

String _plain(List<MdInline> inl) => inlinePlainText(inl);

void main() {
  group('blocks', () {
    test('headings, paragraphs, rules and quotes', () {
      final b = parseMarkdown('# Title\n\nSome *text*\nnext line\n\n---\n'
          '> quoted\n> more\n\n### Small ###');
      expect(b, hasLength(5));
      expect((b[0] as MdHeading).level, 1);
      expect((b[0] as MdHeading).text, 'Title');
      expect((b[1] as MdParagraph).text, 'Some *text*\nnext line');
      expect(b[2], isA<MdRule>());
      final q = b[3] as MdQuote;
      expect((q.children.single as MdParagraph).text, 'quoted\nmore');
      expect((b[4] as MdHeading).text, 'Small');
    });

    test('fenced code keeps its text and language, open or closed', () {
      final closed =
          parseMarkdown('```dart\nvoid main() {\n  print(1);\n}\n```').single
              as MdCode;
      expect(closed.language, 'dart');
      expect(closed.code, 'void main() {\n  print(1);\n}');
      expect(closed.closed, isTrue);
      final open =
          parseMarkdown('Look:\n```py\nx = 1\n# no heading').last as MdCode;
      expect(open.closed, isFalse);
      expect(open.code, 'x = 1\n# no heading');
    });

    test('lists: ordered, unordered, nested, with a start number', () {
      final b = parseMarkdown('3. one\n4. two\n   - a\n   - b\n     1. deep\n'
          '5. three\n\n- x\n  continued\n- y');
      expect(b, hasLength(2));
      final ol = b[0] as MdList;
      expect(ol.ordered, isTrue);
      expect(ol.start, 3);
      expect(ol.items, hasLength(3));
      final nested = ol.items[1][1] as MdList;
      expect(nested.ordered, isFalse);
      expect(nested.items, hasLength(2));
      expect((nested.items[1][1] as MdList).ordered, isTrue);
      final ul = b[1] as MdList;
      expect((ul.items[0].single as MdParagraph).text, 'x\ncontinued');
    });

    test('a nested list indented by two under a number still nests', () {
      final ol = parseMarkdown('1. one\n  - sub\n2. two').single as MdList;
      expect(ol.items, hasLength(2));
      expect(ol.items[0][1], isA<MdList>());
    });

    test('tables with alignment, and a pipe in code', () {
      final t = parseMarkdown('| Name | Size |\n|:--|--:|\n| `a|b` | 2 |\n'
              '| c | 3 |')
          .single as MdTable;
      expect(t.header, ['Name', 'Size']);
      expect(t.aligns, [MdAlign.left, MdAlign.right]);
      expect(t.rows, [
        ['`a|b`', '2'],
        ['c', '3'],
      ]);
    });

    test('a table whose separator has not arrived is still text', () {
      expect(parseMarkdown('| a | b |').single, isA<MdParagraph>());
    });

    test('incremental parsing keeps settled blocks', () {
      final doc = MarkdownDocument();
      final first = doc.update('# Hi\n\nPara one\n\n- a');
      final second = doc.update('# Hi\n\nPara one\n\n- a\n- b');
      expect(identical(first[0], second[0]), isTrue);
      expect(identical(first[1], second[1]), isTrue);
      expect((second[2] as MdList).items, hasLength(2));
      // Not an extension: parsed again from the start.
      final third = doc.update('Other');
      expect(third.single, isA<MdParagraph>());
      // The same result as a fresh parse, block for block.
      const text = 'a\n\n```\ncode\n\nmore\n```\n\n1. x\n\n   y\n2. z';
      final d = MarkdownDocument();
      for (var i = 1; i <= text.length; i++) {
        d.update(text.substring(0, i));
      }
      expect(d.blocks.map((b) => b.runtimeType),
          parseMarkdown(text).map((b) => b.runtimeType));
    });
  });

  group('inline', () {
    test('emphasis, code, strike and links', () {
      final i = parseInline(
          'a **b** *c* _d_ ~~e~~ `f` [g](https://x.y) <https://z.z>');
      expect(i.whereType<MdStyled>().map((s) => s.style),
          [MdStyle.bold, MdStyle.italic, MdStyle.italic, MdStyle.strike]);
      expect(i.whereType<MdCodeSpan>().single.code, 'f');
      expect(i.whereType<MdLink>().map((l) => l.url),
          ['https://x.y', 'https://z.z']);
      expect(_plain(i), 'a b c d e f g https://z.z');
    });

    test('bare web and resource links, without trailing punctuation', () {
      final i = parseInline('See https://atomic.place/x. Or did:ad:abc123, '
          'or atomic:foo!');
      expect(i.whereType<MdLink>().map((l) => l.url),
          ['https://atomic.place/x', 'did:ad:abc123', 'atomic:foo']);
    });

    test('snake_case and 2*3*4 stay text', () {
      expect(_plain(parseInline('snake_case_name')), 'snake_case_name');
      expect(parseInline('snake_case_name').single, isA<MdText>());
      expect(parseInline('2 * 3 * 4').single, isA<MdText>());
    });

    test('an unclosed pair stays text, or styles the rest while streaming', () {
      expect(_plain(parseInline('so **bold')), 'so **bold');
      final open = parseInline('so **bold', open: true);
      expect((open.last as MdStyled).style, MdStyle.bold);
      expect(_plain(open), 'so bold');
      final code = parseInline('run `npm i', open: true);
      expect((code.last as MdCodeSpan).code, 'npm i');
    });

    test('escapes', () {
      expect(_plain(parseInline(r'\*not\* \`x\`')), '*not* `x`');
    });
  });

  group('MarkdownView', () {
    testWidgets('renders every kind of block', (tester) async {
      await tester.pumpWidget(_app(const MarkdownView(
        '# Plan\n\nThis is **important** and `code`.\n\n'
        '```dart\nfinal x = 1;\n```\n\n'
        '- one\n- two\n  1. nested\n\n'
        '> a quote\n\n'
        '| A | B |\n|---|---|\n| 1 | 2 |\n\n---\n\n[link](https://a.b)',
      )));
      expect(find.text('Plan'), findsOneWidget);
      expect(find.text('This is important and code.'), findsOneWidget);
      expect(find.text('final x = 1;'), findsOneWidget);
      expect(find.text('dart'), findsOneWidget);
      expect(find.byTooltip('Copy code'), findsOneWidget);
      expect(find.text('•'), findsNWidgets(2));
      expect(find.text('1.'), findsOneWidget);
      expect(find.text('nested'), findsOneWidget);
      expect(find.text('a quote'), findsOneWidget);
      expect(find.byType(Table), findsOneWidget);
      expect(find.byType(Divider), findsWidgets);
      expect(find.text('link'), findsOneWidget);
      expect(find.byType(SelectionArea), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('long code lines scroll instead of overflowing',
        (tester) async {
      await tester.pumpWidget(_app(MarkdownView(
          '```\n${'x' * 400}\n```\n\n| ${'wide ' * 40} | b |\n|--|--|\n| 1 | 2 |')));
      expect(tester.takeException(), isNull);
    });

    testWidgets('copy puts the code on the clipboard', (tester) async {
      String? copied;
      tester.binding.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String;
        }
        return null;
      });
      await tester.pumpWidget(_app(const MarkdownView('```\nls -la\n```')));
      await tester.tap(find.byTooltip('Copy code'));
      await tester.pump();
      expect(copied, 'ls -la');
      await tester.pump(const Duration(seconds: 2));
    });

    testWidgets('links go to the handler', (tester) async {
      final opened = <String>[];
      await tester.pumpWidget(_app(MarkdownView(
        'Open [the doc](did:ad:doc1)',
        onLink: opened.add,
      )));
      await tester.tapOnText(find.textRange.ofSubstring('the doc'));
      expect(opened, ['did:ad:doc1']);
    });

    testWidgets('a streaming answer with an open fence and bold renders',
        (tester) async {
      Future<void> show(String t) => tester.pumpWidget(_app(MarkdownView(
            t,
            streaming: true,
          )));
      await show('Here **is');
      expect(find.text('Here is'), findsOneWidget);
      await show('Here **is** code:\n\n```js\nconsole.lo');
      expect(find.text('console.lo'), findsOneWidget);
      expect(find.text('js'), findsOneWidget);
      await show('Here **is** code:\n\n```js\nconsole.log(1)\n```\n\nDone.');
      expect(find.text('Done.'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('inline mode keeps what a person typed', (tester) async {
      await tester.pumpWidget(_app(const MarkdownView(
        '# not a heading\n1. not a list **but bold**',
        inline: true,
      )));
      expect(
          find.text('# not a heading\n1. not a list but bold'), findsOneWidget);
    });

    testWidgets('dark theme and a large font scale', (tester) async {
      await tester.pumpWidget(MediaQuery(
        data: const MediaQueryData(textScaler: TextScaler.linear(1.3)),
        child: _app(
          const MarkdownView('## Big\n\n- item with `code`\n\n```\nx\n```'),
          colors: AppColors.dark,
        ),
      ));
      expect(find.text('Big'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  });
}
