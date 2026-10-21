import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

double _lum(Color c) => c.computeLuminance();

/// WCAG contrast ratio.
double _contrast(Color a, Color b) {
  final hi = _lum(a) > _lum(b) ? a : b;
  final lo = identical(hi, a) ? b : a;
  return (_lum(hi) + 0.05) / (_lum(lo) + 0.05);
}

Color _opaque(Color c, Color over) => Color.alphaBlend(c, over);

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  for (final entry in {'light': AppColors.light, 'dark': AppColors.dark}.entries) {
    test('${entry.key}: header band, rows and text levels have the contrast',
        () {
      final c = entry.value;
      // The header band is exactly the bottom bar's colour.
      expect(c.sectionBand, c.barSurface);
      // The selected row differs from the header band and the page.
      expect(c.rowHighlight, isNot(c.sectionBand));
      expect(_contrast(c.rowHighlight, c.sectionBand), greaterThanOrEqualTo(1.05));
      expect(_contrast(c.rowHighlight, c.bgBody), greaterThan(1.0));
      // Three readable text levels.
      final header = c.sectionHeaderText.color!;
      final title = c.textPrimary;
      final caption = c.textSecondary;
      expect(_contrast(header, c.sectionBand), greaterThanOrEqualTo(4.5));
      expect(_contrast(title, c.bgBody), greaterThanOrEqualTo(4.5));
      expect(_contrast(caption, c.bgBody), greaterThanOrEqualTo(4.5));
      expect(_contrast(caption, c.rowHighlight), greaterThanOrEqualTo(4.5));
      expect(_contrast(caption, c.sectionBand), greaterThanOrEqualTo(4.5));
      // The caption is clearly quieter than the item title and the header.
      expect(_contrast(title, caption), greaterThan(1.8));
      expect(header, title, reason: 'the header is full strength');
      expect(_opaque(c.sectionHeaderText.color!, c.bgBody), header);
    });
  }

  for (final brightness in [Brightness.light, Brightness.dark]) {
    testWidgets('$brightness: headers are bands, hairline between sections',
        (tester) async {
      tester.view.physicalSize = const Size(400, 1600);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final c = brightness == Brightness.light ? AppColors.light : AppColors.dark;
      final api = FakeApi(
        favoriteList: [
          (
            subject: 'did:ad:doc',
            title: 'Plain doc',
            className: 'document-v2',
            openedAt: 0,
            emoji: null,
            picture: null
          )
        ],
      );
      await tester.pumpWidget(app(ChatsScreen(drive: 'did:ad:drive', api: api),
          brightness: brightness));
      await tester.pumpAndSettle();

      // The first section has no hairline above it, the others do.
      expect(find.byKey(const ValueKey('section-divider-drives')), findsNothing);
      expect(find.byKey(const ValueKey('section-divider-favorites')), findsOneWidget);
      expect(tester.getSize(find.byKey(const ValueKey('section-divider-favorites'))).height, 1);

      // The heading sits on the band, with the shared header style.
      final heading = find.descendant(
          of: find.byKey(const ValueKey('home-panel-favorites')),
          matching: find.byType(Material));
      expect(tester.widget<Material>(heading.first).color, c.sectionBand);
      final title = tester.widget<Text>(find.descendant(
          of: find.byKey(const ValueKey('home-panel-favorites')),
          matching: find.text('Favorites')));
      expect(title.style!.fontSize, 14);
      expect(title.style!.fontWeight, FontWeight.w700);
      expect(title.style!.color, c.textPrimary);

      // The item: its title in the text colour, a different style from the
      // header; a row is not on the band.
      final item = tester.widget<ListTile>(find.ancestor(
          of: find.text('Plain doc'), matching: find.byType(ListTile)));
      expect(item.titleTextStyle!.color, c.textPrimary);
      expect(item.titleTextStyle!.fontWeight, FontWeight.w400);
      expect(item.titleTextStyle!.fontSize, 15);
      expect(item.subtitleTextStyle!.color, c.textSecondary);
    });
  }
}
