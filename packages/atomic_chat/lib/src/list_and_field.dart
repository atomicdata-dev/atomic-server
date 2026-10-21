import 'package:flutter/material.dart';

/// A list above a field at the bottom (a chat and its composer, search and
/// its field). When the page is too low for both, as sideways with the
/// keyboard up (about 60 dp left), only the field shows, scrollable: the two
/// together overflowed the page there.
class ListAndField extends StatelessWidget {
  final Widget list;
  final Widget field;

  /// Below this height only the field shows.
  final double minHeight;

  /// The field runs the whole width of the pane (its own edge-to-edge
  /// border), and keeps its content to the readable width itself.
  final bool fullWidthField;

  const ListAndField({
    super.key,
    required this.list,
    required this.field,
    this.minHeight = 120,
    this.fullWidthField = false,
  });

  @override
  Widget build(BuildContext context) {
    final Widget bottom = fullWidthField ? field : ReadableWidth(child: field);
    return LayoutBuilder(
      builder: (context, box) => box.maxHeight < minHeight
          ? SingleChildScrollView(reverse: true, child: bottom)
          // The list runs the whole width, so its scrollbar and overscroll
          // sit at the pane's edge; it centres its own content with
          // [readableHorizontalPadding].
          : Column(children: [Expanded(child: list), bottom]),
    );
  }
}

/// The horizontal padding that centres a scrollable's content in a column of
/// at most [ReadableWidth.maxWidth] while the scrollable itself (and its
/// scrollbar) spans [paneWidth]. [gutter] is added on each side, as inside
/// the column. Narrower than the column it is just [gutter].
EdgeInsets readableHorizontalPadding(double paneWidth, {double gutter = 0}) =>
    EdgeInsets.symmetric(horizontal: gutter + readableSideInset(paneWidth));

/// The empty margin each side of the readable column in a [paneWidth] pane.
double readableSideInset(double paneWidth) =>
    paneWidth <= ReadableWidth.maxWidth
        ? 0
        : (paneWidth - ReadableWidth.maxWidth) / 2;

/// Text-heavy pages (a chat, settings, sync) in a wide pane: at most
/// [maxWidth] wide, centred. Narrower than that (a phone) the child gets the
/// whole width, unchanged.
class ReadableWidth extends StatelessWidget {
  static const maxWidth = 720.0;

  final Widget child;

  const ReadableWidth({super.key, required this.child});

  @override
  Widget build(BuildContext context) => LayoutBuilder(
        builder: (context, box) => box.maxWidth <= maxWidth
            ? child
            : Center(
                child: SizedBox(
                  width: maxWidth,
                  height: box.hasBoundedHeight ? box.maxHeight : null,
                  child: child,
                ),
              ),
      );
}
