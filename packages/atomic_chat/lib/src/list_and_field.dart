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

  const ListAndField({
    super.key,
    required this.list,
    required this.field,
    this.minHeight = 120,
  });

  @override
  Widget build(BuildContext context) => ReadableWidth(
        child: LayoutBuilder(
          builder: (context, box) => box.maxHeight < minHeight
              ? SingleChildScrollView(reverse: true, child: field)
              : Column(children: [Expanded(child: list), field]),
        ),
      );
}

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
