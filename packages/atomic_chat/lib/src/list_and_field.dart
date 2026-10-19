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
  Widget build(BuildContext context) => LayoutBuilder(
        builder: (context, box) => box.maxHeight < minHeight
            ? SingleChildScrollView(reverse: true, child: field)
            : Column(children: [Expanded(child: list), field]),
      );
}
