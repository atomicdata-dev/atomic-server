import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import 'atomic_wordmark_svg.dart';

/// The top bar of every native screen: the same height, padding, title style,
/// back affordance (shown when the route can pop) and safe-area handling
/// (the status bar inset is applied here and nowhere else). Use as a
/// [Scaffold.appBar].
///
/// Pass a [title] string or, for something richer, a [titleWidget] (the home
/// page shows [AtomicWordmark]); [actions] go on the right.
class AppTopBar extends StatelessWidget implements PreferredSizeWidget {
  static const height = kToolbarHeight;

  final String? title;
  final Widget? titleWidget;
  final List<Widget> actions;

  /// Overrides the automatic back button.
  final Widget? leading;

  const AppTopBar({
    super.key,
    this.title,
    this.titleWidget,
    this.actions = const [],
    this.leading,
  }) : assert(title != null || titleWidget != null);

  @override
  Size get preferredSize => const Size.fromHeight(height);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return AppBar(
      backgroundColor: c.bgBody,
      surfaceTintColor: Colors.transparent,
      scrolledUnderElevation: 0,
      toolbarHeight: height,
      centerTitle: false,
      titleSpacing: 16,
      leading: leading,
      automaticallyImplyLeading: true,
      title: titleWidget ??
          Text(
            title!,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: c.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.w600,
            ),
          ),
      actions: [...actions, const SizedBox(width: 4)],
    );
  }
}

/// The atomic.place wordmark: the web logo's artwork (see
/// `atomic_wordmark_svg.dart`) in the theme's text colour, with the gradient
/// full stop. Left-aligned, [height] tall.
class AtomicWordmark extends StatelessWidget {
  final double height;

  const AtomicWordmark({super.key, this.height = 22});

  @override
  Widget build(BuildContext context) {
    final color = context.appColors.textPrimary;
    final hex =
        '#${(color.toARGB32() & 0xFFFFFF).toRadixString(16).padLeft(6, '0')}';
    return Semantics(
      label: 'atomic.place',
      excludeSemantics: true,
      child: SvgPicture.string(
        atomicWordmarkSvg.replaceAll('currentColor', hex),
        key: const Key('atomic-wordmark'),
        height: height,
        alignment: Alignment.centerLeft,
      ),
    );
  }
}
