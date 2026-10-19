import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';

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

/// The atomic.place wordmark as text: "atomic", a small dot in the brand blue,
/// "place".
class AtomicWordmark extends StatelessWidget {
  final double fontSize;

  const AtomicWordmark({super.key, this.fontSize = 22});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final style = TextStyle(
      color: c.textPrimary,
      fontSize: fontSize,
      fontWeight: FontWeight.w700,
      letterSpacing: -0.5,
    );
    return Semantics(
      label: 'atomic.place',
      excludeSemantics: true,
      child: Row(
        key: const Key('atomic-wordmark'),
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.baseline,
        textBaseline: TextBaseline.alphabetic,
        children: [
          Text('atomic', style: style),
          Container(
            width: fontSize * 0.3,
            height: fontSize * 0.3,
            margin: EdgeInsets.symmetric(horizontal: fontSize * 0.1),
            decoration: BoxDecoration(color: c.main, shape: BoxShape.circle),
          ),
          Text('place', style: style),
        ],
      ),
    );
  }
}
