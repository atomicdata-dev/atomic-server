import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import 'app_shell.dart';
import 'atomic_wordmark_svg.dart';
import 'home_sections.dart' show HomeSection;

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
    final back = leading == null ? SectionBack._of(context) : null;
    return AppBar(
      backgroundColor: c.bgBody,
      surfaceTintColor: Colors.transparent,
      scrolledUnderElevation: 0,
      toolbarHeight: height,
      centerTitle: false,
      titleSpacing: 16,
      leading: leading ?? back,
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

/// Marks a page as belonging to a home [section] (a chat to "AI chats").
/// Next to the list pane (the split layout) its back goes to that section's
/// full list in the detail pane, with the bar's back arrow and the system
/// back alike: the home is the sidebar, always in view, so popping to it
/// would do nothing. On a phone it changes nothing.
class SectionBack extends StatelessWidget {
  final HomeSection section;
  final Widget child;

  const SectionBack({super.key, required this.section, required this.child});

  /// The bar's back button for the enclosing [SectionBack], if the layout is
  /// split.
  static Widget? _of(BuildContext context) {
    final scope = context.getInheritedWidgetOfExactType<_SectionScope>();
    final shell = ShellScope.maybeOf(context);
    if (scope == null || shell == null || !shell.split) return null;
    return BackButton(onPressed: () => _go(shell, scope.section));
  }

  /// The section's full list; the first page (the activity) when the section
  /// has nothing to list.
  static void _go(ShellController shell, HomeSection section) =>
      shell.homeSections.value.contains(section)
          ? shell.openHomeSection(section)
          : shell.goHome();

  @override
  Widget build(BuildContext context) {
    final shell = ShellScope.maybeOf(context);
    final split = shell != null && shell.split;
    return _SectionScope(
      section: section,
      child: split
          ? PopScope(
              canPop: false,
              onPopInvokedWithResult: (didPop, _) {
                if (!didPop) _go(shell, section);
              },
              child: child)
          : child,
    );
  }
}

class _SectionScope extends InheritedWidget {
  final HomeSection section;

  const _SectionScope({required this.section, required super.child});

  @override
  bool updateShouldNotify(_SectionScope old) => section != old.section;
}

/// The atomic.place wordmark: the web logo's artwork (see
/// `atomic_wordmark_svg.dart`) in the theme's text colour, with the gradient
/// full stop. [height] tall; left-aligned by default (top bar), pass
/// [alignment] `Alignment.center` to centre it (welcome screen).
class AtomicWordmark extends StatelessWidget {
  final double height;
  final Alignment alignment;

  const AtomicWordmark({
    super.key,
    this.height = 22,
    this.alignment = Alignment.centerLeft,
  });

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
        alignment: alignment,
      ),
    );
  }
}
