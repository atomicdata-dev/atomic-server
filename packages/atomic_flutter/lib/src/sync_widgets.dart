/// The pieces every part of the Sync screen is built from, so cards, rows,
/// headers, chips and buttons look the same wherever they are used.
///
/// The token set:
///
/// - Type: section header 15 sp w600 (85% text, like the Home headings), body
///   14, caption 13 (muted, at least 4.5:1), chip 12, page title 20.
/// - Space: 4 / 8 / 12 / 16 / 24 ([SyncGap]). Page gutter 16.
/// - Card: [AppColors.bg1] surface, 1 dp [AppColors.bg2] border, 12 dp radius,
///   no shadow; rows inside are at least 48 dp, divided by a 1 dp line of the
///   border colour.
/// - Chip: a 26 dp pill, tinted background, readable text, 18 dp icon.
/// - Buttons: 48 dp, 12 dp radius; filled (primary), outlined (secondary),
///   text in the alert colour (destructive).
/// - Icons: 24 dp (20 in chips and trailing actions).
/// - Tones: the colours of the toast's accents ([SyncTone]).
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'theme.dart';

/// The Sync screen's spacing scale.
abstract final class SyncGap {
  static const xs = 4.0;
  static const s = 8.0;
  static const m = 12.0;
  static const l = 16.0;
  static const xl = 24.0;
}

/// The colours of [AppColors], or the matching default when the app registers
/// none (a test, a host without them).
AppColors syncColors(BuildContext context) {
  final theme = Theme.of(context);
  return theme.extension<AppColors>() ??
      (theme.brightness == Brightness.dark ? AppColors.dark : AppColors.light);
}

/// Text styles, built from the colours so dark and light both read.
abstract final class SyncText {
  static TextStyle body(AppColors c) =>
      TextStyle(fontSize: 14, height: 1.3, color: c.textPrimary);
  static TextStyle bodyStrong(AppColors c) =>
      body(c).copyWith(fontWeight: FontWeight.w600);
  static TextStyle caption(AppColors c) =>
      TextStyle(fontSize: 13, height: 1.3, color: c.textSecondary);
  static TextStyle header(AppColors c) => TextStyle(
      fontSize: 15,
      fontWeight: FontWeight.w600,
      color: c.textPrimary.withValues(alpha: 0.85));
  static TextStyle title(AppColors c) => TextStyle(
      fontSize: 20, fontWeight: FontWeight.w600, color: c.textPrimary);
  static TextStyle chip(Color color) =>
      TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: color);
  static TextStyle mono(AppColors c) => caption(c)
      .copyWith(fontFamily: 'monospace', fontFamilyFallback: const ['Courier']);
}

/// What a chip or note says about a state. The hues are the toast's
/// (`ToastPalette`), so a "Connected" chip and a success toast match.
enum SyncTone { neutral, info, success, warning, error }

extension SyncToneColors on SyncTone {
  Color color(AppColors c) {
    final dark = c.bgBody.computeLuminance() < 0.5;
    switch (this) {
      case SyncTone.neutral:
        return c.textSecondary;
      case SyncTone.info:
        return dark ? const Color(0xFF8FA9F5) : const Color(0xFF4C6CC4);
      case SyncTone.success:
        return dark ? const Color(0xFF6BCB93) : const Color(0xFF2E7D4F);
      case SyncTone.warning:
        return dark ? const Color(0xFFD9A94A) : const Color(0xFF9A6200);
      case SyncTone.error:
        return dark ? const Color(0xFFE3917B) : const Color(0xFFB85C45);
    }
  }
}

/// A section: a header (15 sp, 48 dp tall) and a card of [children].
class SyncSection extends StatelessWidget {
  const SyncSection({
    super.key,
    required this.title,
    required this.children,
    this.trailing,
    this.divided = true,
    this.padded = false,
  });

  final String title;
  final List<Widget> children;

  /// At the header's right end: a refresh button, a count.
  final Widget? trailing;

  /// A line between the card's rows.
  final bool divided;

  /// The card's children get 16 dp around them as a block (a form, text)
  /// instead of being rows.
  final bool padded;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: SyncGap.m),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SyncHeader(title, trailing: trailing),
          if (children.isNotEmpty)
            SyncCard(
                divided: divided && !padded,
                padding: padded ? const EdgeInsets.all(SyncGap.l) : null,
                children: children),
        ],
      ),
    );
  }
}

/// A section's title row.
class SyncHeader extends StatelessWidget {
  const SyncHeader(this.title, {super.key, this.trailing});

  final String title;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 48),
      child: Row(children: [
        Expanded(
          child: Semantics(
            header: true,
            child: Text(title,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: SyncText.header(c)),
          ),
        ),
        if (trailing != null) trailing!,
      ]),
    );
  }
}

/// The decoration every card shares.
BoxDecoration syncCardDecoration(AppColors c) => BoxDecoration(
      color: c.bg1,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: c.bg2, width: 1),
    );

/// A bordered surface of rows.
class SyncCard extends StatelessWidget {
  const SyncCard({
    super.key,
    required this.children,
    this.divided = false,
    this.padding,
    this.margin = EdgeInsets.zero,
  });

  final List<Widget> children;
  final bool divided;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry margin;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final rows = <Widget>[];
    for (var i = 0; i < children.length; i++) {
      if (divided && i > 0) {
        rows.add(Divider(height: 1, thickness: 1, color: c.bg2));
      }
      rows.add(children[i]);
    }
    return Container(
      margin: margin,
      width: double.infinity,
      decoration: syncCardDecoration(c),
      clipBehavior: Clip.antiAlias,
      child: Padding(
        padding: padding ?? EdgeInsets.zero,
        child: Material(
          type: MaterialType.transparency,
          child: Column(
              crossAxisAlignment: CrossAxisAlignment.start, children: rows),
        ),
      ),
    );
  }
}

/// One line: an optional icon, a label and a value, 48 dp at least. Tapping
/// copies [copy] when given (and says so), else calls [onTap].
class KeyValueRow extends StatelessWidget {
  const KeyValueRow({
    super.key,
    required this.label,
    this.value,
    this.valueWidget,
    this.icon,
    this.copy,
    this.copyLabel,
    this.onTap,
    this.trailing,
    this.mono = false,
  });

  final String label;
  final String? value;

  /// Instead of [value]: a bar, a spinner.
  final Widget? valueWidget;
  final IconData? icon;

  /// The text a tap copies, with [copyLabel] ("ID") for the "… copied" note.
  final String? copy;
  final String? copyLabel;
  final VoidCallback? onTap;
  final Widget? trailing;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final tap = copy != null
        ? () {
            Clipboard.setData(ClipboardData(text: copy!));
            ScaffoldMessenger.maybeOf(context)?.showSnackBar(SnackBar(
                content: Text('${copyLabel ?? label} copied'),
                duration: const Duration(seconds: 2)));
          }
        : onTap;
    final row = ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 48),
      child: Padding(
        padding: const EdgeInsets.symmetric(
            horizontal: SyncGap.l, vertical: SyncGap.s),
        child: Row(children: [
          if (icon != null) ...[
            Icon(icon, size: 24, color: c.main),
            const SizedBox(width: SyncGap.m),
          ],
          Flexible(
            flex: 2,
            child: Text(label, style: SyncText.body(c)),
          ),
          const SizedBox(width: SyncGap.m),
          Expanded(
            flex: 3,
            child: valueWidget ??
                Text(value ?? '',
                    textAlign: TextAlign.end,
                    style: mono ? SyncText.mono(c) : SyncText.caption(c),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 2),
          ),
          if (copy != null) ...[
            const SizedBox(width: SyncGap.s),
            Icon(Icons.copy, size: 20, color: c.textSecondary),
          ],
          if (trailing != null) ...[
            const SizedBox(width: SyncGap.s),
            trailing!,
          ],
        ]),
      ),
    );
    if (tap == null) return row;
    return InkWell(
      onTap: tap,
      child:
          Semantics(button: true, label: '$label, ${value ?? ''}', child: row),
    );
  }
}

/// A pill: tinted background, readable text.
class StatusChip extends StatelessWidget {
  const StatusChip(this.label,
      {super.key, this.tone = SyncTone.neutral, this.icon});

  final String label;
  final SyncTone tone;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final color = tone.color(c);
    return Container(
      height: 26,
      padding: const EdgeInsets.symmetric(horizontal: 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(13),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        if (icon != null) ...[
          Icon(icon, size: 18, color: color),
          const SizedBox(width: SyncGap.xs),
        ],
        Text(label, style: SyncText.chip(color)),
      ]),
    );
  }
}

enum SyncButtonKind { primary, secondary, destructive }

/// A 48 dp button: filled for the one main action, outlined for others, plain
/// red text for what removes something.
class SyncActionButton extends StatelessWidget {
  const SyncActionButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.icon,
    this.kind = SyncButtonKind.secondary,
  });

  final String label;
  final IconData? icon;
  final VoidCallback? onPressed;
  final SyncButtonKind kind;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    const shape = RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)));
    const size = Size(0, 48);
    final text = Text(label, style: const TextStyle(fontSize: 14));
    final iconWidget = icon == null ? null : Icon(icon, size: 20);
    switch (kind) {
      case SyncButtonKind.primary:
        final style = FilledButton.styleFrom(
            minimumSize: size, shape: shape, backgroundColor: c.main);
        return iconWidget == null
            ? FilledButton(onPressed: onPressed, style: style, child: text)
            : FilledButton.icon(
                onPressed: onPressed,
                style: style,
                icon: iconWidget,
                label: text);
      case SyncButtonKind.secondary:
        final style = OutlinedButton.styleFrom(
            minimumSize: size,
            shape: shape,
            foregroundColor: c.textPrimary,
            side: BorderSide(color: c.bg2));
        return iconWidget == null
            ? OutlinedButton(onPressed: onPressed, style: style, child: text)
            : OutlinedButton.icon(
                onPressed: onPressed,
                style: style,
                icon: iconWidget,
                label: text);
      case SyncButtonKind.destructive:
        final style = TextButton.styleFrom(
            minimumSize: size, shape: shape, foregroundColor: c.alert);
        return iconWidget == null
            ? TextButton(onPressed: onPressed, style: style, child: text)
            : TextButton.icon(
                onPressed: onPressed,
                style: style,
                icon: iconWidget,
                label: text);
    }
  }
}

/// A quiet button inside a card (Copy ID, Switch to this): text, 48 dp tall
/// target, the main colour.
class SyncTextAction extends StatelessWidget {
  const SyncTextAction(
      {super.key, required this.label, required this.onPressed, this.icon});

  final String label;
  final IconData? icon;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final style = TextButton.styleFrom(
      minimumSize: const Size(0, 48),
      foregroundColor: c.main,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(12))),
      textStyle: const TextStyle(fontSize: 14),
    );
    return icon == null
        ? TextButton(onPressed: onPressed, style: style, child: Text(label))
        : TextButton.icon(
            onPressed: onPressed,
            style: style,
            icon: Icon(icon, size: 20),
            label: Text(label));
  }
}

/// A banner or an empty state: an icon and a line, tinted by [tone].
class SyncNote extends StatelessWidget {
  const SyncNote(this.text,
      {super.key, this.tone = SyncTone.neutral, this.icon, this.action});

  final String text;
  final SyncTone tone;
  final IconData? icon;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final color = tone.color(c);
    final plain = tone == SyncTone.neutral;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(
          horizontal: SyncGap.l, vertical: SyncGap.m),
      decoration: plain
          ? null
          : BoxDecoration(
              color: color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(12)),
      child: Row(children: [
        if (icon != null) ...[
          Icon(icon, size: 24, color: plain ? c.textSecondary : color),
          const SizedBox(width: SyncGap.m),
        ],
        Expanded(
          child:
              Text(text, style: plain ? SyncText.caption(c) : SyncText.body(c)),
        ),
        if (action != null) action!,
      ]),
    );
  }
}

/// A share of a total, as a thin bar.
class ShareBar extends StatelessWidget {
  const ShareBar(this.share, {super.key});

  /// 0..1.
  final double share;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    return ClipRRect(
      borderRadius: BorderRadius.circular(3),
      child: SizedBox(
        height: 6,
        child: Stack(children: [
          Positioned.fill(child: ColoredBox(color: c.bg2)),
          Positioned.fill(
            child: FractionallySizedBox(
              alignment: Alignment.centerLeft,
              widthFactor: share.clamp(0.0, 1.0),
              child: ColoredBox(color: c.main),
            ),
          ),
        ]),
      ),
    );
  }
}

/// A 20 dp spinner for a row's trailing end.
class SyncSpinner extends StatelessWidget {
  const SyncSpinner({super.key});

  @override
  Widget build(BuildContext context) => const SizedBox.square(
      dimension: 20, child: CircularProgressIndicator(strokeWidth: 2));
}

/// A two-line row: an icon, a title, a muted subtitle and a trailing widget;
/// 56 dp when it has a subtitle, else 48.
class SyncRow extends StatelessWidget {
  const SyncRow({
    super.key,
    required this.title,
    this.subtitle,
    this.icon,
    this.iconColor,
    this.trailing,
    this.onTap,
    this.destructive = false,
  });

  final String title;
  final String? subtitle;
  final IconData? icon;
  final Color? iconColor;
  final Widget? trailing;
  final VoidCallback? onTap;
  final bool destructive;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final row = ConstrainedBox(
      constraints: BoxConstraints(minHeight: subtitle == null ? 48 : 56),
      child: Padding(
        padding: const EdgeInsets.symmetric(
            horizontal: SyncGap.l, vertical: SyncGap.s),
        child: Row(children: [
          if (icon != null) ...[
            Icon(icon,
                size: 24,
                color: iconColor ?? (destructive ? c.textSecondary : c.main)),
            const SizedBox(width: SyncGap.m),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: SyncText.body(c)),
                if (subtitle != null && subtitle!.isNotEmpty)
                  Text(subtitle!, style: SyncText.caption(c)),
              ],
            ),
          ),
          if (trailing != null) ...[
            const SizedBox(width: SyncGap.s),
            trailing!,
          ],
        ]),
      ),
    );
    return onTap == null ? row : InkWell(onTap: onTap, child: row);
  }
}
