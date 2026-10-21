import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';

import 'chat_text_styles.dart';
import 'row_leading.dart';

/// "14:05": the time of a message inside its bubble (the day is on the
/// separator above).
String clockTime(int ms) {
  final at = DateTime.fromMillisecondsSinceEpoch(ms);
  String two(int n) => n.toString().padLeft(2, '0');
  return '${two(at.hour)}:${two(at.minute)}';
}

/// A person's round picture: their initial on a colour from their name (the
/// shared [RowLeading] machinery, so a picture slots in when one is known).
Widget personAvatar(String name, double size, {Key? key}) => RowLeading(
      key: key,
      fallbackLabel: name.trim().isEmpty ? '?' : name.trim(),
      fallbackIcon: Icons.person_outline,
      shape: RowShape.circle,
      showInitial: true,
      size: size,
    );

/// One message of a room or conversation as a messenger shows it: mine on the
/// right in an accent bubble, the others' on the left in a neutral one with
/// the sender's avatar beside the last message of a run, the sender's name
/// on the first (in group chats), and the time inside the last.
class MessageRow extends StatelessWidget {
  final bool mine;

  /// First and last message of a run of one sender (corners, gaps, name,
  /// avatar and time follow from it).
  final bool first;
  final bool last;

  /// The sender's name above the text (group chats, first of a run).
  final String? name;

  /// Who the avatar shows (others only); null leaves out the avatar slot.
  final String? avatarOf;

  /// The text of the message.
  final Widget content;

  /// The time to show inside the bubble, and whether the message is still
  /// being sent.
  final String? time;
  final bool sending;

  /// The width the list has for rows.
  final double listWidth;

  const MessageRow({
    super.key,
    required this.mine,
    required this.first,
    required this.last,
    this.name,
    this.avatarOf,
    required this.content,
    this.time,
    this.sending = false,
    required this.listWidth,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final styles = ChatTextStyles.of(context);
    final slot = avatarOf != null && !mine
        ? ChatTextStyles.avatarSize + ChatTextStyles.avatarGap
        : 0.0;
    final cap = ChatTextStyles.bubbleMaxWidth(listWidth);
    final maxWidth = cap < listWidth - slot ? cap : listWidth - slot;
    Widget body = content;
    if (time != null || sending) {
      final muted = mine ? ChatTextStyles.onOwnMuted : c.textSecondary;
      body = Row(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Flexible(child: content),
          const SizedBox(width: 8),
          Padding(
            padding: const EdgeInsets.only(bottom: 1),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              if (time != null)
                Text(time!,
                    key: const Key('message-time'),
                    style: styles.time.copyWith(color: muted)),
              if (sending) ...[
                if (time != null) const SizedBox(width: 3),
                Icon(Icons.schedule,
                    key: const Key('message-sending'), size: 12, color: muted),
              ],
            ]),
          ),
        ],
      );
    }
    final bubble = Container(
      key: const Key('message-bubble'),
      constraints: BoxConstraints(maxWidth: maxWidth),
      padding: ChatTextStyles.bubblePadding,
      decoration: ChatTextStyles.bubbleDecoration(c,
          mine: mine, joinAbove: !first, joinBelow: !last),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (name != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 2),
              child: Text(name!,
                  key: const Key('message-author'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: styles.sender
                      .copyWith(color: ChatTextStyles.nameColor(c, name!))),
            ),
          body,
        ],
      ),
    );
    return Padding(
      padding: EdgeInsets.only(top: ChatTextStyles.gapAbove(first)),
      child: Row(
        mainAxisAlignment:
            mine ? MainAxisAlignment.end : MainAxisAlignment.start,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (slot > 0) ...[
            SizedBox(
              width: ChatTextStyles.avatarSize,
              height: last ? ChatTextStyles.avatarSize : 0,
              child: last
                  ? personAvatar(avatarOf!, ChatTextStyles.avatarSize,
                      key: const Key('message-avatar'))
                  : null,
            ),
            const SizedBox(width: ChatTextStyles.avatarGap),
          ],
          bubble,
        ],
      ),
    );
  }
}

/// The 44 dp send button: the main colour with a white arrow when there is
/// something to send, a quiet disc when there is not (the colours ease over
/// 150 ms).
class ChatSendButton extends StatelessWidget {
  final VoidCallback? onPressed;
  final String tooltip;
  final IconData icon;

  const ChatSendButton({
    super.key,
    required this.onPressed,
    this.tooltip = 'Send',
    this.icon = Icons.arrow_upward,
  });

  static const size = 44.0;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return IconButton.filled(
      tooltip: tooltip,
      onPressed: onPressed,
      icon: Icon(icon),
      style: ButtonStyle(
        fixedSize: const WidgetStatePropertyAll(Size.square(size)),
        minimumSize: const WidgetStatePropertyAll(Size.square(size)),
        padding: const WidgetStatePropertyAll(EdgeInsets.zero),
        animationDuration: const Duration(milliseconds: 150),
        backgroundColor: WidgetStateProperty.resolveWith((s) =>
            s.contains(WidgetState.disabled)
                ? c.bg1
                : ChatTextStyles.ownBubble(c)),
        foregroundColor: WidgetStateProperty.resolveWith((s) =>
            s.contains(WidgetState.disabled)
                ? c.textSecondary
                : ChatTextStyles.onOwn),
        side: WidgetStateProperty.resolveWith((s) =>
            s.contains(WidgetState.disabled)
                ? BorderSide(color: ChatTextStyles.hairline(c))
                : BorderSide.none),
      ),
    );
  }
}

/// The look of the message field: a pill (24 dp radius, at least 48 dp high)
/// filled like others' bubbles with a hairline edge.
InputDecoration chatFieldDecoration(BuildContext context,
    {String hint = 'Message'}) {
  final c = context.appColors;
  final styles = ChatTextStyles.of(context);
  OutlineInputBorder edge(Color color) => OutlineInputBorder(
        borderRadius: BorderRadius.circular(24),
        borderSide: BorderSide(color: color),
      );
  final line = ChatTextStyles.hairline(c);
  return InputDecoration(
    hintText: hint,
    hintStyle: styles.composerHint,
    filled: true,
    fillColor: c.bg1,
    isDense: true,
    constraints: const BoxConstraints(minHeight: 48),
    contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
    border: edge(line),
    enabledBorder: edge(line),
    disabledBorder: edge(line),
    focusedBorder: edge(c.main),
  );
}

/// The strip a composer sits in: the page colour, a hairline above, 8 dp
/// around, clear of the system bottom inset.
class ChatComposerFrame extends StatelessWidget {
  final Widget child;
  const ChatComposerFrame({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.bgBody,
        border: Border(top: BorderSide(color: ChatTextStyles.hairline(c))),
      ),
      child: SafeArea(
        top: false,
        child: Padding(padding: const EdgeInsets.all(8), child: child),
      ),
    );
  }
}

/// A compact chat title: a round picture (or [icon]), the name and a muted
/// line below it, right after the back arrow.
class ChatHeader extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData? icon;

  const ChatHeader({
    super.key,
    required this.title,
    this.subtitle = '',
    this.icon,
  });

  static const avatarSize = 36.0;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    return Row(
      children: [
        icon != null
            ? Container(
                key: const Key('chat-header-avatar'),
                width: avatarSize,
                height: avatarSize,
                decoration: BoxDecoration(
                    color: c.mainSelectedBg, shape: BoxShape.circle),
                child: Icon(icon, size: 20, color: c.main),
              )
            : personAvatar(title, avatarSize,
                key: const Key('chat-header-avatar')),
        const SizedBox(width: 10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(title,
                  key: const Key('chat-header-title'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                      color: c.textPrimary,
                      fontSize: 17.5,
                      fontWeight: FontWeight.w600,
                      height: 1.2)),
              if (subtitle.isNotEmpty)
                Text(subtitle,
                    key: const Key('chat-header-subtitle'),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                        color: c.textSecondary, fontSize: 12.5, height: 1.2)),
            ],
          ),
        ),
      ],
    );
  }
}
