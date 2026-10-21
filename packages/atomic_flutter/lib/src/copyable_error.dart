import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Error or diagnostic text a person can select and copy for a bug report:
/// [SelectableText] in the error colour (long-press / right-click gives the
/// platform's selection toolbar) plus a Copy button that puts the whole text
/// on the clipboard. Long texts start collapsed to [collapsedLines] with a
/// "Show more" toggle; the copy always takes the full text.
class ErrorText extends StatefulWidget {
  const ErrorText(
    this.text, {
    super.key,
    this.color,
    this.fontSize = 14,
    this.textAlign,
    this.showCopy = true,
    this.collapsedLines = 6,
    this.style,
  });

  final String text;

  /// Defaults to the theme's error colour.
  final Color? color;
  final double fontSize;
  final TextAlign? textAlign;
  final bool showCopy;
  final int collapsedLines;

  /// Merged over the default style (colour, size).
  final TextStyle? style;

  @override
  State<ErrorText> createState() => _ErrorTextState();
}

class _ErrorTextState extends State<ErrorText> {
  bool _expanded = false;
  bool _copied = false;
  Timer? _timer;

  bool get _long =>
      widget.text.length > 280 ||
      '\n'.allMatches(widget.text).length >= widget.collapsedLines;

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: widget.text));
    if (!mounted) return;
    setState(() => _copied = true);
    _timer?.cancel();
    _timer = Timer(const Duration(milliseconds: 1500), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    final color = widget.color ?? Theme.of(context).colorScheme.error;
    final collapsed = _long && !_expanded;
    final body = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        SelectableText(
          widget.text,
          textAlign: widget.textAlign,
          maxLines: collapsed ? widget.collapsedLines : null,
          style: TextStyle(color: color, fontSize: widget.fontSize)
              .merge(widget.style),
        ),
        if (_long)
          GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: () => setState(() => _expanded = !_expanded),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Text(_expanded ? 'Show less' : 'Show more',
                  style: TextStyle(
                      color: color,
                      fontSize: widget.fontSize - 1,
                      decoration: TextDecoration.underline)),
            ),
          ),
      ],
    );
    if (!widget.showCopy) return body;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: body),
        if (_copied)
          Padding(
            padding: const EdgeInsets.only(left: 8, top: 8),
            child: Text('Copied',
                style: TextStyle(color: color, fontSize: widget.fontSize - 1)),
          )
        else
          IconButton(
            icon: Icon(Icons.copy, size: 18, color: color),
            tooltip: 'Copy',
            onPressed: _copy,
            constraints: const BoxConstraints.tightFor(width: 36, height: 36),
            padding: EdgeInsets.zero,
          ),
      ],
    );
  }
}

/// Wraps an error panel so every plain [Text] in it can be selected too.
/// Only for error panels, never a whole app: it takes over drags.
class SelectableErrorPanel extends StatelessWidget {
  const SelectableErrorPanel({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) => SelectionArea(child: child);
}
