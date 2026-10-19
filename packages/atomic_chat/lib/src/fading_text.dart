import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';

/// Text that arrives in pieces, each piece fading in as it lands: the answer
/// of a model while it is written.
class FadingText extends StatefulWidget {
  /// The pieces, in order, with the moment each arrived.
  final List<(String, DateTime)> chunks;
  final TextStyle style;
  final Duration fade;

  /// The clock the arrival times are read against; replaceable for a test.
  final DateTime Function() now;

  const FadingText({
    super.key,
    required this.chunks,
    required this.style,
    this.fade = const Duration(milliseconds: 350),
    this.now = DateTime.now,
  });

  @override
  State<FadingText> createState() => _FadingTextState();
}

class _FadingTextState extends State<FadingText>
    with SingleTickerProviderStateMixin {
  late final Ticker _ticker = createTicker((_) {
    // One last redraw once everything has faded in, then rest.
    setState(() {});
    if (_settled) _ticker.stop();
  });

  bool get _settled {
    if (widget.chunks.isEmpty) return true;
    return widget.now().difference(widget.chunks.last.$2) > widget.fade;
  }

  @override
  void didUpdateWidget(FadingText old) {
    super.didUpdateWidget(old);
    if (!_ticker.isActive) _ticker.start();
  }

  @override
  void initState() {
    super.initState();
    _ticker.start();
  }

  @override
  void dispose() {
    _ticker.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final now = widget.now();
    final base = widget.style.color ?? DefaultTextStyle.of(context).style.color;
    return Text.rich(
      TextSpan(
        style: widget.style,
        children: [
          for (final (text, at) in widget.chunks)
            TextSpan(
              text: text,
              style: TextStyle(
                color: base?.withValues(
                  alpha: (base.a *
                          (now.difference(at).inMicroseconds /
                              widget.fade.inMicroseconds))
                      .clamp(0.0, base.a),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
