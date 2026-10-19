import 'dart:async';

import 'package:flutter/material.dart';

/// Keeps a page that another page covers from rebuilding while the keyboard
/// of the page on top animates. Every frame of that animation changes
/// `MediaQuery.viewInsets`, and a hidden page (the home with all its rows)
/// would rebuild each time for nothing. While the route is not the current one
/// the page sees the [MediaQueryData] it had when it was last on top, so
/// nothing below it is notified. When it is on top again it stays frozen a
/// moment longer, while the keyboard of the page that just left is closing.
///
/// (The route's secondary animation does not tell: a `MaterialPageRoute` has
/// none for routes that are not Material ones.) Must be built inside a
/// [ModalRoute].
class CoveredInsetsFreeze extends StatefulWidget {
  final Widget child;

  /// How long a page that is on top again keeps the insets it had.
  @visibleForTesting
  static const hold = Duration(milliseconds: 300);

  const CoveredInsetsFreeze({super.key, required this.child});

  @override
  State<CoveredInsetsFreeze> createState() => _CoveredInsetsFreezeState();
}

class _CoveredInsetsFreezeState extends State<CoveredInsetsFreeze> {
  MediaQueryData? _frozen;
  bool _holding = false;
  Timer? _release;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final current = ModalRoute.of(context)?.isCurrent ?? true;
    _release?.cancel();
    _release = null;
    if (!current) {
      _holding = true;
    } else if (_holding) {
      _release = Timer(CoveredInsetsFreeze.hold, () {
        if (mounted) setState(() => _holding = false);
      });
    }
  }

  @override
  void dispose() {
    _release?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // This builder is the only thing that follows the keyboard: it is tiny,
    // and [widget.child] is the same instance each time, so it is skipped.
    final child = widget.child;
    return Builder(builder: (context) {
      final live = MediaQuery.of(context);
      if (!_holding) {
        _frozen = null;
        return MediaQuery(data: live, child: child);
      }
      return MediaQuery(data: _frozen ??= live, child: child);
    });
  }
}
