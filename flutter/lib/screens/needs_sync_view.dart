import 'package:atomic_flutter/atomic_flutter.dart'
    show SyncGap, SyncText, syncColors, SyncTone, SyncToneColors;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../atomic/sync_failure.dart';

/// Size of the progress ring: the hero of the searching state.
const double kSyncHeroRing = 112;

/// "Sync your drive": this device has no drive yet. While [searching] the
/// progress indicator is the hero; on [failure] it becomes a calm warning.
class NeedsSyncView extends StatelessWidget {
  const NeedsSyncView({
    super.key,
    required this.searching,
    required this.onRetry,
    required this.onPair,
    required this.onPaste,
    required this.onBack,
    this.status,
    this.progress,
    this.syncing = false,
    this.count,
    this.failure,
  });

  final bool searching;

  /// A drive was found and is arriving (vs. still looking for it).
  final bool syncing;
  final String? status;

  /// 0..1 when known; null for indeterminate.
  final double? progress;
  final String? count;
  final SyncFailure? failure;
  final VoidCallback onRetry;
  final VoidCallback onPair;
  final VoidCallback onPaste;
  final VoidCallback onBack;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final failed = !searching && failure != null;
    return Scaffold(
      backgroundColor: c.pageBg,
      appBar: AppBar(
        backgroundColor: c.pageBg,
        elevation: 0,
        scrolledUnderElevation: 0,
        leading: IconButton(
          key: const ValueKey('needsSync-back'),
          icon: const Icon(Icons.arrow_back),
          tooltip: 'Back',
          onPressed: onBack,
        ),
      ),
      body: SafeArea(
        child: LayoutBuilder(builder: (context, box) {
          return SingleChildScrollView(
            physics: const ClampingScrollPhysics(),
            padding: const EdgeInsets.symmetric(horizontal: SyncGap.xl),
            child: ConstrainedBox(
              constraints: BoxConstraints(minHeight: box.maxHeight),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 420),
                  child: IntrinsicHeight(
                    child: Column(
                      key: const ValueKey('needsSync'),
                      children: [
                        const Spacer(flex: 2),
                        failed
                            ? const _FailureHero()
                            : _SearchHero(progress: progress),
                        const SizedBox(height: SyncGap.xl),
                        Text(
                          failed
                              ? failure!.title
                              : (syncing
                                  ? 'Syncing your drive…'
                                  : 'Looking for your devices'),
                          key: const ValueKey('needsSync-title'),
                          textAlign: TextAlign.center,
                          style: TextStyle(
                              fontSize: 22,
                              fontWeight: FontWeight.w700,
                              color: c.textPrimary),
                        ),
                        const SizedBox(height: SyncGap.s),
                        if (failed)
                          Text(failure!.summary,
                              key: const ValueKey('needsSync-summary'),
                              textAlign: TextAlign.center,
                              style: SyncText.body(c)
                                  .copyWith(color: c.textSecondary))
                        else ...[
                          Text(
                            [
                              status ??
                                  'Searching the network and your account',
                              if (count != null) count!,
                            ].join(' · '),
                            key: const ValueKey('needsSync-status'),
                            textAlign: TextAlign.center,
                            style: SyncText.bodyStrong(c),
                          ),
                          const SizedBox(height: SyncGap.s),
                          Text(
                            'Open Atomic on a device that has your drive and '
                            'keep it on the same network.',
                            maxLines: 2,
                            textAlign: TextAlign.center,
                            style: SyncText.body(c)
                                .copyWith(color: c.textSecondary),
                          ),
                        ],
                        if (failed && failure!.details.isNotEmpty)
                          _Details(lines: failure!.details),
                        const Spacer(flex: 2),
                        ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 360),
                          child: Wrap(
                            alignment: WrapAlignment.center,
                            spacing: SyncGap.m,
                            runSpacing: SyncGap.m,
                            children: [
                              if (failed)
                                _small(
                                  context,
                                  key: const ValueKey('needsSync-retry'),
                                  primary: true,
                                  icon: Icons.refresh,
                                  label: 'Try again',
                                  onPressed: onRetry,
                                ),
                              _small(
                                context,
                                key: const ValueKey('needsSync-pair'),
                                primary: !failed,
                                icon: Icons.qr_code_scanner,
                                label: 'Pair with QR',
                                onPressed: onPair,
                              ),
                              _small(
                                context,
                                key: const ValueKey('needsSync-paste'),
                                text: true,
                                icon: Icons.content_paste,
                                label: 'Paste node ID',
                                onPressed: onPaste,
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(height: SyncGap.xl),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          );
        }),
      ),
    );
  }

  /// A compact action: 40 dp high, 14 sp, 12 dp radius, as wide as its label.
  Widget _small(
    BuildContext context, {
    required Key key,
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
    bool primary = false,
    bool text = false,
  }) {
    final c = syncColors(context);
    const shape = RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)));
    const size = Size(0, 40);
    const textStyle = TextStyle(fontSize: 14, fontWeight: FontWeight.w600);
    final iconW = Icon(icon, size: 18);
    final labelW = Text(label);
    if (text) {
      return TextButton.icon(
        key: key,
        onPressed: onPressed,
        icon: iconW,
        label: labelW,
        style: TextButton.styleFrom(
            minimumSize: size,
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            shape: shape,
            foregroundColor: c.main,
            textStyle: textStyle),
      );
    }
    if (primary) {
      return FilledButton.icon(
        key: key,
        onPressed: onPressed,
        icon: iconW,
        label: labelW,
        style: FilledButton.styleFrom(
            minimumSize: size,
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            shape: shape,
            backgroundColor: c.main,
            textStyle: textStyle),
      );
    }
    return FilledButton.tonalIcon(
      key: key,
      onPressed: onPressed,
      icon: iconW,
      label: labelW,
      style: FilledButton.styleFrom(
          minimumSize: size,
          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
          shape: shape,
          textStyle: textStyle),
    );
  }
}

/// The progress hero: a 112 dp ring around the sync icon, with soft pulses
/// behind it. With reduced motion: a static full ring and a small bar.
class _SearchHero extends StatefulWidget {
  const _SearchHero({this.progress});
  final double? progress;

  @override
  State<_SearchHero> createState() => _SearchHeroState();
}

class _SearchHeroState extends State<_SearchHero>
    with SingleTickerProviderStateMixin {
  late final AnimationController _pulse = AnimationController(
      vsync: this, duration: const Duration(milliseconds: 1600));

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (MediaQuery.disableAnimationsOf(context)) {
      _pulse.stop();
    } else if (!_pulse.isAnimating) {
      _pulse.repeat();
    }
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final reduced = MediaQuery.disableAnimationsOf(context);
    final ring = SizedBox(
      key: const ValueKey('needsSync-hero'),
      width: kSyncHeroRing,
      height: kSyncHeroRing,
      child: Stack(alignment: Alignment.center, children: [
        SizedBox.expand(
          child: CircularProgressIndicator(
            strokeWidth: 6,
            value: reduced ? (widget.progress ?? 1.0) : widget.progress,
            backgroundColor: c.bg2,
            color: c.main,
            semanticsLabel: 'Looking for your devices',
          ),
        ),
        Icon(Icons.sync, size: 48, color: c.main),
      ]),
    );
    return Column(mainAxisSize: MainAxisSize.min, children: [
      SizedBox(
        width: 168,
        height: 168,
        child: Stack(alignment: Alignment.center, children: [
          if (!reduced)
            RepaintBoundary(
              child: CustomPaint(
                size: const Size(168, 168),
                painter: _PulsePainter(_pulse, c.main),
              ),
            ),
          ring,
        ]),
      ),
      if (reduced) ...[
        const SizedBox(height: SyncGap.m),
        SizedBox(
          width: 120,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              key: const ValueKey('needsSync-bar'),
              minHeight: 4,
              color: c.main,
              backgroundColor: c.bg2,
            ),
          ),
        ),
      ],
    ]);
  }
}

/// Three rings expanding from the ring's edge and fading out.
class _PulsePainter extends CustomPainter {
  _PulsePainter(this.t, this.color) : super(repaint: t);
  final Animation<double> t;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final centre = size.center(Offset.zero);
    const r0 = kSyncHeroRing / 2;
    final r1 = size.width / 2;
    for (var i = 0; i < 3; i++) {
      final p = (t.value + i / 3) % 1.0;
      final paint = Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.5
        ..color = color.withValues(alpha: 0.28 * (1 - p));
      canvas.drawCircle(centre, r0 + (r1 - r0) * p, paint);
    }
  }

  @override
  bool shouldRepaint(_PulsePainter old) => old.color != color;
}

class _FailureHero extends StatelessWidget {
  const _FailureHero();

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    final tone = SyncTone.warning.color(c);
    return Container(
      key: const ValueKey('needsSync-hero'),
      width: kSyncHeroRing,
      height: kSyncHeroRing,
      decoration: BoxDecoration(
          shape: BoxShape.circle, color: tone.withValues(alpha: 0.14)),
      child: Icon(Icons.sync_problem, size: 48, color: tone),
    );
  }
}

/// A collapsed "Details" row; opens a selectable panel with the raw lines.
class _Details extends StatefulWidget {
  const _Details({required this.lines});
  final List<String> lines;

  @override
  State<_Details> createState() => _DetailsState();
}

class _DetailsState extends State<_Details> {
  bool _open = false;

  @override
  Widget build(BuildContext context) {
    final c = syncColors(context);
    return Padding(
      padding: const EdgeInsets.only(top: SyncGap.l),
      child: Column(children: [
        TextButton.icon(
          key: const ValueKey('needsSync-details'),
          onPressed: () => setState(() => _open = !_open),
          icon: Icon(_open ? Icons.expand_less : Icons.expand_more, size: 18),
          label: const Text('Details'),
          style: TextButton.styleFrom(
              minimumSize: const Size(0, 40),
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              foregroundColor: c.textSecondary,
              textStyle: const TextStyle(fontSize: 14)),
        ),
        AnimatedSize(
          duration: const Duration(milliseconds: 180),
          alignment: Alignment.topCenter,
          child: !_open
              ? const SizedBox(width: double.infinity)
              : Container(
                  key: const ValueKey('needsSync-details-panel'),
                  width: double.infinity,
                  padding: const EdgeInsets.all(SyncGap.m),
                  decoration: BoxDecoration(
                    color: c.bg1,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: c.bg2),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      SelectableText(
                        widget.lines.join('\n'),
                        style: SyncText.mono(c)
                            .copyWith(fontSize: 12, color: c.textSecondary),
                      ),
                      Align(
                        alignment: Alignment.centerRight,
                        child: TextButton.icon(
                          key: const ValueKey('needsSync-copy'),
                          onPressed: () => Clipboard.setData(
                              ClipboardData(text: widget.lines.join('\n'))),
                          icon: const Icon(Icons.copy, size: 16),
                          label: const Text('Copy'),
                          style: TextButton.styleFrom(
                              minimumSize: const Size(0, 40),
                              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                              foregroundColor: c.main,
                              textStyle: const TextStyle(fontSize: 14)),
                        ),
                      ),
                    ],
                  ),
                ),
        ),
      ]),
    );
  }
}
