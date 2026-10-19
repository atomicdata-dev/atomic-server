import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/stroke_data.dart';
import '../models/canvas_entry.dart';
import '../gallery/canvas_store.dart';
import '../atomic/atomic_client.dart';
import 'canvas_painter.dart';
import 'fan_helpers.dart';
import 'thumbnail.dart';
import '../widgets/bottom_toolbar.dart';
import '../widgets/fan_overlay.dart';
import '../widgets/history_scrubber.dart';
import '../theme.dart';

/// Android re-registers the back callback when the window resizes, which
/// looks like a back press. Ignore those for a beat after metrics change.
@visibleForTesting
bool ignorePopFromRotation(DateTime? lastMetricsChange, DateTime now) =>
    lastMetricsChange != null &&
    now.difference(lastMetricsChange) < const Duration(milliseconds: 600);

class InfiniteCanvas extends StatefulWidget {
  final CanvasEntry canvas;
  final CanvasStore store;
  final VoidCallback onClose;
  final VoidCallback onNewCanvas;

  const InfiniteCanvas({
    super.key,
    required this.canvas,
    required this.store,
    required this.onClose,
    required this.onNewCanvas,
  });

  @override
  State<InfiniteCanvas> createState() => _InfiniteCanvasState();
}

class _InfiniteCanvasState extends State<InfiniteCanvas>
    with WidgetsBindingObserver {
  // ── Viewport ────────────────────────────────────────────────────────────────
  double _scale = 1.0;
  Offset _offset = Offset.zero;

  /// True until the initial zoom-to-fit has been applied. Suppresses painting
  /// the first frame at the wrong scale.
  bool _pendingInitialFit = false;

  // ── Zoom-to-fit toggle ──────────────────────────────────────────────────────
  double? _savedScale;
  Offset? _savedOffset;

  // ── Zoom scrub ──────────────────────────────────────────────────────────────
  bool _isZoomMode = false;
  double _zoomScrubStartScale = 1.0;
  double _zoomScrubAccumDx = 0.0;
  Offset _zoomScrubCanvasCenter = Offset.zero;

  // ── Strokes ─────────────────────────────────────────────────────────────────
  late List<StrokeData> _strokes;
  StrokeData? _currentStroke;

  // ── History ─────────────────────────────────────────────────────────────────
  // Not `final`: rebuilt by `_applyStrokesFromStore` every time a remote change
  // lands (now that live sync actually delivers them), so it is reassigned, not
  // just mutated — a `late final` here threw LateInitializationError on the
  // second remote update and left the canvas a white screen.
  late List<HistoryAction> _allActions;
  int _actionIndex = 0;
  final List<DiscardedBranch> _discardedBranches = [];
  bool _isHistoryMode = false;
  double _historyIndex = 0.0;
  DiscardedBranch? _previewBranch;
  List<StrokeData>? _scrubPreviewStrokes;
  double _scrubStartIndex = 0.0;
  double _scrubAccumDx = 0.0;

  /// Loro oplog versions (oldest → newest) when history was created on another device.
  List<List<int>> _loroVersionIds = [];
  List<List<StrokeData>> _loroStrokeStates = [];
  bool _useLoroHistory = false;

  // ── Tool ────────────────────────────────────────────────────────────────────
  bool _eraserMode = false;
  bool _erasing = false; // true while eraser drag is active
  Color _penColor = const Color(0xFF000000);
  Color _prevColor = const Color(0xFFE63946);
  double _penWidth = 10.0;
  double _prevWidth = 3.0;

  // ── Fan ─────────────────────────────────────────────────────────────────────
  FanType? _fanType;
  Offset _fanButtonCenter = Offset.zero;
  Offset _fanDragOffset = Offset.zero;
  Color? _hoveredColor;
  double? _hoveredWidth;

  // ── Peek hint ───────────────────────────────────────────────────────────────
  Timer? _peekTimer;
  bool _isPeeking = false;

  // ── Pointer ─────────────────────────────────────────────────────────────────
  final Map<int, Offset> _activePointers = {};
  Offset? _panStart;
  Offset? _panOffsetStart;
  double? _pinchStartDist;
  double? _pinchStartScale;
  Offset? _pinchStartMidpoint;
  Offset? _pinchStartOffset;
  Offset? _mmPanStart;
  Offset? _mmOffsetStart;

  bool get _canUndo => _actionIndex > 0;
  bool get _canRedo => _actionIndex < _allActions.length;
  bool get _fanOpen => _fanType != null;
  Offset _toCanvas(Offset s) => (s - _offset) / _scale;

  List<StrokeData> get _strokesToDraw {
    if (_previewBranch != null) return _previewBranch!.strokes;
    if (_scrubPreviewStrokes != null) return _scrubPreviewStrokes!;
    if (_isHistoryMode) return _strokes;
    return _strokes;
  }

  bool _watching = false;
  bool _loroCanUndo = false;
  bool _loroCanRedo = false;

  bool get _canUndoToolbar => _isHistoryMode ? _actionIndex > 0 : _loroCanUndo;
  bool get _canRedoToolbar =>
      _isHistoryMode ? _actionIndex < _allActions.length : _loroCanRedo;

  DateTime? _lastMetricsChange;
  Size? _lastSize;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _strokes = List.of(widget.canvas.strokes);
    _allActions = _strokes.map((s) => StrokeAdded(s) as HistoryAction).toList();
    _actionIndex = _allActions.length;
    _penColor = widget.canvas.penColor;
    _prevColor = widget.canvas.prevColor;
    if (_strokes.isNotEmpty) {
      _pendingInitialFit = true;
      WidgetsBinding.instance
          .addPostFrameCallback((_) => _zoomToFit(isInitial: true));
    }
    _startWatchingResource();
    _refreshUndoRedoState();
    _hydrateLoroHistory();
  }

  List<StrokeData> _parseStrokesJson(String jsonStr) {
    if (jsonStr.isEmpty || jsonStr == '[]') return const [];
    final decoded = jsonDecode(jsonStr);
    if (decoded is List) {
      return decoded
          .map((s) => StrokeData.fromJson(s as Map<String, dynamic>))
          .toList();
    }
    return const [];
  }

  /// Build scrub steps from the synced Loro oplog (tablet edits → phone history).
  Future<void> _hydrateLoroHistory() async {
    final id = widget.canvas.id;
    if (id.isEmpty) return;
    try {
      await AtomicClient.warmResourceHistory(id);
      final versions = await AtomicClient.getResourceHistory(id);
      if (versions.length < 2) return;

      final states = <List<StrokeData>>[];
      final ids = <List<int>>[];
      for (final v in versions.reversed) {
        final json = await AtomicClient.getResourceAtVersion(id, v.id);
        states.add(_parseStrokesJson(json));
        ids.add(v.id);
      }
      if (!mounted) return;
      setState(() {
        _loroStrokeStates = states;
        _loroVersionIds = ids;
        _useLoroHistory = true;
        _historyIndex = states.length.toDouble();
        _actionIndex = states.length;
      });
    } catch (e) {
      debugPrint('Loro history hydrate failed: $e');
    }
  }

  Future<void> _refreshUndoRedoState() async {
    final state = await widget.store.undoRedoState(widget.canvas);
    if (!mounted) return;
    setState(() {
      _loroCanUndo = state.canUndo;
      _loroCanRedo = state.canRedo;
    });
  }

  void _applyStrokesFromStore() {
    _strokes = List.of(widget.canvas.strokes);
    _allActions = _strokes.map((s) => StrokeAdded(s) as HistoryAction).toList();
    _actionIndex = _allActions.length;
  }

  @override
  void dispose() {
    _watching = false;
    _peekTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// Watch for remote changes to this canvas (live sync from other devices).
  void _startWatchingResource() {
    if (widget.canvas.id.isEmpty) return;
    _watching = true;
    Future(() async {
      while (_watching && mounted) {
        final result = await AtomicClient.watchResource(widget.canvas.id);
        if (!_watching || !mounted || result == 'timeout') continue;
        await widget.store.loadStrokes(widget.canvas);
        if (!mounted) break;
        final remote = widget.canvas.strokes;
        final remoteLen = remote.length;
        final localLen = _strokes.length;
        if (remoteLen != localLen ||
            (remoteLen > 0 &&
                remoteLen == localLen &&
                remote.last != _strokes.last)) {
          setState(() => _applyStrokesFromStore());
          await _refreshUndoRedoState();
          await _hydrateLoroHistory();
        }
      }
    });
  }

  @override
  void didChangeMetrics() {
    _lastMetricsChange = DateTime.now();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final size = MediaQuery.sizeOf(context);
    if (_lastSize != null && _lastSize != size) {
      _lastMetricsChange = DateTime.now();
    }
    _lastSize = size;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      widget.store.onCanvasChanged(widget.canvas, _strokes,
          isDarkMode: Theme.of(context).brightness == Brightness.dark,
          penColor: _penColor,
          prevColor: _prevColor);
    }
  }

  // ── History ─────────────────────────────────────────────────────────────────

  List<StrokeData> _replayActions(List<HistoryAction> actions) {
    final result = <StrokeData>[];
    for (final action in actions) {
      switch (action) {
        case StrokeAdded a:
          result.add(a.stroke);
        case StrokesDeleted d:
          for (final i in d.sortedIndices.reversed) {
            if (i < result.length) result.removeAt(i);
          }
        case StrokesReplaced r:
          for (final i in r.indices.reversed) {
            if (i < result.length) result.removeAt(i);
          }
          for (int i = 0; i < r.indices.length; i++) {
            result.insert(r.indices[i].clamp(0, result.length), r.after[i]);
          }
      }
    }
    return result;
  }

  void _pushAction(HistoryAction action) {
    if (_actionIndex < _allActions.length) {
      final branchStrokes = _replayActions(_allActions);
      final branch = DiscardedBranch(
        id: DateTime.now().millisecondsSinceEpoch,
        fromIndex: _actionIndex,
        strokes: branchStrokes,
      );
      _discardedBranches.add(branch);
      renderThumbnail(branch.strokes,
              isDarkMode: Theme.of(context).brightness == Brightness.dark)
          .then((img) {
        if (mounted) setState(() => branch.thumbnail = img);
      });
      _allActions.removeRange(_actionIndex, _allActions.length);
    }
    _allActions.add(action);
    _actionIndex = _allActions.length;
    widget.store.onCanvasChanged(widget.canvas, _strokes,
        isDarkMode: Theme.of(context).brightness == Brightness.dark,
        penColor: _penColor,
        prevColor: _prevColor);
  }

  void _applyAction(HistoryAction action) {
    switch (action) {
      case StrokeAdded a:
        _strokes.add(a.stroke);
      case StrokesDeleted d:
        for (final i in d.sortedIndices.reversed) {
          _strokes.removeAt(i);
        }
      case StrokesReplaced r:
        for (final i in r.indices.reversed) {
          _strokes.removeAt(i);
        }
        for (int i = 0; i < r.indices.length; i++) {
          _strokes.insert(r.indices[i], r.after[i]);
        }
    }
  }

  void _reverseAction(HistoryAction action) {
    switch (action) {
      case StrokeAdded _:
        _strokes.removeLast();
      case StrokesDeleted d:
        for (int i = 0; i < d.sortedIndices.length; i++) {
          _strokes.insert(d.sortedIndices[i].clamp(0, _strokes.length),
              d.deletedStrokes[i]);
        }
      case StrokesReplaced r:
        for (final i in r.indices.reversed) {
          _strokes.removeAt(i);
        }
        for (int i = 0; i < r.indices.length; i++) {
          _strokes.insert(r.indices[i], r.before[i]);
        }
    }
  }

  void _undo() {
    if (_isHistoryMode) {
      if (!_canUndo) return;
      _actionIndex--;
      setState(() => _reverseAction(_allActions[_actionIndex]));
      return;
    }
    if (!_loroCanUndo) return;
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    Future(() async {
      final ok = await widget.store.undoCanvas(widget.canvas);
      if (!ok || !mounted) return;
      setState(() => _applyStrokesFromStore());
      await _refreshUndoRedoState();
      if (!mounted) return;
      widget.store.onCanvasChanged(widget.canvas, _strokes,
          isDarkMode: isDarkMode, penColor: _penColor, prevColor: _prevColor);
    });
  }

  void _redo() {
    if (_isHistoryMode) {
      if (!_canRedo) return;
      final action = _allActions[_actionIndex];
      _actionIndex++;
      setState(() => _applyAction(action));
      return;
    }
    if (!_loroCanRedo) return;
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    Future(() async {
      final ok = await widget.store.redoCanvas(widget.canvas);
      if (!ok || !mounted) return;
      setState(() => _applyStrokesFromStore());
      await _refreshUndoRedoState();
      if (!mounted) return;
      widget.store.onCanvasChanged(widget.canvas, _strokes,
          isDarkMode: isDarkMode, penColor: _penColor, prevColor: _prevColor);
    });
  }

  // ── Fan ─────────────────────────────────────────────────────────────────────

  void _onFanOpen(({FanType type, Offset center}) info) {
    _cancelPeek();
    setState(() {
      _fanType = info.type;
      _fanButtonCenter = info.center;
      _fanDragOffset = Offset.zero;
      _hoveredColor = null;
      _hoveredWidth = null;
    });
  }

  double get _fanScale => MediaQuery.of(context).size.width < 500 ? 0.65 : 1.0;

  void _onFanDrag(Offset delta) {
    setState(() {
      _fanDragOffset += delta;
      if (_fanType == FanType.color) {
        _hoveredColor = calculateHoveredColor(_fanDragOffset, scale: _fanScale);
      } else {
        _hoveredWidth = calculateHoveredWidth(_fanDragOffset, scale: _fanScale);
      }
    });
  }

  void _onFanClose() {
    if (_isPeeking) return;
    if (_fanType == FanType.color) {
      final picked = _hoveredColor;
      setState(() {
        if (picked != null) {
          _prevColor = _penColor;
          _penColor = picked;
        } else {
          final t = _penColor;
          _penColor = _prevColor;
          _prevColor = t;
        }
        _fanType = null;
        _hoveredColor = null;
        widget.store.onCanvasChanged(widget.canvas, _strokes,
            isDarkMode: Theme.of(context).brightness == Brightness.dark,
            penColor: _penColor,
            prevColor: _prevColor);
      });
    } else if (_fanType == FanType.width) {
      final picked = _hoveredWidth;
      setState(() {
        if (picked != null) {
          _prevWidth = _penWidth;
          _penWidth = picked;
        } else {
          final t = _penWidth;
          _penWidth = _prevWidth;
          _prevWidth = t;
        }
        _fanType = null;
        _hoveredWidth = null;
      });
    }
  }

  void _onColorTap() {
    setState(() {
      final t = _penColor;
      _penColor = _prevColor;
      _prevColor = t;
    });
    widget.store.onCanvasChanged(widget.canvas, _strokes,
        isDarkMode: Theme.of(context).brightness == Brightness.dark,
        penColor: _penColor,
        prevColor: _prevColor);
  }

  void _onWidthTap() => setState(() {
        final t = _penWidth;
        _penWidth = _prevWidth;
        _prevWidth = t;
      });

  // ── Peek hint ───────────────────────────────────────────────────────────────

  void _cancelPeek() {
    _peekTimer?.cancel();
    if (_isPeeking) {
      setState(() {
        _isPeeking = false;
        _fanType = null;
        _hoveredColor = null;
        _hoveredWidth = null;
        _isHistoryMode = false;
        _isZoomMode = false;
      });
    }
  }

  void _peekFan(FanType type, Offset center) {
    _cancelPeek();
    setState(() {
      _isPeeking = true;
      _fanType = type;
      _fanButtonCenter = center;
      _fanDragOffset = Offset.zero;
      _hoveredColor = null;
      _hoveredWidth = null;
    });
  }

  void _peekEnd() {
    if (!_isPeeking) return;
    setState(() {
      _isPeeking = false;
      _fanType = null;
      _hoveredColor = null;
      _hoveredWidth = null;
      _isHistoryMode = false;
      _isZoomMode = false;
    });
  }

  void _peekZoom() {
    _cancelPeek();
    setState(() {
      _isPeeking = true;
      _isZoomMode = true;
    });
  }

  void _peekHistory() {
    if (_allActions.isEmpty && !_useLoroHistory) return;
    _cancelPeek();
    setState(() {
      _isPeeking = true;
      _isHistoryMode = true;
      _historyIndex = _actionIndex.toDouble();
    });
  }

  // ── Zoom to fit ─────────────────────────────────────────────────────────────

  void _zoomToFit({bool isInitial = false}) {
    if (_strokes.isEmpty) {
      setState(() {
        _scale = 1.0;
        _offset = Offset.zero;
      });
      return;
    }

    if (!isInitial && _savedScale != null) {
      setState(() {
        _scale = _savedScale!;
        _offset = _savedOffset!;
        _savedScale = null;
        _savedOffset = null;
      });
      return;
    }

    _savedScale = _scale;
    _savedOffset = _offset;

    final strokes = _strokesToDraw;
    final size = (context.findRenderObject() as RenderBox).size;
    double minX = double.infinity, minY = double.infinity;
    double maxX = double.negativeInfinity, maxY = double.negativeInfinity;

    for (final stroke in strokes) {
      final half = stroke.strokeWidth / 2;
      for (final point in stroke.points) {
        minX = min(minX, point.dx - half);
        minY = min(minY, point.dy - half);
        maxX = max(maxX, point.dx + half);
        maxY = max(maxY, point.dy + half);
      }
    }

    final contentW = maxX - minX;
    final contentH = maxY - minY;
    if (contentW <= 0 && contentH <= 0) return;

    const padding = 40.0;
    final viewW = size.width - padding * 2;
    final viewH = size.height - padding * 2;
    if (viewW <= 0 || viewH <= 0) return;

    final s = min(viewW / contentW, viewH / contentH).clamp(0.05, 30.0);
    final cx = (minX + maxX) / 2;
    final cy = (minY + maxY) / 2;

    setState(() {
      _scale = s;
      _offset = Offset(size.width / 2 - cx * s, size.height / 2 - cy * s);
      _pendingInitialFit = false;
    });
  }

  void _onZoomScrubStart() {
    _savedScale = null;
    _savedOffset = null;
    _zoomScrubStartScale = _scale;
    _zoomScrubAccumDx = 0;
    final size = (context.findRenderObject() as RenderBox).size;
    _zoomScrubCanvasCenter = _toCanvas(Offset(size.width / 2, size.height / 2));
  }

  void _onZoomScrubDelta(double dx) {
    _zoomScrubAccumDx += dx;
    final size = (context.findRenderObject() as RenderBox).size;
    final screenCenter = Offset(size.width / 2, size.height / 2);
    final factor = pow(2, _zoomScrubAccumDx / 150).toDouble();
    final newScale = (_zoomScrubStartScale * factor).clamp(0.05, 30.0);
    setState(() {
      _scale = newScale;
      _offset = screenCenter - _zoomScrubCanvasCenter * newScale;
    });
  }

  void _onZoomScrubEnd() {}

  // ── History scrubber ────────────────────────────────────────────────────────

  void _onUndoPressStart() {
    _cancelPeek();
    setState(() {
      _isHistoryMode = true;
      _historyIndex = _actionIndex.toDouble();
      _scrubStartIndex = _historyIndex;
      _scrubAccumDx = 0;
    });
  }

  void _onUndoPanDelta(double dx) {
    _scrubAccumDx += dx;
    if (_useLoroHistory && _loroStrokeStates.isNotEmpty) {
      final total = _loroStrokeStates.length.toDouble();
      setState(() {
        _historyIndex = (_scrubStartIndex + (_scrubAccumDx / 300.0) * total)
            .clamp(0, total);
        final idx =
            _historyIndex.toInt().clamp(0, _loroStrokeStates.length - 1);
        _scrubPreviewStrokes = List.of(_loroStrokeStates[idx]);
      });
      return;
    }
    final total = _allActions.length.toDouble();
    setState(() {
      _historyIndex =
          (_scrubStartIndex + (_scrubAccumDx / 300.0) * total).clamp(0, total);
      _scrubPreviewStrokes =
          _replayActions(_allActions.take(_historyIndex.toInt()).toList());
    });
  }

  Future<void> _onUndoPanEnd() async {
    if (!_isHistoryMode) return;
    final pb = _previewBranch;
    if (pb != null) {
      final currentStrokes = _replayActions(_allActions);
      final newBranch = DiscardedBranch(
        id: DateTime.now().millisecondsSinceEpoch,
        fromIndex: _actionIndex,
        strokes: currentStrokes,
      );
      _discardedBranches.add(newBranch);
      renderThumbnail(newBranch.strokes,
              isDarkMode: Theme.of(context).brightness == Brightness.dark)
          .then((img) {
        if (mounted) setState(() => newBranch.thumbnail = img);
      });
      setState(() {
        _allActions.clear();
        _allActions.addAll(pb.strokes.map((s) => StrokeAdded(s)));
        _actionIndex = _allActions.length;
        _strokes.clear();
        _strokes.addAll(pb.strokes);
        _discardedBranches.remove(pb);
        _previewBranch = null;
        _scrubPreviewStrokes = null;
        _isHistoryMode = false;
      });
    } else if (_useLoroHistory && _loroVersionIds.isNotEmpty) {
      final idx = _historyIndex.toInt().clamp(0, _loroVersionIds.length - 1);
      final versionId = _loroVersionIds[idx];
      try {
        await AtomicClient.checkoutCanvasVersion(widget.canvas.id, versionId);
        await widget.store.loadStrokes(widget.canvas);
        if (!mounted) return;
        setState(() {
          _applyStrokesFromStore();
          _previewBranch = null;
          _scrubPreviewStrokes = null;
          _isHistoryMode = false;
        });
        await _refreshUndoRedoState();
      } catch (e) {
        debugPrint('Failed to apply Loro history version: $e');
      }
    } else {
      final idx = _historyIndex.toInt();
      setState(() {
        _actionIndex = idx;
        _strokes = _replayActions(_allActions.take(idx).toList());
        _previewBranch = null;
        _scrubPreviewStrokes = null;
        // Keep history mode if branches exist so user can tap one
        if (_discardedBranches.isEmpty) {
          _isHistoryMode = false;
        }
      });
      // Auto-dismiss after 3s if branches are showing
      if (_discardedBranches.isNotEmpty) {
        Future.delayed(const Duration(seconds: 3), () {
          if (mounted && _isHistoryMode) {
            setState(() => _isHistoryMode = false);
          }
        });
      }
      widget.store.onCanvasChanged(widget.canvas, _strokes,
          isDarkMode: Theme.of(context).brightness == Brightness.dark,
          penColor: _penColor,
          prevColor: _prevColor);
      widget.store.saveFullStrokeState(widget.canvas, _strokes);
    }
  }

  // ── Eraser ─────────────────────────────────────────────────────────────────

  final Set<int> _erasedDuringDrag = {};

  void _eraseAt(Offset canvasPoint) {
    final hitRadius = 15.0 / _scale;
    bool changed = false;
    for (int i = 0; i < _strokes.length; i++) {
      if (_erasedDuringDrag.contains(i)) continue;
      for (final pt in _strokes[i].points) {
        if ((pt - canvasPoint).distance <
            hitRadius + _strokes[i].strokeWidth / 2) {
          _erasedDuringDrag.add(i);
          changed = true;
          break;
        }
      }
    }
    if (changed) {
      // Show preview without the erased strokes
      final preview = <StrokeData>[];
      for (int i = 0; i < _strokes.length; i++) {
        if (!_erasedDuringDrag.contains(i)) preview.add(_strokes[i]);
      }
      setState(() => _scrubPreviewStrokes = preview);
    }
  }

  void _finishErase() {
    if (_erasedDuringDrag.isEmpty) return;
    final indices = _erasedDuringDrag.toList()..sort();
    final deleted = indices.map((i) => _strokes[i]).toList();
    _pushAction(StrokesDeleted(indices, deleted));
    final newStrokes = <StrokeData>[];
    for (int i = 0; i < _strokes.length; i++) {
      if (!_erasedDuringDrag.contains(i)) newStrokes.add(_strokes[i]);
    }
    _strokes = newStrokes;
    _scrubPreviewStrokes = null;
    _erasedDuringDrag.clear();
    setState(() {});
    widget.store.saveFullStrokeState(widget.canvas, _strokes);
  }

  // ── Scroll ──────────────────────────────────────────────────────────────────

  void _onPointerSignal(PointerSignalEvent event) {
    if (_fanOpen) return;
    if (event is PointerScrollEvent) {
      setState(() {
        final isZoom = HardwareKeyboard.instance.isControlPressed;
        if (isZoom) {
          final factor = (1.0 - event.scrollDelta.dy * 0.01).clamp(0.8, 1.25);
          final fc = _toCanvas(event.localPosition);
          _scale = (_scale * factor).clamp(0.05, 30.0);
          _offset = event.localPosition - fc * _scale;
        } else {
          _offset -= event.scrollDelta;
        }
      });
    } else if (event is PointerScaleEvent) {
      setState(() {
        final fc = _toCanvas(event.localPosition);
        _scale = (_scale * event.scale).clamp(0.05, 30.0);
        _offset = event.localPosition - fc * _scale;
      });
    }
  }

  // ── Touch ───────────────────────────────────────────────────────────────────

  /// Once a stylus is detected, finger touches become pan instead of draw.
  bool _penDetected = false;

  bool _isStylus(PointerEvent e) =>
      e.kind == PointerDeviceKind.stylus ||
      e.kind == PointerDeviceKind.invertedStylus;

  bool _shouldDraw(PointerDownEvent e) {
    if (_isStylus(e)) {
      _penDetected = true;
      return true;
    }
    if (e.kind == PointerDeviceKind.mouse) return true;
    // Finger: draw only if no pen has been detected
    if (e.kind == PointerDeviceKind.touch && !_penDetected) return true;
    return false;
  }

  void _onPointerDown(PointerDownEvent e) {
    if (_fanOpen && !_isPeeking) return;
    if (_isPeeking) _cancelPeek();
    if (e.buttons == kMiddleMouseButton) {
      _mmPanStart = e.localPosition;
      _mmOffsetStart = _offset;
      return;
    }

    _activePointers[e.pointer] = e.localPosition;

    if (_activePointers.length == 2) {
      setState(() => _currentStroke = null);
      _panStart = null;
      _panOffsetStart = null;
      final pts = _activePointers.values.toList();
      _pinchStartDist = (pts[0] - pts[1]).distance;
      _pinchStartScale = _scale;
      _pinchStartMidpoint = (pts[0] + pts[1]) / 2;
      _pinchStartOffset = _offset;
    } else if (_activePointers.length == 1) {
      if (_shouldDraw(e)) {
        if (_eraserMode) {
          _erasing = true;
          _eraseAt(_toCanvas(e.localPosition));
        } else {
          setState(() => _currentStroke = StrokeData(
                points: [_toCanvas(e.localPosition)],
                color: _penColor,
                strokeWidth: _penWidth,
              ));
        }
      } else {
        _panStart = e.localPosition;
        _panOffsetStart = _offset;
      }
    }
  }

  void _onPointerMove(PointerMoveEvent e) {
    if (_fanOpen && !_isPeeking) return;
    if (_mmPanStart != null && e.buttons == kMiddleMouseButton) {
      setState(
          () => _offset = _mmOffsetStart! + (e.localPosition - _mmPanStart!));
      return;
    }
    _activePointers[e.pointer] = e.localPosition;

    if (_activePointers.length >= 2 && _pinchStartDist != null) {
      final pts = _activePointers.values.toList();
      final dist = (pts[0] - pts[1]).distance;
      final mid = (pts[0] + pts[1]) / 2;
      final ns =
          (_pinchStartScale! * dist / _pinchStartDist!).clamp(0.05, 30.0);
      final cm =
          (_pinchStartMidpoint! - _pinchStartOffset!) / _pinchStartScale!;
      setState(() {
        _scale = ns;
        _offset = mid - cm * ns;
      });
    } else if (_activePointers.length == 1 && _erasing) {
      _eraseAt(_toCanvas(e.localPosition));
    } else if (_activePointers.length == 1 && _currentStroke != null) {
      final cp = _toCanvas(e.localPosition);
      if ((cp - _currentStroke!.points.last).distance > 2 / _scale) {
        setState(() => _currentStroke =
            _currentStroke!.copyWith(points: [..._currentStroke!.points, cp]));
      }
    } else if (_activePointers.length == 1 && _panStart != null) {
      setState(
          () => _offset = _panOffsetStart! + (e.localPosition - _panStart!));
    }
  }

  void _onPointerUp(PointerUpEvent e) {
    _mmPanStart = null;
    _mmOffsetStart = null;
    if (_erasing) {
      _erasing = false;
      _finishErase();
    }
    _activePointers.remove(e.pointer);

    if (_currentStroke != null && _activePointers.isEmpty) {
      final stroke = _currentStroke!;
      setState(() {
        _strokes.add(stroke);
        _currentStroke = null;
      });
      _pushAction(StrokeAdded(stroke));
      // Push stroke to Loro immediately (CRDT-friendly append)
      widget.store.pushStroke(widget.canvas, stroke).then((_) {
        if (mounted) _refreshUndoRedoState();
      });
    }
    if (_activePointers.length < 2) {
      _pinchStartDist = null;
      _pinchStartScale = null;
      _pinchStartMidpoint = null;
      _pinchStartOffset = null;
      if (_activePointers.length == 1) {
        _panStart = _activePointers.values.first;
        _panOffsetStart = _offset;
      }
    }
    if (_activePointers.isEmpty) {
      _panStart = null;
      _panOffsetStart = null;
    }
  }

  void _onPointerCancel(PointerCancelEvent e) {
    _activePointers.remove(e.pointer);
    setState(() => _currentStroke = null);
  }

  // ── Build ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop ||
            ignorePopFromRotation(_lastMetricsChange, DateTime.now())) {
          return;
        }
        widget.onClose();
      },
      child: Scaffold(
        backgroundColor: context.appColors.canvasBg,
        body: Stack(
          children: [
            Listener(
              onPointerDown: _onPointerDown,
              onPointerMove: _onPointerMove,
              onPointerUp: _onPointerUp,
              onPointerCancel: _onPointerCancel,
              onPointerSignal: _onPointerSignal,
              behavior: HitTestBehavior.opaque,
              child: Visibility(
                visible: !_pendingInitialFit,
                maintainSize: true,
                maintainAnimation: true,
                maintainState: true,
                child: CustomPaint(
                  painter: CanvasPainter(
                    strokes: _strokesToDraw,
                    currentStroke: _isHistoryMode ? null : _currentStroke,
                    scale: _scale,
                    offset: _offset,
                    isDarkMode: Theme.of(context).brightness == Brightness.dark,
                  ),
                  child: const SizedBox.expand(),
                ),
              ),
            ),
            if (_fanOpen)
              AnimatedOpacity(
                opacity: _isPeeking ? 0.7 : 1.0,
                duration: const Duration(milliseconds: 150),
                child: FanOverlay(
                  buttonCenter: _fanButtonCenter,
                  dragOffset: _fanDragOffset,
                  type: _fanType!,
                  hoveredColor: _hoveredColor,
                  hoveredWidth: _hoveredWidth,
                  canvasScale: _scale,
                  isDarkMode: Theme.of(context).brightness == Brightness.dark,
                ),
              ),
            if (_isHistoryMode)
              HistoryScrubberOverlay(
                actionIndex: _historyIndex.toInt(),
                totalActions: _useLoroHistory && _loroStrokeStates.isNotEmpty
                    ? _loroStrokeStates.length
                    : _allActions.length,
                branches: _discardedBranches,
                previewBranch: _previewBranch,
                onBranchHover: (b) => setState(() => _previewBranch = b),
                onBranchHoverEnd: () => setState(() => _previewBranch = null),
                onBranchTap: (b) {
                  _previewBranch = b;
                  _onUndoPanEnd();
                },
              ),
            Positioned(
              left: 0,
              right: 0,
              bottom: MediaQuery.of(context).viewPadding.bottom + 8,
              child: Center(
                child: BottomToolbar(
                  penColor: _penColor,
                  penWidth: _penWidth,
                  canUndo: _canUndoToolbar,
                  canRedo: _canRedoToolbar,
                  eraserMode: _eraserMode,
                  onEraserToggle: () =>
                      setState(() => _eraserMode = !_eraserMode),
                  onFanOpen: _onFanOpen,
                  onFanDrag: _onFanDrag,
                  onFanClose: _onFanClose,
                  onColorTap: _onColorTap,
                  onWidthTap: _onWidthTap,
                  onUndo: _undo,
                  onRedo: _redo,
                  onUndoPressStart: _onUndoPressStart,
                  onUndoPanDelta: _onUndoPanDelta,
                  onUndoPanEnd: _onUndoPanEnd,
                  onGallery: widget.onClose,
                  onNewCanvas: widget.onNewCanvas,
                  onZoomToFit: () => _zoomToFit(),
                  onZoomScrubStart: _onZoomScrubStart,
                  onZoomScrubDelta: _onZoomScrubDelta,
                  onZoomScrubEnd: _onZoomScrubEnd,
                  onPeek: _peekFan,
                  onPeekEnd: _peekEnd,
                  onPeekHistory: _peekHistory,
                  onPeekZoom: _peekZoom,
                  activeFan: _fanType,
                  historyMode: _isHistoryMode,
                  zoomMode: _isZoomMode,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
