import { useDarkMode } from '@helpers/useDarkMode';
import {
  blobHashHex,
  canvas,
  DEFAULT_STROKE_WIDTH,
  ELEMENT_HAIRLINE_WIDTH,
  enableLoro,
  hexToBytes,
  isBlobSubject,
  server,
  parseCanvasStrokes,
  ResourceEvents,
  strokeToJson,
  type CanvasStroke,
  type Resource,
} from '@tomic/lib';
import type { ResourcePageProps } from '@views/ResourcePage';
import { useCallback, useEffect, useRef, useState } from 'react';
import styled from 'styled-components';
import {
  drawCanvasStrokes,
  drawSelectionHalo,
  drawSelectionOverlay,
  HANDLE_RADIUS,
  onCanvasImageLoaded,
  primeCanvasImage,
  screenToCanvas,
  setCanvasImageResolver,
} from './canvas-draw';
import {
  elementBounds,
  lassoSelect,
  TEXT_FONT_FAMILY,
  TEXT_LINE_HEIGHT,
  transformSelection,
  unionBounds,
} from './canvas-elements';
import { useStore, type Store } from '@tomic/react';
import { FilePickerDialog } from '@components/forms/FilePicker/FilePickerDialog';
import { useUpload } from '../../hooks/useUpload';
import { imageMimeTypes } from '../../helpers/filetypes';
import { errorHandler } from '../../handlers/errorHandler';
import {
  FaCircleInfo,
  FaEraser,
  FaFont,
  FaImage,
  FaPalette,
  FaPen,
  FaRotateLeft,
  FaRotateRight,
  FaTrash,
  FaVectorSquare,
} from 'react-icons/fa6';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { FanOverlay } from './FanOverlay';
import {
  hoveredColor as resolveHoveredColor,
  hoveredWidth as resolveHoveredWidth,
} from './fan-helpers';
import { currentWheelSessionStartedAt } from '@helpers/wheelSession';
import {
  archiveBranch,
  bootstrapUndoSteps,
  cloneStrokes,
  loadCanvasHistory,
  saveCanvasHistory,
  scrubIndexFor,
  SCRUB_DRAG_THRESHOLD,
  stacksAt,
  strokesEqual,
  timelineOf,
  UNDO_STACK_LIMIT,
  type DiscardedBranch,
} from './history-helpers';
import { HistoryScrubOverlay } from './HistoryScrubOverlay';
import { RemoteCursors, useCanvasPresence } from './CanvasPresence';

/**
 * Pixels of horizontal drag on the zoom button that double (or halve) the
 * canvas scale. Matches Flutter's `_onZoomScrubDelta` ratio.
 */
const ZOOM_SCRUB_PX_PER_2X = 150;
const ZOOM_MIN = 0.05;
const ZOOM_MAX = 30;
/** Hints that belong to a held button linger this long after release. */
const HINT_LINGER_MS = 100;

/**
 * Pen-color swatches and stroke widths — match Flutter `fan_helpers.dart` so
 * a canvas drawn on one device renders identically on the other. Stored as
 * 0xAARRGGBB ints so the wire format also matches Flutter's `StrokeData`.
 */
const PEN_COLORS = [
  0xff000000, 0xffe63946, 0xfff4a261, 0xff2a9d8f, 0xff457b9d, 0xff9b5de5,
];
/**
 * Eraser hit-radius in screen pixels — multiplied by `1 / scale` at the
 * call site so the visual radius is constant regardless of zoom.
 */
const ERASE_SCREEN_RADIUS = 15;

type Tool = 'pen' | 'eraser' | 'lasso' | 'text';

/** Finger wobble below this still counts as a tap on the color/size buttons. */
const FAN_DRAG_THRESHOLD = 10;

/** Screen-pixel radius around a selection corner that grabs the scale handle. */
const HANDLE_HIT_RADIUS = HANDLE_RADIUS + 14;
/** Font size of a new text element, in screen pixels at the current zoom. */
const NEW_TEXT_SCREEN_SIZE = 28;
const FILE_BLOB_PROPERTY = 'https://atomicdata.dev/properties/blob';
const PEN_SEEN_KEY = 'atomic-canvas-pen-seen';
const MIN_SCALE = 0.05;
const MAX_SCALE = 30;

/** The bytes this device already has for a File resource, else the server's
 *  download URL: something an `<img>` can load. */
async function resolveImageUrl(
  store: Store,
  subject: string,
): Promise<string | undefined> {
  const file = await store.getResource(subject);
  const blob = file.get(FILE_BLOB_PROPERTY);
  const clientDb = store.getClientDb?.();

  if (typeof blob === 'string' && isBlobSubject(blob) && clientDb) {
    const hash = blobHashHex(blob);
    const bytes = hash ? await clientDb.getBlob(hexToBytes(hash)) : null;

    if (bytes) return URL.createObjectURL(new Blob([bytes as BlobPart]));
  }

  const url = file.get(server.properties.downloadUrl);

  return typeof url === 'string' ? url : undefined;
}

function loadImageSize(url: string): Promise<{ w: number; h: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image();

    img.onload = () => resolve({ w: img.naturalWidth, h: img.naturalHeight });
    img.onerror = () => reject(new Error('Could not read that image'));
    img.src = url;
  });
}

type TextEdit = {
  /** Index of the element being edited, null for a new one. */
  index: number | null;
  x: number;
  y: number;
  size: number;
  color: number;
  text: string;
};

type TransformGesture = {
  pointerId: number;
  mode: 'move' | 'scale';
  start: [number, number];
  anchor: [number, number];
  corner: [number, number];
  base: CanvasStroke[];
  selection: number[];
  moved: boolean;
};

function readPenSeen(): boolean {
  try {
    return localStorage.getItem(PEN_SEEN_KEY) === '1';
  } catch {
    return false;
  }
}

type ScrubState = {
  pointerId: number;
  startX: number;
  /** Snapshot of the full history timeline, captured at gesture start:
   *  `[...undoStack, currentStrokes, ...redoStack (oldest-first)]`. */
  timeline: CanvasStroke[][];
  /** Index the scrub started at — the current state's timeline position. */
  startIndex: number;
  /** most recent index resolved during the gesture */
  currentIndex: number;
  dragged: boolean;
};

/** The branch tile under the given screen point, if any. Used while the
 *  undo button owns the pointer capture — the tiles never receive the
 *  events themselves, so hit-test by coordinates. */
function branchIdAtPoint(x: number, y: number): string | null {
  for (const el of document.elementsFromPoint(x, y)) {
    const id = (el as HTMLElement).dataset?.branchId;

    if (id) return id;
  }

  return null;
}

/** True when the keyboard event originated from a text field or editor. */
function isEditableKeyboardTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.closest('input, textarea, select')) return true;

  for (let el: HTMLElement | null = target; el; el = el.parentElement) {
    if (el.isContentEditable) return true;
  }

  return false;
}

export const CanvasPage: React.FC<ResourcePageProps> = ({ resource }) => {
  const [darkMode] = useDarkMode();
  const store = useStore();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Live pointer sharing over the drive presence channel: broadcast our
  // pointer's world position, render other sessions' pointers.
  const { cursors, broadcastPointer, clearPointer } = useCanvasPresence(
    resource.subject,
  );

  const [strokes, setStrokes] = useState<CanvasStroke[]>([]);
  const [currentStroke, setCurrentStroke] = useState<CanvasStroke | null>(null);
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [penColor, setPenColor] = useState(PEN_COLORS[0]);
  const [prevColor, setPrevColor] = useState(PEN_COLORS[1]);
  const [penWidth, setPenWidth] = useState(DEFAULT_STROKE_WIDTH);
  const [prevWidth, setPrevWidth] = useState(3);
  const [tool, setTool] = useState<Tool>('pen');
  const eraserMode = tool === 'eraser';
  const [selection, setSelection] = useState<number[]>([]);
  const [lassoPath, setLassoPath] = useState<[number, number][] | null>(null);
  const [textEdit, setTextEdit] = useState<TextEdit | null>(null);
  // A pen / stylus has been seen on this device: one finger then pans
  // instead of drawing, because the pen is the drawing tool.
  const [penDetected, setPenDetected] = useState(readPenSeen);
  const { upload } = useUpload(resource);
  const [imagePickerOpen, setImagePickerOpen] = useState(false);
  const textFieldRef = useRef<HTMLTextAreaElement>(null);
  // Pixels the toolbar is lifted so the app's bottom navigation bar never
  // covers it (see the effect below).
  const [toolbarLift, setToolbarLift] = useState(0);
  const toolbarRef = useRef<HTMLDivElement>(null);
  const textOpen = textEdit !== null;

  // Wheel events (pan AND zoom) are ignored if the current wheel session
  // started before the canvas was mounted — that's how we detect macOS
  // momentum-scroll tails carried over from the previous view. See
  // `helpers/wheelSession.ts`. Reset on resource change (= canvas-to-canvas
  // navigation) so each canvas starts gated.
  // Infinity until the mount effect below stamps a real time, so any wheel
  // session that started before this canvas was visible is gated. `performance.now()`
  // during render trips `react/purity`.
  const canvasMountedAtRef = useRef(Number.POSITIVE_INFINITY);

  // Custom cursor preview: a circle the size of the next stroke at the
  // current zoom (`penWidth × scale`). Null while not hovering, or while
  // drawing / erasing / panning (those have their own visual feedback).
  // Position is relative to the canvas container.
  const [cursorPos, setCursorPos] = useState<{ x: number; y: number } | null>(
    null,
  );

  // Persistent undo / redo stacks (per-canvas, localStorage-backed).
  // Loro's `UndoManager` is session-scoped — once the page reloads it
  // starts empty and the undo button greys out even with prior strokes
  // present. Instead, store snapshots of `strokeData` before each user
  // edit and persist them. On mount we either load from `localStorage` or
  // bootstrap from `getLoroHistory()` so a canvas you've never opened on
  // this device still has its full pre-existing history available.
  const undoStackRef = useRef<CanvasStroke[][]>([]);
  const redoStackRef = useRef<CanvasStroke[][]>([]);
  /** Whether the Loro-history bootstrap has already run for this canvas on
   *  this device. Persisted so it runs at most once — see the mount effect. */
  const bootstrappedRef = useRef(false);
  /** In-flight guard: holds a promise while a bootstrap operation is running.
   *  Waiters join the in-flight work instead of bailing. */
  const bootstrappingPromiseRef = useRef<Promise<void> | null>(null);

  // Discarded branch leaves — versions abandoned by editing after an undo,
  // recoverable from the overlay while holding the undo button. Kept in a
  // ref (gesture handlers) and mirrored to state (overlay rendering).
  const branchesRef = useRef<DiscardedBranch[]>([]);
  const [branches, setBranches] = useState<DiscardedBranch[]>([]);

  // Fan state — populated while the user holds + drags the colour or
  // width button. `fanType` null means no fan is open. The overlay reads
  // these refs through React state to render previews.
  const [fanType, setFanType] = useState<'color' | 'width' | null>(null);
  const [fanButtonCenter, setFanButtonCenter] = useState<{
    x: number;
    y: number;
  } | null>(null);
  const [fanDragOffset, setFanDragOffset] = useState<{ x: number; y: number }>({
    x: 0,
    y: 0,
  });
  const [fanHoveredColor, setFanHoveredColor] = useState<number | null>(null);
  const [fanHoveredWidth, setFanHoveredWidth] = useState<number | null>(null);
  const [fanPeek, setFanPeek] = useState(false);
  // Pointer-ID owning the open fan gesture, plus whether the drag has
  // crossed the tap-vs-drag threshold.
  const fanGestureRef = useRef<{
    pointerId: number;
    type: 'color' | 'width';
    buttonCenter: { x: number; y: number };
    /** Where the press landed; a tap is measured against this, not the centre. */
    start: { x: number; y: number };
    dragged: boolean;
  } | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | undefined>();
  const [canUndo, setCanUndo] = useState(false);
  const [canRedo, setCanRedo] = useState(false);

  // History scrub preview — when set, the canvas paints these instead of the
  // live `strokes`. Matches Flutter's drag-to-scrub gesture on the undo
  // button.
  const [previewStrokes, setPreviewStrokes] = useState<CanvasStroke[] | null>(
    null,
  );
  const scrubRef = useRef<ScrubState | null>(null);

  // Version overlay lifecycle: 'held' while the pointer is down on the
  // undo button, 'grace' for a few seconds after a scrub release (branch
  // tiles stay hoverable / clickable), 'closed' otherwise.
  const [overlayMode, setOverlayMode] = useState<'closed' | 'held' | 'grace'>(
    'closed',
  );
  const graceTimerRef = useRef<number | undefined>(undefined);
  // Timeline position shown in the overlay's progress bar.
  const [scrubStep, setScrubStep] = useState(0);
  const [scrubTotal, setScrubTotal] = useState(1);
  // Branch tile currently under the pointer. Ref mirrors state so the
  // pointer-up handler reads the value set during the same gesture.
  const [hoveredBranchId, setHoveredBranchId] = useState<string | null>(null);
  const hoveredBranchIdRef = useRef<string | null>(null);

  // Eraser drag state: indices of strokes the current drag has marked for
  // deletion. Materialized as one atomic `replaceListItems` on release so the
  // UndoManager records the whole erase as one undo step.
  const erasedIndicesRef = useRef<Set<number>>(new Set());

  const scaleRef = useRef(scale);
  const offsetRef = useRef(offset);
  const strokesRef = useRef(strokes);
  const currentStrokeRef = useRef(currentStroke);
  const previewStrokesRef = useRef(previewStrokes);
  const eraserModeRef = useRef(eraserMode);
  const toolRef = useRef(tool);
  const selectionRef = useRef(selection);
  /** Element count when the selection was made; a different count means the
   *  strokes changed underneath it, so the indices no longer mean the same. */
  const selectionLengthRef = useRef(0);
  const lassoPathRef = useRef(lassoPath);
  const lassoPointerRef = useRef<number | null>(null);
  const transformRef = useRef<TransformGesture | null>(null);
  const textEditRef = useRef<TextEdit | null>(null);
  const penDetectedRef = useRef(penDetected);
  const penContactRef = useRef(false);
  const touchesRef = useRef(new Map<number, { x: number; y: number }>());
  const pinchRef = useRef<{
    dist: number;
    scale: number;
    wx: number;
    wy: number;
  } | null>(null);
  /** True from the second finger down until every finger is up, so the
   *  fingers left over after a pinch never start a stroke. */
  const gestureActiveRef = useRef(false);
  const isPanningRef = useRef(false);
  const panStartRef = useRef<{
    x: number;
    y: number;
    ox: number;
    oy: number;
  } | null>(null);
  const drawingPointerRef = useRef<number | null>(null);
  const erasingPointerRef = useRef<number | null>(null);
  const isPanModeRef = useRef(false);
  const [panMode, setPanMode] = useState<'idle' | 'ready' | 'panning'>('idle');

  // Fit the drawing to the viewport once per canvas, when its strokes
  // first arrive — but never after the user has taken over the view
  // (drawn, panned, or zoomed), so a late Loro sync or their own first
  // stroke on an empty canvas can't yank the viewport out from under
  // them.
  const initialFitSubjectRef = useRef<string | null>(null);
  const viewTouchedRef = useRef(false);

  // Track Space key for pan mode (Space+drag = pan, matching Figma/Photoshop).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.code === 'Space') {
        if (isEditableKeyboardTarget(e.target)) return;
        // preventDefault on EVERY keydown, including auto-repeats: a held
        // Space fires repeat events, and an unprevented repeat performs
        // the browser default (scroll / button activation) while the user
        // is mid-pan.
        e.preventDefault();

        if (!e.repeat) {
          isPanModeRef.current = true;
          setPanMode('ready');
        }
      }
    };

    const onKeyUp = (e: KeyboardEvent) => {
      if (e.code === 'Space') {
        if (isEditableKeyboardTarget(e.target)) return;
        isPanModeRef.current = false;
        setPanMode('idle');
      }
    };

    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keyup', onKeyUp);

    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keyup', onKeyUp);
    };
  }, []);

  scaleRef.current = scale;
  offsetRef.current = offset;
  strokesRef.current = strokes;
  currentStrokeRef.current = currentStroke;
  previewStrokesRef.current = previewStrokes;
  eraserModeRef.current = eraserMode;
  toolRef.current = tool;
  selectionRef.current = selection;
  lassoPathRef.current = lassoPath;
  textEditRef.current = textEdit;
  penDetectedRef.current = penDetected;

  const reloadStrokesFromResource = useCallback((res: Resource) => {
    setStrokes(parseCanvasStrokes(res.get(canvas.properties.strokeData)));
  }, []);

  const persistTimerRef = useRef<number | undefined>(undefined);

  const writeHistoryNow = useCallback(() => {
    if (persistTimerRef.current !== undefined) {
      window.clearTimeout(persistTimerRef.current);
      persistTimerRef.current = undefined;
    }

    saveCanvasHistory(resource.subject, {
      undo: undoStackRef.current,
      redo: redoStackRef.current,
      branches: branchesRef.current,
      bootstrapped: bootstrappedRef.current,
    });
  }, [resource.subject]);

  /** Persist the undo / redo stacks + branches under the canvas subject.
   *  Serializing up to 400 full stroke snapshots is the expensive part of an
   *  undo, so it runs once things settle instead of on every press; it is
   *  flushed when the page is hidden or the canvas closes. */
  const persistHistory = useCallback(() => {
    if (persistTimerRef.current !== undefined) {
      window.clearTimeout(persistTimerRef.current);
    }

    persistTimerRef.current = window.setTimeout(writeHistoryNow, 500);
  }, [writeHistoryNow]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') writeHistoryNow();
    };

    window.addEventListener('pagehide', writeHistoryNow);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.removeEventListener('pagehide', writeHistoryNow);
      document.removeEventListener('visibilitychange', onVisibility);

      if (persistTimerRef.current !== undefined) {
        writeHistoryNow();
      }
    };
  }, [writeHistoryNow]);

  useEffect(() => {
    // Reset the wheel-session gate baseline on mount and on canvas-to-
    // canvas navigation, so we can detect "this wheel session began
    // before this canvas was visible".
    canvasMountedAtRef.current = performance.now();
    viewTouchedRef.current = false;

    reloadStrokesFromResource(resource);

    // Load the persistent undo state for THIS canvas.
    const stored = loadCanvasHistory(resource.subject);
    undoStackRef.current = stored.undo;
    redoStackRef.current = stored.redo;
    branchesRef.current = stored.branches;
    bootstrappedRef.current = stored.bootstrapped;
    bootstrappingPromiseRef.current = null;
    setBranches(stored.branches);
    setCanUndo(stored.undo.length > 0);
    setCanRedo(stored.redo.length > 0);

    let cancelled = false;

    if (
      !stored.bootstrapped &&
      stored.undo.length === 0 &&
      stored.redo.length === 0
    ) {
      // First open on this device: this canvas may still have undoable
      // history in its Loro oplog. Reconstructing it means materializing
      // every version, which is far too expensive to spend on opening a
      // canvas nobody may ever undo — so only ask the cheap question here
      // ("is there anything older than now?") and leave the reconstruction
      // to `ensureUndoStack`, on the first undo or scrub.
      //
      // Still async: `hasPriorLoroVersions()` reads the oplog, which is
      // empty until the Loro WASM has loaded. Reading it synchronously left
      // the undo button permanently disabled on a cold page load.
      (async () => {
        try {
          await enableLoro();
        } catch {
          return;
        }

        if (cancelled) return;

        // Don't override the state of steps made while the WASM loaded.
        if (
          undoStackRef.current.length > 0 ||
          redoStackRef.current.length > 0
        ) {
          return;
        }

        if (resource.hasPriorLoroVersions()) {
          setCanUndo(true);
        }
      })();
    }

    const unsub = resource.on(ResourceEvents.LocalChange, prop => {
      if (
        prop === canvas.properties.strokeData ||
        prop === '' ||
        prop === undefined
      ) {
        reloadStrokesFromResource(resource);
      }
    });

    return () => {
      cancelled = true;
      unsub();
    };
  }, [resource, reloadStrokesFromResource]);

  const paint = useCallback(() => {
    const el = canvasRef.current;
    const container = containerRef.current;

    if (!el || !container) {
      return;
    }

    const ctx = el.getContext('2d');

    if (!ctx) {
      return;
    }

    const dpr = window.devicePixelRatio || 1;
    const w = container.clientWidth;
    const h = container.clientHeight;

    if (el.width !== w * dpr || el.height !== h * dpr) {
      el.width = w * dpr;
      el.height = h * dpr;
      el.style.width = `${w}px`;
      el.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    ctx.clearRect(0, 0, w, h);
    drawCanvasStrokes(
      ctx,
      // Show the scrub preview while the user is dragging the undo button;
      // otherwise the live strokes. The current in-progress stroke is
      // hidden during scrub (we're showing a historical state).
      previewStrokesRef.current ?? strokesRef.current,
      previewStrokesRef.current ? null : currentStrokeRef.current,
      scaleRef.current,
      offsetRef.current.x,
      offsetRef.current.y,
      darkMode,
    );

    const list = previewStrokesRef.current ?? strokesRef.current;
    const selected = unionBounds(
      selectionRef.current
        .filter(i => list[i])
        .map(i => elementBounds(list[i])),
    );

    drawSelectionHalo(
      ctx,
      selectionRef.current.filter(i => list[i]).map(i => list[i]),
      scaleRef.current,
      offsetRef.current.x,
      offsetRef.current.y,
      '#3b82f6',
    );
    drawSelectionOverlay(
      ctx,
      lassoPathRef.current,
      selected,
      scaleRef.current,
      offsetRef.current.x,
      offsetRef.current.y,
      '#3b82f6',
    );
  }, [darkMode]);

  useEffect(() => {
    paint();
  }, [
    paint,
    strokes,
    currentStroke,
    scale,
    offset,
    previewStrokes,
    selection,
    lassoPath,
  ]);

  // The canvas area is sized from the viewport height the browser reports,
  // which on tablets and phones can be taller than what is visible. Measure
  // the real overlap with the navigation bar instead of trusting that sum.
  useEffect(() => {
    const area = containerRef.current;

    if (!area) return;

    const update = () => {
      const nav = document.querySelector('div[aria-label="navigation"]');
      const a = area.getBoundingClientRect();
      const n = nav?.getBoundingClientRect();
      // Only a bar along the bottom edge can cover the toolbar.
      const covers = n && n.top > a.top + a.height / 2;

      setToolbarLift(covers ? Math.max(0, Math.round(a.bottom - n.top)) : 0);

      // Popups that sit above the toolbar follow its height (it may wrap).
      const bar = toolbarRef.current;

      if (bar) {
        area.style.setProperty(
          '--canvas-toolbar-h',
          `${Math.round(bar.getBoundingClientRect().height)}px`,
        );
      }
    };

    update();

    const ro = new ResizeObserver(update);
    const later = window.setTimeout(update, 500);

    ro.observe(area);

    if (toolbarRef.current) ro.observe(toolbarRef.current);

    window.addEventListener('resize', update);
    window.visualViewport?.addEventListener('resize', update);

    return () => {
      ro.disconnect();
      window.clearTimeout(later);
      window.removeEventListener('resize', update);
      window.visualViewport?.removeEventListener('resize', update);
    };
  }, []);

  // Focus the text field only after the tap that opened it has finished: the
  // browser moves focus to the canvas as the press ends, which would blur a
  // field focused any earlier and close it empty.
  useEffect(() => {
    if (!textOpen) return;

    const id = window.setTimeout(() => textFieldRef.current?.focus(), 60);

    return () => window.clearTimeout(id);
  }, [textOpen]);

  // An image element's `src` is an uploaded File resource. Resolve it to the
  // bytes this device already has, else the server's download URL.
  useEffect(() => {
    setCanvasImageResolver(subject => resolveImageUrl(store, subject));

    return () => setCanvasImageResolver(undefined);
  }, [store]);

  // Images decode asynchronously; repaint when one is ready.
  useEffect(() => onCanvasImageLoaded(paint), [paint]);

  // Drop a selection once the strokes changed under it (an undo, a remote
  // edit): its indices would point at other elements.
  useEffect(() => {
    if (
      selectionRef.current.length > 0 &&
      strokes.length !== selectionLengthRef.current
    ) {
      setSelection([]);
    }
  }, [strokes]);

  useEffect(() => {
    const container = containerRef.current;

    if (!container) {
      return;
    }

    const ro = new ResizeObserver(() => paint());
    ro.observe(container);

    return () => ro.disconnect();
  }, [paint]);

  // ──────────────── Undo / Redo / scrub-history (Flutter parity) ───────────
  //
  // The undo button is a three-in-one gesture, mirroring Flutter's canvas:
  //
  // * tap → single-step undo;
  // * press + horizontal drag → scrub the local history timeline
  //   (`[...undoStack, current, ...redoStack]`) with live preview; release
  //   rebalances the stacks around the landed index, so the future stays
  //   redoable;
  // * press, drag over a version thumbnail in the overlay, release →
  //   restore that discarded branch (the current tip is archived as a new
  //   branch first, so nothing is ever lost).
  //
  // See `planning/canvas-undo-consolidation.md` for the design history.

  /** Snapshot the current strokes onto the undo stack. Called before every
   *  user-visible edit (push stroke, erase). The user is diverging from
   *  any redo future, so the abandoned future's furthest state is archived
   *  as a recoverable branch leaf before the redo stack is cleared. */
  const pushUndoSnapshot = useCallback(
    (preEditStrokes: CanvasStroke[]) => {
      if (redoStackRef.current.length > 0) {
        // The bottom of the redo stack is the furthest-forward state — the
        // tip the user originally walked back from.
        branchesRef.current = archiveBranch(
          branchesRef.current,
          redoStackRef.current[0],
        );
        setBranches(branchesRef.current);
        redoStackRef.current = [];
      }

      undoStackRef.current.push(cloneStrokes(preEditStrokes));

      if (undoStackRef.current.length > UNDO_STACK_LIMIT) {
        undoStackRef.current.shift();
      }

      persistHistory();
      setCanUndo(true);
      setCanRedo(false);
    },
    [persistHistory],
  );

  const applyHistoricalStrokes = useCallback(
    async (target: CanvasStroke[]) => {
      setSaving(true);
      setSaveError(undefined);

      try {
        await enableLoro();
        resource.replaceListItems(
          canvas.properties.strokeData,
          target.map(strokeToJson),
        );
        await resource.save();
      } catch (e) {
        setSaveError(e instanceof Error ? e.message : String(e));
      } finally {
        setSaving(false);
      }
    },
    [resource],
  );

  /** Reconstruct undo steps from this canvas's Loro history, for a canvas
   *  whose history was made on another device. Materializing every version
   *  is expensive, so it happens on first contact with the undo control —
   *  hovering it, pressing it, or Ctrl+Z — rather than on open. Runs at most
   *  once per canvas per device; cheap to call on every interaction after.
   *
   *  Async: awaits Loro WASM readiness before reading the oplog, so it's
   *  safe to call from the keyboard shortcut (Ctrl+Z) even on a cold page
   *  load. */
  const ensureUndoStack = useCallback(async () => {
    if (bootstrappedRef.current) return;

    if (bootstrappingPromiseRef.current) {
      await bootstrappingPromiseRef.current;

      return;
    }

    const targetSubject = resource.subject;
    const promise = (async () => {
      try {
        await enableLoro();

        if (resource.subject !== targetSubject) {
          return;
        }

        const versions = resource.getLoroHistory();
        const current = parseCanvasStrokes(
          resource.get(canvas.properties.strokeData),
        );
        const steps = bootstrapUndoSteps(
          versions.map(v => v.propvals.get(canvas.properties.strokeData)),
          current,
        );

        // If the user started drawing before this completed, prepend the Loro
        // history (which is older) to the existing undo stack instead of
        // discarding their edits. Filter out duplicates: if pushUndoSnapshot
        // already captured a state that's also in the Loro history, don't add
        // it twice.
        if (undoStackRef.current.length > 0) {
          const filtered = steps.filter(
            step =>
              !undoStackRef.current.some(existing =>
                strokesEqual(existing, step),
              ),
          );

          undoStackRef.current = [...filtered, ...undoStackRef.current].slice(
            -UNDO_STACK_LIMIT,
          );
        } else {
          undoStackRef.current = steps;
        }

        // Record the attempt even when it found nothing, so a canvas with no
        // recoverable history doesn't pay for the walk again on the next open.
        bootstrappedRef.current = true;
        setCanUndo(undoStackRef.current.length > 0);
        persistHistory();
      } finally {
        bootstrappingPromiseRef.current = null;
      }
    })();

    bootstrappingPromiseRef.current = promise;
    await promise;
  }, [resource, persistHistory]);

  const handleUndo = useCallback(async () => {
    await ensureUndoStack();

    if (undoStackRef.current.length === 0) return;

    const target = undoStackRef.current.pop()!;
    redoStackRef.current.push(cloneStrokes(strokesRef.current));

    if (redoStackRef.current.length > UNDO_STACK_LIMIT) {
      redoStackRef.current.shift();
    }

    persistHistory();
    setCanUndo(undoStackRef.current.length > 0);
    setCanRedo(true);

    await applyHistoricalStrokes(target);
  }, [applyHistoricalStrokes, persistHistory, ensureUndoStack]);

  const handleRedo = useCallback(async () => {
    if (redoStackRef.current.length === 0) return;

    const target = redoStackRef.current.pop()!;
    undoStackRef.current.push(cloneStrokes(strokesRef.current));

    if (undoStackRef.current.length > UNDO_STACK_LIMIT) {
      undoStackRef.current.shift();
    }

    persistHistory();
    setCanUndo(true);
    setCanRedo(redoStackRef.current.length > 0);

    await applyHistoricalStrokes(target);
  }, [applyHistoricalStrokes, persistHistory]);

  const closeOverlay = useCallback(() => {
    if (graceTimerRef.current !== undefined) {
      window.clearTimeout(graceTimerRef.current);
      graceTimerRef.current = undefined;
    }

    setOverlayMode('closed');
    hoveredBranchIdRef.current = null;
    setHoveredBranchId(null);
  }, []);

  /** Keep the overlay interactive for a moment after a scrub release so
   *  branch thumbnails can still be hovered / clicked (Flutter parity). */
  const openGraceWindow = useCallback(() => {
    if (graceTimerRef.current !== undefined) {
      window.clearTimeout(graceTimerRef.current);
    }

    setOverlayMode('grace');
    graceTimerRef.current = window.setTimeout(() => {
      graceTimerRef.current = undefined;
      setOverlayMode('closed');
      hoveredBranchIdRef.current = null;
      setHoveredBranchId(null);
      setPreviewStrokes(null);
    }, HINT_LINGER_MS);
  }, []);

  // Clear a pending grace timer on unmount / canvas navigation.
  useEffect(() => closeOverlay, [closeOverlay, resource.subject]);

  /** Restore a discarded branch leaf: archive the current timeline tip as
   *  a new branch (so switching is itself recoverable), make the restore
   *  undoable, and write the branch's strokes to the resource. */
  const restoreBranch = useCallback(
    async (branchId: string) => {
      const branch = branchesRef.current.find(b => b.id === branchId);

      if (!branch) return;

      const current = strokesRef.current;
      // The timeline tip is the furthest-forward state: the bottom of the
      // redo stack if the user has undone, otherwise the current strokes.
      const tip =
        redoStackRef.current.length > 0 ? redoStackRef.current[0] : current;

      let nextBranches = branchesRef.current.filter(b => b.id !== branchId);

      if (!strokesEqual(tip, branch.strokes)) {
        nextBranches = archiveBranch(nextBranches, tip);
      }

      branchesRef.current = nextBranches;
      setBranches(nextBranches);

      redoStackRef.current = [];
      undoStackRef.current.push(cloneStrokes(current));

      if (undoStackRef.current.length > UNDO_STACK_LIMIT) {
        undoStackRef.current.shift();
      }

      persistHistory();
      setCanUndo(true);
      setCanRedo(false);

      await applyHistoricalStrokes(branch.strokes);
    },
    [applyHistoricalStrokes, persistHistory],
  );

  const onUndoPointerDown = useCallback(
    async (e: React.PointerEvent) => {
      if (!canUndo && !canRedo && branchesRef.current.length === 0) return;

      e.preventDefault();
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);

      await ensureUndoStack();

      const timeline = timelineOf(
        { undo: undoStackRef.current, redo: redoStackRef.current },
        strokesRef.current,
      );
      const startIndex = undoStackRef.current.length;

      scrubRef.current = {
        pointerId: e.pointerId,
        startX: e.clientX,
        timeline,
        startIndex,
        currentIndex: startIndex,
        dragged: false,
      };

      // Press-and-hold immediately shows the version overlay (peek).
      if (graceTimerRef.current !== undefined) {
        window.clearTimeout(graceTimerRef.current);
        graceTimerRef.current = undefined;
      }

      setScrubStep(startIndex);
      setScrubTotal(timeline.length);
      setOverlayMode('held');
    },
    [canUndo, canRedo, ensureUndoStack],
  );

  const onUndoPointerMove = useCallback((e: React.PointerEvent) => {
    const s = scrubRef.current;
    if (!s || s.pointerId !== e.pointerId) return;

    // Dragging over a version thumbnail previews that branch and takes
    // precedence over the scrub position.
    const branchId = branchIdAtPoint(e.clientX, e.clientY);

    if (branchId !== hoveredBranchIdRef.current) {
      hoveredBranchIdRef.current = branchId;
      setHoveredBranchId(branchId);
    }

    if (branchId) {
      const branch = branchesRef.current.find(b => b.id === branchId);

      if (branch) {
        s.dragged = true;
        setPreviewStrokes(branch.strokes);

        return;
      }
    }

    const dx = e.clientX - s.startX;
    if (!s.dragged && Math.abs(dx) < SCRUB_DRAG_THRESHOLD) return;
    s.dragged = true;

    const idx = scrubIndexFor(s.startIndex, dx, s.timeline.length);

    if (idx !== s.currentIndex) {
      s.currentIndex = idx;
      setScrubStep(idx);
    }

    setPreviewStrokes(idx === s.startIndex ? null : (s.timeline[idx] ?? null));
  }, []);

  const onUndoPointerUp = useCallback(
    async (e: React.PointerEvent) => {
      const s = scrubRef.current;
      if (!s || s.pointerId !== e.pointerId) return;
      (e.currentTarget as HTMLElement).releasePointerCapture?.(e.pointerId);
      scrubRef.current = null;

      const pickedBranch = hoveredBranchIdRef.current;
      hoveredBranchIdRef.current = null;
      setHoveredBranchId(null);
      setPreviewStrokes(null);

      // Released on a version thumbnail → restore that branch.
      if (pickedBranch) {
        closeOverlay();
        await restoreBranch(pickedBranch);

        return;
      }

      // No drag → tap = single-step undo.
      if (!s.dragged) {
        closeOverlay();
        await handleUndo();

        return;
      }

      if (s.currentIndex !== s.startIndex) {
        // Land on the scrubbed-to state: rebalance the stacks around the
        // new position. The rest of the timeline stays reachable — undo
        // and redo keep walking it, nothing is truncated.
        const next = stacksAt(s.timeline, s.currentIndex);
        undoStackRef.current = next.undo;
        redoStackRef.current = next.redo;
        persistHistory();
        setCanUndo(next.undo.length > 0);
        setCanRedo(next.redo.length > 0);

        await applyHistoricalStrokes(s.timeline[s.currentIndex]);
      }

      // Keep the overlay around briefly if there are branches to pick.
      if (branchesRef.current.length > 0) {
        openGraceWindow();
      } else {
        closeOverlay();
      }
    },
    [
      applyHistoricalStrokes,
      closeOverlay,
      handleUndo,
      openGraceWindow,
      persistHistory,
      restoreBranch,
    ],
  );

  const onUndoPointerCancel = useCallback(
    (e: React.PointerEvent) => {
      const s = scrubRef.current;
      if (!s || s.pointerId !== e.pointerId) return;
      scrubRef.current = null;
      setPreviewStrokes(null);
      closeOverlay();
    },
    [closeOverlay],
  );

  /** Hover / click on branch tiles during the post-release grace window. */
  const onBranchHover = useCallback(
    (id: string | null) => {
      // Hovering a tile keeps the panel open; leaving it restarts the short wait.
      if (id) {
        if (graceTimerRef.current !== undefined) {
          window.clearTimeout(graceTimerRef.current);
          graceTimerRef.current = undefined;
        }
      } else {
        openGraceWindow();
      }

      hoveredBranchIdRef.current = id;
      setHoveredBranchId(id);
      const branch = id
        ? branchesRef.current.find(b => b.id === id)
        : undefined;
      setPreviewStrokes(branch ? branch.strokes : null);
    },
    [openGraceWindow],
  );

  const onBranchPick = useCallback(
    async (id: string) => {
      setPreviewStrokes(null);
      closeOverlay();
      await restoreBranch(id);
    },
    [closeOverlay, restoreBranch],
  );

  // ──────────────── Save / draw the actual stroke ──────────────────────────

  const pushStrokeToServer = async (
    stroke: CanvasStroke,
    preEditStrokes: CanvasStroke[],
  ) => {
    pushUndoSnapshot(preEditStrokes);
    setSaving(true);
    setSaveError(undefined);

    try {
      await enableLoro();
      resource.pushListItem(canvas.properties.strokeData, strokeToJson(stroke));
      await resource.save();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  // ──────────────── Eraser: drag across strokes deletes them ───────────────
  //
  // Identical hit-test to Flutter's `_eraseAt`: per stroke, any point within
  // `(15 + width/2)` screen pixels of the cursor marks the stroke. All
  // marked strokes flush as one atomic `replaceListItems` on release so the
  // UndoManager records the erase as a single undo step.

  const eraseAt = useCallback((canvasX: number, canvasY: number) => {
    const hitRadius = ERASE_SCREEN_RADIUS / scaleRef.current;
    const erased = erasedIndicesRef.current;
    const strokesNow = strokesRef.current;
    let changed = false;

    for (let i = 0; i < strokesNow.length; i++) {
      if (erased.has(i)) continue;
      const stroke = strokesNow[i];
      const radius = hitRadius + stroke.width / 2 / scaleRef.current;

      for (const [px, py] of stroke.path) {
        if (Math.hypot(canvasX - px, canvasY - py) < radius) {
          erased.add(i);
          changed = true;
          break;
        }
      }
    }

    if (changed) {
      // Optimistic visual: paint the canvas without the erased strokes.
      // We DON'T mutate the resource until pointer-up; this is preview
      // only. Reusing `previewStrokes` keeps `paint()` consistent.
      const preview = strokesNow.filter((_, i) => !erased.has(i));
      setPreviewStrokes(preview);
    }
  }, []);

  const finishErase = useCallback(async () => {
    if (erasedIndicesRef.current.size === 0) {
      setPreviewStrokes(null);

      return;
    }

    const preEdit = strokesRef.current;
    const remaining = preEdit.filter(
      (_, i) => !erasedIndicesRef.current.has(i),
    );
    erasedIndicesRef.current = new Set();
    setPreviewStrokes(null);

    pushUndoSnapshot(preEdit);

    setSaving(true);
    setSaveError(undefined);

    try {
      await enableLoro();
      resource.replaceListItems(
        canvas.properties.strokeData,
        remaining.map(strokeToJson),
      );
      await resource.save();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }, [pushUndoSnapshot, resource]);

  // ──────────────── Pointer flow: pan / draw / erase ───────────────────────

  /**
   * Update / clear the cursor preview. Called from both pointerenter and
   * pointermove so the preview appears the moment the cursor enters the
   * canvas, not only after the first move.
   */
  const trackCursorForPreview = useCallback((e: React.PointerEvent) => {
    if (
      e.pointerType === 'touch' ||
      isPanningRef.current ||
      drawingPointerRef.current !== null ||
      erasingPointerRef.current !== null ||
      toolRef.current !== 'pen'
    ) {
      setCursorPos(null);

      return;
    }

    const container = containerRef.current;

    if (!container) return;

    const rect = container.getBoundingClientRect();
    setCursorPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
  }, []);

  // ──────────────── Selection: lasso, move, scale, delete ──────────────────

  /** Write a whole new element list as one undoable step. */
  const commitReplace = useCallback(
    async (next: CanvasStroke[], pre: CanvasStroke[]) => {
      pushUndoSnapshot(pre);
      setSaving(true);
      setSaveError(undefined);

      try {
        await enableLoro();
        resource.replaceListItems(
          canvas.properties.strokeData,
          next.map(strokeToJson),
        );
        await resource.save();
      } catch (err) {
        setSaveError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [pushUndoSnapshot, resource],
  );

  const selectElements = useCallback((indices: number[], length: number) => {
    selectionLengthRef.current = length;
    selectionRef.current = indices;
    setSelection(indices);
  }, []);

  const deleteSelection = useCallback(() => {
    const picked = new Set(selectionRef.current);

    if (picked.size === 0) return;

    const pre = strokesRef.current;
    const next = pre.filter((_, i) => !picked.has(i));

    selectElements([], next.length);
    setStrokes(next);
    void commitReplace(next, pre);
  }, [commitReplace, selectElements]);

  /** Recolor the selected strokes and text as one undoable step. */
  const recolorSelection = useCallback(
    (color: number) => {
      const picked = new Set(selectionRef.current);

      if (picked.size === 0) return;

      const pre = strokesRef.current;
      const next = pre.map((el, i) =>
        picked.has(i) && el.kind !== 'image' ? { ...el, color } : el,
      );

      if (next.every((el, i) => el === pre[i])) return;

      setStrokes(next);
      void commitReplace(next, pre);
    },
    [commitReplace],
  );

  /** The topmost element under a point (a tap), or -1. */
  const hitTestAt = (x: number, y: number): number => {
    const reach = 12 / scaleRef.current;
    const list = strokesRef.current;

    for (let i = list.length - 1; i >= 0; i--) {
      const el = list[i];

      if (el.kind) {
        const b = elementBounds(el);

        if (x >= b.minX && x <= b.maxX && y >= b.minY && y <= b.maxY) return i;

        continue;
      }

      const radius = reach + el.width / 2;

      if (el.path.some(([px, py]) => Math.hypot(x - px, y - py) < radius)) {
        return i;
      }
    }

    return -1;
  };

  const startLassoOrTransform = (
    e: React.PointerEvent,
    x: number,
    y: number,
  ) => {
    const el = canvasRef.current;

    if (!el) return;

    const list = strokesRef.current;
    const picked = selectionRef.current.filter(i => list[i]);
    const bounds = unionBounds(picked.map(i => elementBounds(list[i])));

    if (bounds) {
      const rect = el.getBoundingClientRect();
      const s = scaleRef.current;
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const corners: [number, number][] = [
        [bounds.minX, bounds.minY],
        [bounds.maxX, bounds.minY],
        [bounds.minX, bounds.maxY],
        [bounds.maxX, bounds.maxY],
      ];
      const cornerIndex = corners.findIndex(
        ([cx, cy]) =>
          Math.hypot(
            sx - (cx * s + offsetRef.current.x),
            sy - (cy * s + offsetRef.current.y),
          ) <= HANDLE_HIT_RADIUS,
      );
      const pad = 8 / s;
      const inside =
        x >= bounds.minX - pad &&
        x <= bounds.maxX + pad &&
        y >= bounds.minY - pad &&
        y <= bounds.maxY + pad;

      if (cornerIndex >= 0 || inside) {
        transformRef.current = {
          pointerId: e.pointerId,
          mode: cornerIndex >= 0 ? 'scale' : 'move',
          start: [x, y],
          anchor: corners[3 - Math.max(cornerIndex, 0)],
          corner: corners[Math.max(cornerIndex, 0)],
          base: list,
          selection: picked,
          moved: false,
        };
        el.setPointerCapture(e.pointerId);

        return;
      }
    }

    selectElements([], list.length);
    lassoPointerRef.current = e.pointerId;
    setLassoPath([[x, y]]);
    el.setPointerCapture(e.pointerId);
  };

  /** The element list a transform gesture currently describes. */
  const transformedStrokes = (
    g: TransformGesture,
    x: number,
    y: number,
  ): CanvasStroke[] => {
    if (g.mode === 'move') {
      return transformSelection(
        g.base,
        g.selection,
        1,
        0,
        0,
        x - g.start[0],
        y - g.start[1],
      );
    }

    const dx = g.corner[0] - g.anchor[0];
    const dy = g.corner[1] - g.anchor[1];
    const len2 = dx * dx + dy * dy || 1;
    const factor = Math.min(
      50,
      Math.max(0.05, ((x - g.anchor[0]) * dx + (y - g.anchor[1]) * dy) / len2),
    );

    return transformSelection(
      g.base,
      g.selection,
      factor,
      g.anchor[0],
      g.anchor[1],
      0,
      0,
    );
  };

  // ──────────────── Text tool ──────────────────────────────────────────────

  const commitText = async () => {
    const edit = textEditRef.current;

    if (!edit) return;

    textEditRef.current = null;
    setTextEdit(null);
    setPreviewStrokes(null);

    const text = edit.text.replace(/\s+$/, '');
    const pre = strokesRef.current;

    if (edit.index === null) {
      if (!text) return;

      const element: CanvasStroke = {
        color: edit.color,
        width: ELEMENT_HAIRLINE_WIDTH,
        path: [[edit.x, edit.y]],
        kind: 'text',
        text,
        size: edit.size,
      };

      setStrokes(prev => [...prev, element]);
      await pushStrokeToServer(element, pre);

      return;
    }

    const old = pre[edit.index];

    if (!old || text === old.text) return;

    const next = text
      ? pre.map((el, i) => (i === edit.index ? { ...el, text } : el))
      : pre.filter((_, i) => i !== edit.index);

    setStrokes(next);
    await commitReplace(next, pre);
  };

  const startText = (x: number, y: number) => {
    const hit = hitTestAt(x, y);
    const existing = hit >= 0 ? strokesRef.current[hit] : undefined;

    if (existing?.kind === 'text') {
      // Hide the element while its text is edited in place.
      setPreviewStrokes(strokesRef.current.filter((_, i) => i !== hit));
      setTextEdit({
        index: hit,
        x: existing.path[0][0],
        y: existing.path[0][1],
        size: existing.size ?? 24,
        color: existing.color,
        text: existing.text ?? '',
      });

      return;
    }

    setTextEdit({
      index: null,
      x,
      y,
      size: NEW_TEXT_SCREEN_SIZE / scaleRef.current,
      color: penColor,
      text: '',
    });
  };

  // ──────────────── Image tool ─────────────────────────────────────────────

  /** Place an existing File resource on the canvas, in the middle of the
   *  view, and hand it to the lasso so it can be moved and scaled. */
  const placeImage = async (src: string) => {
    const container = containerRef.current;

    if (!container) return;

    try {
      const url = await resolveImageUrl(store, src);

      if (!url) throw new Error('That file has no image to show');

      const natural = await loadImageSize(url);

      primeCanvasImage(src, url);

      const s = scaleRef.current;
      const screenW = Math.min(natural.w, container.clientWidth * 0.5);
      const w = screenW / s;
      const h = (w * natural.h) / natural.w;
      const cx = (container.clientWidth / 2 - offsetRef.current.x) / s;
      const cy = (container.clientHeight / 2 - offsetRef.current.y) / s;
      const element: CanvasStroke = {
        color: 0xff000000,
        width: ELEMENT_HAIRLINE_WIDTH,
        path: [[cx - w / 2, cy - h / 2]],
        kind: 'image',
        src,
        w,
        h,
      };
      const pre = strokesRef.current;

      viewTouchedRef.current = true;
      setStrokes([...pre, element]);
      setTool('lasso');
      selectElements([pre.length], pre.length + 1);
      await pushStrokeToServer(element, pre);
    } catch (err) {
      errorHandler(err);
    }
  };

  const uploadAndPlaceImage = async (file: File) => {
    const [subject] = await upload([file]);

    if (subject) await placeImage(subject);
  };

  // ──────────────── Pointer flow: pan / pinch / draw / erase ───────────────

  const notePen = (e: React.PointerEvent) => {
    if (e.pointerType !== 'pen' || penDetectedRef.current) return;

    penDetectedRef.current = true;
    setPenDetected(true);

    try {
      localStorage.setItem(PEN_SEEN_KEY, '1');
    } catch {
      // Remembering the pen is a convenience only.
    }
  };

  /** Drop whatever the current pointer was doing without saving it. */
  const abortActiveTool = () => {
    if (drawingPointerRef.current !== null) {
      drawingPointerRef.current = null;
      setCurrentStroke(null);
    }

    if (erasingPointerRef.current !== null) {
      erasingPointerRef.current = null;
      erasedIndicesRef.current = new Set();
      setPreviewStrokes(null);
    }

    if (lassoPointerRef.current !== null) {
      lassoPointerRef.current = null;
      setLassoPath(null);
    }

    if (transformRef.current) {
      transformRef.current = null;
      setPreviewStrokes(null);
    }

    isPanningRef.current = false;
    panStartRef.current = null;
    setPanMode(isPanModeRef.current ? 'ready' : 'idle');
  };

  const startPan = (e: React.PointerEvent) => {
    isPanningRef.current = true;
    setPanMode('panning');
    panStartRef.current = {
      x: e.clientX,
      y: e.clientY,
      ox: offsetRef.current.x,
      oy: offsetRef.current.y,
    };
    canvasRef.current?.setPointerCapture(e.pointerId);
  };

  const startPinch = () => {
    const container = containerRef.current;
    const [a, b] = [...touchesRef.current.values()];

    if (!container || !a || !b) return;

    const rect = container.getBoundingClientRect();
    const mx = (a.x + b.x) / 2 - rect.left;
    const my = (a.y + b.y) / 2 - rect.top;

    pinchRef.current = {
      dist: Math.hypot(a.x - b.x, a.y - b.y),
      scale: scaleRef.current,
      wx: (mx - offsetRef.current.x) / scaleRef.current,
      wy: (my - offsetRef.current.y) / scaleRef.current,
    };
  };

  /** Two fingers: zoom by the change in distance, pan with the midpoint,
   *  keeping the canvas point first under the fingers under them. */
  const movePinch = () => {
    const container = containerRef.current;
    const pinch = pinchRef.current;
    const [a, b] = [...touchesRef.current.values()];

    if (!container || !pinch || !a || !b || pinch.dist < 1) return;

    const rect = container.getBoundingClientRect();
    const mx = (a.x + b.x) / 2 - rect.left;
    const my = (a.y + b.y) / 2 - rect.top;
    const next = Math.min(
      MAX_SCALE,
      Math.max(
        MIN_SCALE,
        (pinch.scale * Math.hypot(a.x - b.x, a.y - b.y)) / pinch.dist,
      ),
    );

    setScale(next);
    setOffset({ x: mx - pinch.wx * next, y: my - pinch.wy * next });
  };

  const onPointerDown = (e: React.PointerEvent) => {
    notePen(e);
    viewTouchedRef.current = true;
    // Drawing / erasing starts — hide the hover preview; the stroke itself
    // is the feedback.
    setCursorPos(null);

    const el = canvasRef.current;

    if (!el) {
      return;
    }

    // Any tap on the canvas ends a text edit (its blur commits it).
    if (textEditRef.current) {
      void commitText();

      return;
    }

    if (e.pointerType === 'pen') {
      penContactRef.current = true;

      // The pen takes over from a finger that was panning.
      if (isPanningRef.current) abortActiveTool();
    } else if (e.pointerType === 'touch') {
      // Palm rejection: ignore fingers while the pen touches the screen.
      if (penContactRef.current) return;

      touchesRef.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
      el.setPointerCapture(e.pointerId);

      if (touchesRef.current.size >= 2) {
        abortActiveTool();
        gestureActiveRef.current = true;
        startPinch();

        return;
      }

      if (gestureActiveRef.current) return;

      // With a pen around, a finger moves the canvas; without one it draws.
      if (penDetectedRef.current) {
        startPan(e);

        return;
      }
    }

    if (e.button === 1 || (e.button === 0 && isPanModeRef.current)) {
      startPan(e);

      return;
    }

    if (e.button !== 0) {
      return;
    }

    const rect = el.getBoundingClientRect();
    const [x, y] = screenToCanvas(
      e.clientX,
      e.clientY,
      rect,
      scaleRef.current,
      offsetRef.current.x,
      offsetRef.current.y,
    );

    if (toolRef.current === 'eraser') {
      erasingPointerRef.current = e.pointerId;
      el.setPointerCapture(e.pointerId);
      eraseAt(x, y);

      return;
    }

    if (toolRef.current === 'lasso') {
      startLassoOrTransform(e, x, y);

      return;
    }

    if (toolRef.current === 'text') {
      startText(x, y);

      return;
    }

    drawingPointerRef.current = e.pointerId;
    setCurrentStroke({
      color: penColor,
      width: penWidth,
      path: [[x, y]],
    });
    el.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    notePen(e);
    trackCursorForPreview(e);

    if (e.pointerType === 'touch' && touchesRef.current.has(e.pointerId)) {
      touchesRef.current.set(e.pointerId, { x: e.clientX, y: e.clientY });

      if (gestureActiveRef.current) {
        if (touchesRef.current.size >= 2) movePinch();

        return;
      }
    }

    if (isPanningRef.current && panStartRef.current) {
      const dx = e.clientX - panStartRef.current.x;
      const dy = e.clientY - panStartRef.current.y;
      setOffset({
        x: panStartRef.current.ox + dx,
        y: panStartRef.current.oy + dy,
      });

      return;
    }

    const el = canvasRef.current;

    if (!el) {
      return;
    }

    const rect = el.getBoundingClientRect();
    const [x, y] = screenToCanvas(
      e.clientX,
      e.clientY,
      rect,
      scaleRef.current,
      offsetRef.current.x,
      offsetRef.current.y,
    );

    broadcastPointer(x, y);

    if (erasingPointerRef.current === e.pointerId) {
      eraseAt(x, y);

      return;
    }

    const gesture = transformRef.current;

    if (gesture && gesture.pointerId === e.pointerId) {
      gesture.moved = true;
      setPreviewStrokes(transformedStrokes(gesture, x, y));

      return;
    }

    if (lassoPointerRef.current === e.pointerId && lassoPathRef.current) {
      const path = lassoPathRef.current;
      const last = path[path.length - 1];

      if (Math.hypot(x - last[0], y - last[1]) > 2 / scaleRef.current) {
        setLassoPath([...path, [x, y]]);
      }

      return;
    }

    if (
      drawingPointerRef.current !== e.pointerId ||
      !currentStrokeRef.current
    ) {
      return;
    }

    const stroke = currentStrokeRef.current;
    const last = stroke.path[stroke.path.length - 1];
    const minDist = 2 / scaleRef.current;

    if (Math.hypot(x - last[0], y - last[1]) > minDist) {
      setCurrentStroke({
        ...stroke,
        path: [...stroke.path, [x, y]],
      });
    }
  };

  const finishStroke = (e: React.PointerEvent) => {
    if (e.pointerType === 'pen') {
      penContactRef.current = false;
    } else if (e.pointerType === 'touch') {
      touchesRef.current.delete(e.pointerId);

      if (touchesRef.current.size < 2) pinchRef.current = null;

      if (gestureActiveRef.current) {
        canvasRef.current?.releasePointerCapture?.(e.pointerId);

        // The gesture is over once the last finger lifts.
        if (touchesRef.current.size === 0) gestureActiveRef.current = false;

        return;
      }
    }

    if (isPanningRef.current) {
      isPanningRef.current = false;
      panStartRef.current = null;
      setPanMode(isPanModeRef.current ? 'ready' : 'idle');
      canvasRef.current?.releasePointerCapture(e.pointerId);

      return;
    }

    if (erasingPointerRef.current === e.pointerId) {
      erasingPointerRef.current = null;
      canvasRef.current?.releasePointerCapture(e.pointerId);
      void finishErase();

      return;
    }

    const gesture = transformRef.current;

    if (gesture && gesture.pointerId === e.pointerId) {
      transformRef.current = null;
      canvasRef.current?.releasePointerCapture(e.pointerId);

      const next = previewStrokesRef.current;
      setPreviewStrokes(null);

      // A release without a drag leaves the strokes as they were.
      if (gesture.moved && next && e.type !== 'pointercancel') {
        setStrokes(next);
        void commitReplace(next, gesture.base);
      }

      return;
    }

    if (lassoPointerRef.current === e.pointerId) {
      lassoPointerRef.current = null;
      canvasRef.current?.releasePointerCapture(e.pointerId);

      const path = lassoPathRef.current ?? [];
      const list = strokesRef.current;
      setLassoPath(null);

      if (e.type === 'pointercancel') return;

      if (path.length < 4) {
        // A tap picks the element under it.
        const hit = hitTestAt(path[0][0], path[0][1]);
        selectElements(hit >= 0 ? [hit] : [], list.length);
      } else {
        selectElements(lassoSelect(path, list), list.length);
      }

      return;
    }

    if (drawingPointerRef.current !== e.pointerId) {
      return;
    }

    drawingPointerRef.current = null;
    canvasRef.current?.releasePointerCapture(e.pointerId);

    const stroke = currentStrokeRef.current;

    if (!stroke || stroke.path.length === 0) {
      setCurrentStroke(null);

      return;
    }

    // Snapshot pre-edit strokes BEFORE adding the new one — the undo
    // target should restore to *before* this stroke.
    const preEditStrokes = strokesRef.current;
    setStrokes(prev => [...prev, stroke]);
    setCurrentStroke(null);
    void pushStrokeToServer(stroke, preEditStrokes);
  };

  // Wheel handling: attached natively with `{ passive: false }` so we can
  // actually `preventDefault()`. React's synthetic `onWheel` is passive by
  // default and silently drops `preventDefault()` calls, which means
  // Ctrl-/Cmd-wheel and trackpad pinch end up zooming the whole browser
  // page instead of just the canvas.
  useEffect(() => {
    const container = containerRef.current;

    if (!container) return;

    const handleWheel = (e: WheelEvent) => {
      // Suppress the browser's default for every wheel inside the canvas:
      // plain wheel would scroll the page, Ctrl/Cmd-wheel and trackpad
      // pinch would zoom the whole browser UI.
      e.preventDefault();

      const el = canvasRef.current;

      if (!el) return;

      // Ignore wheel events that belong to a scroll session that *started*
      // before this canvas became visible. That session is a macOS
      // momentum-scroll tail carried over from the previous view; the user
      // didn't initiate scrolling here. Once a new wheel session begins
      // (gap > WHEEL_SESSION_GAP_MS, set in `helpers/wheelSession.ts`),
      // its events count normally. See that file for the rationale.
      if (currentWheelSessionStartedAt() < canvasMountedAtRef.current) {
        return;
      }

      viewTouchedRef.current = true;

      // Match Flutter's `_onPointerSignal` (infinite_canvas.dart:747-768):
      //
      // * Plain wheel  → pan the canvas by the scroll delta.
      // * Ctrl / Cmd wheel  → zoom toward the cursor.
      //
      // The Ctrl-modified branch also covers macOS / Windows trackpad pinch,
      // which the browser surfaces as `wheel` events with `ctrlKey === true`.
      if (e.ctrlKey || e.metaKey) {
        const rect = el.getBoundingClientRect();

        // A discrete scrollwheel notch arrives as a single big `deltaY`
        // (typically ±100), so a fixed 10 % step per event is the right
        // feel. A macOS trackpad pinch arrives as a *stream* of small
        // `deltaY` values (often ±2 to ±15); applying that same 10 % step
        // to every event makes the canvas zoom 10×+ per pinch. Switch on
        // magnitude: small deltas → continuous exponential scaling
        // proportional to motion; large deltas → discrete notch.
        const isCoarseNotch = Math.abs(e.deltaY) >= 50;
        const factor = isCoarseNotch
          ? e.deltaY < 0
            ? 1.1
            : 1 / 1.1
          : Math.exp(-e.deltaY * 0.005);
        const nextScale = Math.min(
          30,
          Math.max(0.05, scaleRef.current * factor),
        );
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const worldX = (mx - offsetRef.current.x) / scaleRef.current;
        const worldY = (my - offsetRef.current.y) / scaleRef.current;

        setScale(nextScale);
        setOffset({
          x: mx - worldX * nextScale,
          y: my - worldY * nextScale,
        });

        return;
      }

      // Plain wheel → pan. Negative-delta = subtract from offset so the
      // content scrolls in the natural direction. macOS "natural scrolling"
      // already inverts the sign at the OS layer.
      setOffset({
        x: offsetRef.current.x - e.deltaX,
        y: offsetRef.current.y - e.deltaY,
      });
    };

    container.addEventListener('wheel', handleWheel, { passive: false });

    return () => container.removeEventListener('wheel', handleWheel);
  }, []);

  // ──────────────── Toolbar button handlers ────────────────────────────────

  // Keyboard shortcuts: Ctrl+Z undo, Ctrl+Shift+Z redo.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (isEditableKeyboardTarget(e.target)) return;

      if (
        (e.key === 'Delete' || e.key === 'Backspace') &&
        selectionRef.current.length > 0
      ) {
        e.preventDefault();
        deleteSelection();

        return;
      }

      if (e.key === 'Escape' && selectionRef.current.length > 0) {
        selectElements([], strokesRef.current.length);

        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key === 'z') {
        if (e.shiftKey) {
          e.preventDefault();
          handleRedo();
        } else {
          e.preventDefault();
          handleUndo();
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);

    return () => window.removeEventListener('keydown', onKeyDown);
  }, [handleUndo, handleRedo, deleteSelection, selectElements]);

  // Help dialog — shows the keyboard / gesture cheat-sheet that used to
  // live in an always-visible footer hint. Triggered by the info button at
  // the start of the bottom toolbar.
  const [helpDialogProps, showHelp, , isHelpOpen] = useDialog();

  // ──────────────── Color & Width fans (Flutter parity) ───────────────────
  //
  // Press-and-hold the Color (or Width) button: a fan of swatches sprouts
  // from the button centre (32 colours in 4 rings, 7 widths on a single
  // semicircle). Drag toward a swatch to snap-select it; release to commit
  // (swap prev ↔ current, current ← picked). A plain release without drag
  // = tap = swap prev ↔ current.
  //
  // The button owns the pointer capture; the FanOverlay is render-only.

  const openFanFromButton = useCallback(
    (
      e: React.PointerEvent<HTMLButtonElement>,
      type: 'color' | 'width',
    ): void => {
      e.preventDefault();
      const target = e.currentTarget;
      target.setPointerCapture(e.pointerId);
      const rect = target.getBoundingClientRect();
      const centre = {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
      };
      fanGestureRef.current = {
        pointerId: e.pointerId,
        type,
        buttonCenter: centre,
        start: { x: e.clientX, y: e.clientY },
        dragged: false,
      };
      setFanType(type);
      setFanButtonCenter(centre);
      setFanDragOffset({ x: 0, y: 0 });
      setFanHoveredColor(null);
      setFanHoveredWidth(null);
      setFanPeek(true);
    },
    [],
  );

  const updateFanFromButton = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>): void => {
      const g = fanGestureRef.current;
      if (!g || g.pointerId !== e.pointerId) return;

      const dx = e.clientX - g.buttonCenter.x;
      const dy = e.clientY - g.buttonCenter.y;
      const dragLen = Math.hypot(e.clientX - g.start.x, e.clientY - g.start.y);

      if (!g.dragged && dragLen >= FAN_DRAG_THRESHOLD) {
        g.dragged = true;
        setFanPeek(false);
      }

      setFanDragOffset({ x: dx, y: dy });

      if (g.type === 'color') {
        const hit = resolveHoveredColor({ x: dx, y: dy });
        setFanHoveredColor(hit?.color ?? null);
      } else {
        setFanHoveredWidth(resolveHoveredWidth({ x: dx, y: dy }));
      }
    },
    [],
  );

  const closeFanFromButton = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>): void => {
      const g = fanGestureRef.current;
      if (!g || g.pointerId !== e.pointerId) return;
      (e.currentTarget as HTMLElement).releasePointerCapture?.(e.pointerId);

      const dragged = g.dragged;
      const type = g.type;
      fanGestureRef.current = null;

      // Snapshot hover before clearing state (state setters won't have
      // committed by the time we read).
      const pickedColor = fanHoveredColor;
      const pickedWidth = fanHoveredWidth;

      setFanType(null);
      setFanButtonCenter(null);
      setFanDragOffset({ x: 0, y: 0 });
      setFanHoveredColor(null);
      setFanHoveredWidth(null);
      setFanPeek(false);

      if (!dragged) {
        // Tap → swap prev ↔ current.
        if (type === 'color') {
          setPenColor(prevColor);
          setPrevColor(penColor);
          recolorSelection(prevColor);
        } else {
          setPenWidth(prevWidth);
          setPrevWidth(penWidth);
        }

        return;
      }

      // Drag-release: if a swatch is hovered, commit it (prev ← current,
      // current ← picked). If the user landed in the dead-zone, the
      // gesture is a no-op — same as Flutter.
      if (type === 'color' && pickedColor !== null) {
        setPrevColor(penColor);
        setPenColor(pickedColor);
        recolorSelection(pickedColor);
      } else if (type === 'width' && pickedWidth !== null) {
        setPrevWidth(penWidth);
        setPenWidth(pickedWidth);
      }
    },
    [
      fanHoveredColor,
      fanHoveredWidth,
      penColor,
      penWidth,
      prevColor,
      prevWidth,
      recolorSelection,
    ],
  );

  const cancelFanFromButton = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>): void => {
      const g = fanGestureRef.current;
      if (!g || g.pointerId !== e.pointerId) return;
      fanGestureRef.current = null;
      setFanType(null);
      setFanButtonCenter(null);
      setFanDragOffset({ x: 0, y: 0 });
      setFanHoveredColor(null);
      setFanHoveredWidth(null);
      setFanPeek(false);
    },
    [],
  );

  const chooseTool = (next: Tool) => {
    if (textEditRef.current) void commitText();

    setTool(next);
    selectElements([], strokesRef.current.length);
    setLassoPath(null);
  };

  // ──────────────── Zoom scrub gesture (Flutter parity) ────────────────────
  //
  // Tap zoom = fit-all. Press-and-drag the zoom button horizontally: scale
  // = startScale × 2^(dx / SCRUB_PIXELS_PER_ZOOM_DOUBLE), with the world
  // point under the viewport centre pinned in place so the user's focus
  // doesn't drift. Matches Flutter's `_onZoomScrubDelta` (150 px = 2×).

  const zoomScrubRef = useRef<{
    pointerId: number;
    startX: number;
    startScale: number;
    centerWorld: { x: number; y: number };
    dragged: boolean;
  } | null>(null);

  // The scale bar shows while the zoom button is held, so people find out they
  // can hold it, and goes away a moment after release.
  const [zoomHintShown, setZoomHintShown] = useState(false);
  const zoomHintTimerRef = useRef<number | undefined>(undefined);

  const showZoomHint = useCallback(() => {
    window.clearTimeout(zoomHintTimerRef.current);
    setZoomHintShown(true);
  }, []);

  const hideZoomHintSoon = useCallback(() => {
    window.clearTimeout(zoomHintTimerRef.current);
    zoomHintTimerRef.current = window.setTimeout(
      () => setZoomHintShown(false),
      HINT_LINGER_MS,
    );
  }, []);

  useEffect(() => () => window.clearTimeout(zoomHintTimerRef.current), []);

  const onZoomPointerDown = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>) => {
      const container = containerRef.current;
      if (!container) return;
      e.preventDefault();
      showZoomHint();
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);

      const containerW = container.clientWidth;
      const containerH = container.clientHeight;
      const centerWorldX =
        (containerW / 2 - offsetRef.current.x) / scaleRef.current;
      const centerWorldY =
        (containerH / 2 - offsetRef.current.y) / scaleRef.current;

      zoomScrubRef.current = {
        pointerId: e.pointerId,
        startX: e.clientX,
        startScale: scaleRef.current,
        centerWorld: { x: centerWorldX, y: centerWorldY },
        dragged: false,
      };
    },
    [showZoomHint],
  );

  const onZoomPointerMove = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>) => {
      const z = zoomScrubRef.current;
      if (!z || z.pointerId !== e.pointerId) return;

      const dx = e.clientX - z.startX;
      if (!z.dragged && Math.abs(dx) < SCRUB_DRAG_THRESHOLD) return;
      z.dragged = true;

      const container = containerRef.current;
      if (!container) return;

      const nextScale = Math.min(
        30,
        Math.max(0.05, z.startScale * Math.pow(2, dx / ZOOM_SCRUB_PX_PER_2X)),
      );
      setScale(nextScale);
      setOffset({
        x: container.clientWidth / 2 - z.centerWorld.x * nextScale,
        y: container.clientHeight / 2 - z.centerWorld.y * nextScale,
      });
    },
    [],
  );

  // `handleZoomToFit` is declared after these handlers and recreates when
  // `strokes` changes; capture the latest through a ref so the tap path
  // doesn't fit against a stale stroke snapshot. Same pattern as the
  // chatroom send-ref bridge in `ChatRoomPage`.
  const handleZoomToFitRef = useRef<() => void>(() => undefined);

  const onZoomPointerUp = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>) => {
      const z = zoomScrubRef.current;
      if (!z || z.pointerId !== e.pointerId) return;
      (e.currentTarget as HTMLElement).releasePointerCapture?.(e.pointerId);
      zoomScrubRef.current = null;
      hideZoomHintSoon();

      if (!z.dragged) {
        handleZoomToFitRef.current();
      }
    },
    [hideZoomHintSoon],
  );

  const onZoomPointerCancel = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>) => {
      const z = zoomScrubRef.current;
      if (!z || z.pointerId !== e.pointerId) return;
      zoomScrubRef.current = null;
      hideZoomHintSoon();
    },
    [hideZoomHintSoon],
  );

  /** Zoom to fit: compute the bounding box of all strokes, scale to fit
   * with a small padding, center in the viewport. Matches the start-state
   * of Flutter's zoom button when nothing else has zoomed. The latest
   * version is also kept in `handleZoomToFitRef` so `onZoomPointerUp`
   * (declared above) can call it without a stale-closure bug. */
  const handleZoomToFit = useCallback(() => {
    const container = containerRef.current;

    if (!container || strokes.length === 0) {
      // Reset to default view if nothing to fit.
      setScale(1);
      setOffset({ x: 0, y: 0 });

      return;
    }

    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;

    for (const s of strokes) {
      for (const [x, y] of s.path) {
        if (x < minX) minX = x;
        if (y < minY) minY = y;
        if (x > maxX) maxX = x;
        if (y > maxY) maxY = y;
      }
    }

    if (!Number.isFinite(minX)) {
      setScale(1);
      setOffset({ x: 0, y: 0 });

      return;
    }

    const padding = 40;
    const w = container.clientWidth - padding * 2;
    const h = container.clientHeight - padding * 2;
    const contentW = Math.max(1, maxX - minX);
    const contentH = Math.max(1, maxY - minY);
    const nextScale = Math.min(
      30,
      Math.max(0.05, Math.min(w / contentW, h / contentH)),
    );
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;

    setScale(nextScale);
    setOffset({
      x: container.clientWidth / 2 - cx * nextScale,
      y: container.clientHeight / 2 - cy * nextScale,
    });
  }, [strokes]);

  // Mirror the latest `handleZoomToFit` into the ref so the zoom button's
  // tap path always sees fresh strokes (see `handleZoomToFitRef` above).
  handleZoomToFitRef.current = handleZoomToFit;

  // Initial fit-to-drawing: the drawing may extend past the default
  // viewport (it was made on another device, or at another zoom), so
  // opening a canvas starts with everything visible. Waits for strokes
  // (they load in the mount effect, or arrive on the first Loro sync)
  // and yields to the user the moment they touch the view.
  useEffect(() => {
    if (initialFitSubjectRef.current === resource.subject) return;
    if (viewTouchedRef.current || strokes.length === 0) return;

    initialFitSubjectRef.current = resource.subject;
    handleZoomToFit();
  }, [resource.subject, strokes, handleZoomToFit]);

  const widthDotPx = Math.max(4, Math.min(22, penWidth * 0.6));

  return (
    <Page>
      {(saving || saveError) && (
        <SaveStatus $error={!!saveError}>
          {saveError ? `Save failed: ${saveError}` : 'Saving…'}
        </SaveStatus>
      )}
      <CanvasArea
        ref={containerRef}
        $dark={darkMode}
        $panMode={panMode}
        $tool={tool}
        $previewCursor={cursorPos !== null}
        data-pen-detected={penDetected}
      >
        <DrawCanvas
          ref={canvasRef}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerEnter={trackCursorForPreview}
          onPointerLeave={() => {
            setCursorPos(null);
            clearPointer();
          }}
          onPointerUp={finishStroke}
          onPointerCancel={finishStroke}
          onContextMenu={e => e.preventDefault()}
        />
        {textEdit && (
          <TextEditor
            ref={textFieldRef}
            value={textEdit.text}
            rows={textEdit.text.split('\n').length}
            aria-label='Canvas text'
            onChange={e => setTextEdit({ ...textEdit, text: e.target.value })}
            onBlur={() => void commitText()}
            onKeyDown={e => {
              if (e.key === 'Escape') {
                e.preventDefault();
                e.currentTarget.blur();
              }
            }}
            style={{
              left: textEdit.x * scale + offset.x,
              top: textEdit.y * scale + offset.y,
              fontSize: textEdit.size * scale,
              color: colorIntToHex(textEdit.color),
            }}
          />
        )}
        {cursorPos && (
          <CursorPreview
            style={{
              // Diameter clamped so a hairline stroke is still visible and
              // a huge zoomed-in brush stays on screen. Centred on the
              // pointer via the `translate(-50%, -50%)` in CursorPreview.
              width: Math.max(4, penWidth * scale),
              height: Math.max(4, penWidth * scale),
              transform: `translate(${cursorPos.x}px, ${cursorPos.y}px) translate(-50%, -50%)`,
              background: colorIntToHex(penColor),
            }}
          />
        )}
        <RemoteCursors cursors={cursors} scale={scale} offset={offset} />
        <FilePickerDialog
          show={imagePickerOpen}
          onShowChange={setImagePickerOpen}
          allowedMimes={imageMimeTypes}
          onResourcePicked={subject => void placeImage(subject)}
          onNewFilePicked={file => void uploadAndPlaceImage(file)}
        />
        <BottomToolbar ref={toolbarRef} $lift={toolbarLift}>
          <CircleButton
            type='button'
            title='Canvas help'
            onClick={showHelp}
            aria-label='Show canvas help'
          >
            <FaCircleInfo />
          </CircleButton>
          <CircleButton
            type='button'
            title='Pen'
            aria-label='Pen tool'
            $active={tool === 'pen'}
            onClick={() => chooseTool('pen')}
          >
            <FaPen />
          </CircleButton>
          <CircleButton
            type='button'
            title='Eraser'
            aria-label='Eraser tool'
            $active={tool === 'eraser'}
            onClick={() => chooseTool('eraser')}
          >
            <FaEraser />
          </CircleButton>
          <CircleButton
            type='button'
            title='Lasso: circle strokes to select them, then move or scale'
            aria-label='Lasso tool'
            $active={tool === 'lasso'}
            onClick={() => chooseTool('lasso')}
          >
            <FaVectorSquare />
          </CircleButton>
          <CircleButton
            type='button'
            title='Text: tap the canvas and type'
            aria-label='Text tool'
            $active={tool === 'text'}
            onClick={() => chooseTool('text')}
          >
            <FaFont />
          </CircleButton>
          <CircleButton
            type='button'
            title='Image: place a picture'
            aria-label='Place image'
            onClick={() => setImagePickerOpen(true)}
          >
            <FaImage />
          </CircleButton>
          {selection.length > 0 && (
            <CircleButton
              type='button'
              title='Delete selection'
              aria-label='Delete selection'
              onClick={deleteSelection}
            >
              <FaTrash />
            </CircleButton>
          )}
          <ColorCircleButton
            type='button'
            title='Pen color (tap to swap with previous, drag to pick from fan)'
            $color={penColor}
            onPointerDown={e => openFanFromButton(e, 'color')}
            onPointerMove={updateFanFromButton}
            onPointerUp={closeFanFromButton}
            onPointerCancel={cancelFanFromButton}
            aria-label='Pen color'
          >
            <FaPalette />
          </ColorCircleButton>
          <WidthCircleButton
            type='button'
            title={`Stroke width: ${penWidth} (tap to swap with previous, drag to pick from fan)`}
            onPointerDown={e => openFanFromButton(e, 'width')}
            onPointerMove={updateFanFromButton}
            onPointerUp={closeFanFromButton}
            onPointerCancel={cancelFanFromButton}
            aria-label='Stroke width'
          >
            <WidthRing aria-hidden>
              <WidthDot $size={widthDotPx} />
            </WidthRing>
          </WidthCircleButton>
          <CircleButton
            type='button'
            title='Undo (Ctrl+Z) — drag horizontally to scrub history, hold to see discarded versions'
            onPointerDown={onUndoPointerDown}
            onPointerMove={onUndoPointerMove}
            onPointerUp={onUndoPointerUp}
            onPointerCancel={onUndoPointerCancel}
            // Build the undo stack on hover, so the press that follows acts
            // on a stack that is already there. The press paths call this
            // too — touch and Ctrl+Z never hover.
            onPointerEnter={() => void ensureUndoStack()}
            disabled={!canUndo && !canRedo && branches.length === 0}
            aria-pressed={previewStrokes !== null}
          >
            <FaRotateLeft />
          </CircleButton>
          <CircleButton
            type='button'
            title='Redo (Ctrl+Shift+Z)'
            onClick={handleRedo}
            disabled={!canRedo}
          >
            <FaRotateRight />
          </CircleButton>
          <CircleButton
            type='button'
            title='Zoom level: tap to fit everything, drag sideways to zoom'
            aria-label='Zoom level'
            onPointerDown={onZoomPointerDown}
            onPointerMove={onZoomPointerMove}
            onPointerUp={onZoomPointerUp}
            onPointerCancel={onZoomPointerCancel}
          >
            <ZoomLabel>{Math.round(scale * 100)}%</ZoomLabel>
          </CircleButton>
        </BottomToolbar>
        {zoomHintShown && (
          <ZoomHint $lift={toolbarLift} aria-hidden>
            <span>{Math.round(scale * 100)}%</span>
            <ZoomTrack>
              <ZoomTick style={{ left: `${zoomFraction(1) * 100}%` }} />
              <ZoomFill style={{ width: `${zoomFraction(scale) * 100}%` }} />
            </ZoomTrack>
          </ZoomHint>
        )}
        {overlayMode !== 'closed' && (
          <HistoryScrubOverlay
            step={scrubStep}
            totalSteps={scrubTotal}
            branches={branches}
            hoveredBranchId={hoveredBranchId}
            interactive={overlayMode === 'grace'}
            darkMode={darkMode}
            onBranchHover={onBranchHover}
            onBranchPick={onBranchPick}
          />
        )}
      </CanvasArea>
      {fanType && fanButtonCenter && (
        <FanOverlay
          type={fanType}
          buttonCenter={fanButtonCenter}
          dragOffset={fanDragOffset}
          hoveredColor={fanHoveredColor}
          hoveredWidth={fanHoveredWidth}
          peek={fanPeek}
          darkMode={darkMode}
        />
      )}
      <Dialog {...helpDialogProps}>
        {isHelpOpen && (
          <>
            <DialogTitle>
              <h1>Canvas controls</h1>
            </DialogTitle>
            <DialogContent>
              <HelpList>
                <li>
                  <kbd>Left click</kbd> &amp; drag — draw a stroke
                </li>
                <li>
                  <kbd>Scroll</kbd> · <kbd>Space</kbd>+drag · middle-mouse drag
                  — pan the canvas
                </li>
                <li>
                  <kbd>Ctrl</kbd>+<kbd>scroll</kbd> · trackpad pinch — zoom
                  toward the cursor
                </li>
                <li>
                  Tap the eraser button, then drag across strokes to remove them
                </li>
                <li>
                  Lasso: draw a loop around strokes (or tap one) to select them,
                  drag inside the box to move, drag a corner to scale, and press{' '}
                  <kbd>Delete</kbd> to remove
                </li>
                <li>
                  Text: tap the canvas and type; tap existing text to edit it
                </li>
                <li>Image: pick a picture, then move or scale it</li>
                <li>
                  Touch: two fingers pan and zoom. Once a pen has been seen, one
                  finger pans as well; without a pen one finger draws
                </li>
                <li>
                  Tap the colour or width button to swap with the previous
                  choice; press &amp; drag to open the picker fan
                </li>
                <li>
                  Tap <kbd>Undo</kbd> / <kbd>Redo</kbd> to step through edits;
                  drag the undo button left/right to scrub the full history
                </li>
                <li>
                  Hold the undo button to see versions you abandoned by drawing
                  after an undo; drag over one and release to restore it
                </li>
                <li>
                  Tap the zoom button (it shows the zoom level) to fit all
                  strokes; drag left/right to zoom continuously
                </li>
                <li>
                  <kbd>Ctrl</kbd>+<kbd>Z</kbd> undo · <kbd>Ctrl</kbd>+
                  <kbd>Shift</kbd>+<kbd>Z</kbd> redo
                </li>
              </HelpList>
            </DialogContent>
          </>
        )}
      </Dialog>
    </Page>
  );
};

// ──────────────── Styles ───────────────────────────────────────────────────

const Page = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: ${p => p.theme.heights.fullPage};
  background: ${p => p.theme.colors.bg};
  position: relative;
`;

const SaveStatus = styled.span<{ $error?: boolean }>`
  position: absolute;
  top: ${p => p.theme.size()};
  right: ${p => p.theme.size(2)};
  z-index: 2;
  font-size: 0.875rem;
  padding: 4px 10px;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  color: ${p => (p.$error ? p.theme.colors.alert : p.theme.colors.textLight)};
  border: 1px solid
    ${p => (p.$error ? p.theme.colors.alert : p.theme.colors.bg2)};
`;

const CanvasArea = styled.div<{
  $dark: boolean;
  $panMode: string;
  $tool: Tool;
  $previewCursor: boolean;
}>`
  position: relative;
  flex: 1;
  min-height: 400px;
  overflow: hidden;
  touch-action: none;
  background: ${p => p.theme.colors.bg};
  cursor: ${p =>
    p.$panMode === 'ready'
      ? 'grab'
      : p.$panMode === 'panning'
        ? 'grabbing'
        : p.$tool === 'eraser'
          ? 'cell'
          : // Hide the OS cursor only when the in-canvas preview circle is
            // showing — otherwise crosshair stays so the user isn't left
            // with no pointer at all when the cursor is outside the
            // canvas area but `eraser` / `pan` modes are inactive.
            p.$previewCursor
            ? 'none'
            : 'crosshair'};
`;

/**
 * Pen-tip preview that follows the cursor: a circle sized exactly to the
 * stroke that would land if the user pressed and dragged (`penWidth ×
 * scale` in screen pixels) and filled with the current pen colour. The
 * thin outline keeps the preview visible against same-colour patches of
 * canvas. `pointer-events: none` so it never steals the gesture.
 */
const CursorPreview = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  border-radius: 50%;
  pointer-events: none;
  z-index: 2;
  border: 1px solid rgba(255, 255, 255, 0.85);
  box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.4);
  /* The toolbar pill sits above this (z-index 3) so hovering near the
     bottom of the canvas doesn't paint the preview over a button. */
`;

/* Out of flow: the canvas is sized from its area, so it must not also prop the
   area open (otherwise the area never shrinks when the window does). */
const DrawCanvas = styled.canvas`
  position: absolute;
  inset: 0;
  display: block;
`;

/** In-place text field over the canvas, sized to match the drawn text. */
const TextEditor = styled.textarea`
  position: absolute;
  z-index: 2;
  margin: 0;
  padding: 0;
  border: 1px dashed ${p => p.theme.colors.main};
  background: transparent;
  outline: none;
  resize: none;
  overflow: hidden;
  white-space: pre;
  min-width: 2ch;
  field-sizing: content;
  font-family: ${TEXT_FONT_FAMILY};
  line-height: ${TEXT_LINE_HEIGHT};
`;

/** The current zoom as a percentage, shown on the zoom button. */
/** Where a zoom level sits on the bar: logarithmic, like the drag itself. */
const zoomFraction = (z: number): number =>
  Math.min(
    1,
    Math.max(0, Math.log(z / ZOOM_MIN) / Math.log(ZOOM_MAX / ZOOM_MIN)),
  );

const ZoomHint = styled.div<{ $lift: number }>`
  position: absolute;
  bottom: calc(
    ${p => p.theme.size(2)} + var(--canvas-toolbar-h, 64px) + ${p => p.$lift}px
  );
  left: 50%;
  transform: translateX(-50%);
  z-index: 4;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
  font-size: 0.85rem;
  font-variant-numeric: tabular-nums;
  color: ${p => p.theme.colors.text};
  pointer-events: none;
`;

const ZoomTrack = styled.div`
  position: relative;
  width: 180px;
  height: 4px;
  border-radius: 2px;
  background: ${p => p.theme.colors.bg2};
`;

const ZoomFill = styled.div`
  height: 100%;
  border-radius: 2px;
  background: ${p => p.theme.colors.main};
`;

/** Marks 100% on the bar. */
const ZoomTick = styled.div`
  position: absolute;
  top: -3px;
  width: 2px;
  height: 10px;
  margin-left: -1px;
  background: ${p => p.theme.colors.textLight};
`;

const ZoomLabel = styled.span`
  font-size: 0.7rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
`;

const HelpList = styled.ul`
  margin: 0;
  padding-left: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  color: ${p => p.theme.colors.text};

  & kbd {
    background: ${p => p.theme.colors.bg1};
    border: 1px solid ${p => p.theme.colors.bg2};
    border-radius: 4px;
    padding: 0 0.35em;
    font-size: 0.85em;
    font-family: inherit;
  }
`;

/**
 * Bottom pill toolbar — matches Flutter's `bottom_toolbar.dart` desktop
 * layout: floating, centered, rounded, theme-aware background with a soft
 * shadow. Compact widths just shrink the gap; the desktop pill survives.
 */
const BottomToolbar = styled.div<{ $lift: number }>`
  position: absolute;
  bottom: calc(${p => p.theme.size(2)} + ${p => p.$lift}px);
  left: 50%;
  transform: translateX(-50%);
  z-index: 3;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px;
  /* Buttons keep their size and stay round; they wrap instead of squeezing. */
  --canvas-button-size: 44px;
  /* Natural width (not half the area, which left:50% would allow), capped to
     the area; beyond that the buttons wrap. */
  width: max-content;
  max-width: calc(100% - 16px);
  /* Too little room: a second row, not a sideways scroll. */
  flex-wrap: wrap;
  justify-content: center;

  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 32px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);

  /* Phones: a flat bar attached to the bottom and both sides. */
  @media (max-width: 900px) {
    --canvas-button-size: 36px;
    gap: 2px;
    left: 0;
    right: 0;
    transform: none;
    bottom: ${p => p.$lift}px;
    width: auto;
    max-width: none;
    border-radius: 0;
    border-width: 1px 0 0;
    box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.12);
    padding-bottom: calc(6px + env(safe-area-inset-bottom, 0px));
  }

  /* Narrow phones: all eleven buttons must fit without sideways scrolling. */
  @media (max-width: 480px) {
    --canvas-button-size: 32px;
    gap: 0;
    padding-left: 2px;
    padding-right: 2px;
  }
`;

interface CircleButtonProps {
  $active?: boolean;
}

const CircleButton = styled.button<CircleButtonProps>`
  flex: none;
  box-sizing: border-box;
  aspect-ratio: 1;
  /* Drags on a button (fan, scrub, zoom) must reach us, not scroll the bar. */
  touch-action: none;
  min-width: var(--canvas-button-size);
  min-height: var(--canvas-button-size);
  width: var(--canvas-button-size);
  height: var(--canvas-button-size);
  border-radius: 50%;
  border: none;
  background: ${p => (p.$active ? p.theme.colors.main : 'transparent')};
  color: ${p =>
    p.$active
      ? p.theme.colors.bg
      : p.disabled
        ? p.theme.colors.textLight
        : p.theme.colors.text};
  cursor: ${p => (p.disabled ? 'default' : 'pointer')};
  opacity: ${p => (p.disabled ? 0.4 : 1)};
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  padding: 0;
  transition: background 120ms ease;

  &:hover:not(:disabled) {
    background: ${p => (p.$active ? p.theme.colors.main : p.theme.colors.bg1)};
  }
`;

/**
 * Color button: a circle filled with the current pen color. Tap cycles to
 * the next swatch. D2 replaces this with the proper Flutter color fan
 * (drag-to-select among 32 colors).
 */
/* `>>> 0` coerces to unsigned 32-bit; slice(2) drops the alpha bytes
 * since the canvas paints ignoring alpha at the toolbar size. */
const colorIntToHex = (c: number): string =>
  `#${(c >>> 0).toString(16).padStart(8, '0').slice(2)}`;

/** Black or white, whichever reads better on the given color. */
const contrastOn = (c: number): string => {
  const r = (c >>> 16) & 255;
  const g = (c >>> 8) & 255;
  const b = c & 255;

  return 0.299 * r + 0.587 * g + 0.114 * b > 150 ? '#000' : '#fff';
};

const ColorCircleButton = styled.button<{ $color: number }>`
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  color: ${p => contrastOn(p.$color)};
  box-sizing: border-box;
  aspect-ratio: 1;
  /* Drags on a button (fan, scrub, zoom) must reach us, not scroll the bar. */
  touch-action: none;
  min-width: var(--canvas-button-size);
  min-height: var(--canvas-button-size);
  width: var(--canvas-button-size);
  height: var(--canvas-button-size);
  border-radius: 50%;
  background: ${p => colorIntToHex(p.$color)};
  border: 2px solid ${p => p.theme.colors.bg2};
  cursor: pointer;
  padding: 0;

  &:hover {
    border-color: ${p => p.theme.colors.text};
  }
`;

/**
 * Width button: a circle with a centered dot whose size mirrors the current
 * stroke width. Tap cycles. D2 replaces this with the fan.
 */
const WidthCircleButton = styled.button`
  flex: none;
  box-sizing: border-box;
  aspect-ratio: 1;
  /* Drags on a button (fan, scrub, zoom) must reach us, not scroll the bar. */
  touch-action: none;
  min-width: var(--canvas-button-size);
  min-height: var(--canvas-button-size);
  width: var(--canvas-button-size);
  height: var(--canvas-button-size);
  border-radius: 50%;
  border: none;
  background: transparent;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0;

  &:hover {
    background: ${p => p.theme.colors.bg1};
  }
`;

/** Dotted outer ring; the dot inside is filled to the current stroke size. */
const WidthRing = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 78%;
  height: 78%;
  border: 2px dotted ${p => p.theme.colors.textLight};
  border-radius: 50%;
`;

const WidthDot = styled.span<{ $size: number }>`
  width: ${p => p.$size}px;
  height: ${p => p.$size}px;
  border-radius: 50%;
  background: ${p => p.theme.colors.text};
`;
