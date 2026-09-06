import {
  Resource,
  StoreEvents,
  useCanWrite,
  useStore,
  useTitle,
} from '@tomic/react';
import { useEffect, useLayoutEffect, useRef, useState, type JSX } from 'react';
import { FaPencil } from 'react-icons/fa6';
import { styled, css } from 'styled-components';
import {
  PAGE_TITLE_TRANSITION_TAG,
  transitionName,
} from '../helpers/transitionName';
import { LAYOUT_CONTAINER } from '../helpers/containers';
import { transition } from '../helpers/transition';
import { useInlineTitleAffordances } from '../hooks/useInlineTitleAffordances';
import { Flex } from './Row';
import {
  AffordanceRow,
  TitleDecorationAffordances,
  TitleIcon,
} from './ResourceDecorations';

export interface EditableTitleProps {
  resource: Resource;
  /** Uses `name` by default */
  parentRef?: React.RefObject<HTMLTextAreaElement | null>;
  id?: string;
  className?: string;
  /** Called when the user commits the title (Enter or blur) */
  onCommit?: () => void;
  /**
   * View-transition tag for this title. Defaults to PAGE_TITLE_TRANSITION_TAG.
   * Override when a second EditableTitle for the same resource can be on
   * screen at once (e.g. a side panel mirroring the main page's title) —
   * two elements sharing a view-transition-name skips the transition.
   */
  transitionTag?: string;
  /**
   * Show the "Add icon" / "Add cover" affordances next to the title (revealed
   * on hover). Set on main page views; leave off in bars and panels. Only
   * honoured on hover-capable, wide-enough viewports — elsewhere the resource
   * context menu carries the same actions (see `useInlineTitleAffordances`).
   */
  withDecorations?: boolean;
  /**
   * Why this title cannot be changed, when rights are not the reason.
   *
   * Shown on hover in place of "Click to edit title". A field that silently
   * does nothing when clicked reads as broken; one that says why reads as a
   * decision.
   */
  lockedReason?: string;
}

const opts = {
  commit: true,
  validate: false,
};

export function EditableTitle({
  resource,
  parentRef,
  id,
  className,
  onCommit,
  transitionTag = PAGE_TITLE_TRANSITION_TAG,
  withDecorations,
  // Destructured rather than left in `...props`, which is spread onto the
  // input — React would warn about an unknown DOM attribute.
  lockedReason,
  ...props
}: EditableTitleProps): JSX.Element {
  const store = useStore();

  const [text, setText] = useTitle(resource, Infinity, opts);
  const [isEditing, setIsEditing] = useState(false);
  const innerRef = useRef<HTMLTextAreaElement>(null);
  const ref = parentRef || innerRef;

  const canWrite = useCanWrite(resource);
  const canEdit = canWrite && !lockedReason;
  const inlineAffordances = useInlineTitleAffordances();

  // Where the caret goes once the editor mounts. A click lands it on the
  // character under the pointer, like any text field; only a freshly
  // created resource selects its placeholder title so typing replaces it.
  const caretRef = useRef<number | 'all' | 'end'>('end');

  useEffect(() => {
    // Two ways to learn this resource was just manually created:
    //   1. The flag set synchronously by notifyResourceManuallyCreated, in
    //      case the event already fired before this component subscribed
    //      (the navigate-then-emit race).
    //   2. The event itself, for the live case where creation happens while
    //      this component is already mounted.
    if (store.consumeRecentlyCreated(resource.subject)) {
      caretRef.current = 'all';
      setIsEditing(true);
    }

    return store.on(StoreEvents.ResourceManuallyCreated, created => {
      if (created.subject === resource.subject) {
        caretRef.current = 'all';
        setIsEditing(true);
      }
    });
  }, [store, resource.subject]);

  function handleClick(e: React.MouseEvent<HTMLElement>) {
    // The tooltip says why this title is locked; opening an editor anyway
    // would contradict it.
    if (lockedReason) {
      return;
    }

    caretRef.current = caretOffsetAt(e.currentTarget, e.clientX, e.clientY);
    setIsEditing(true);
  }

  const placeholder = canEdit ? 'Set a title' : 'Untitled';

  useEffect(() => {
    const el = ref.current;

    if (!isEditing || !el) {
      return;
    }

    el.focus();

    const caret = caretRef.current;

    if (caret === 'all') {
      el.select();
    } else {
      const at = caret === 'end' ? el.value.length : caret;
      el.setSelectionRange(at, at);
    }
  }, [isEditing]);

  // The editor is a textarea so a long title wraps like the rendered
  // heading instead of scrolling inside a single line. Browsers with
  // `field-sizing: content` grow it on their own; the rest get the height
  // measured here, before paint, so the box never flashes at one row.
  useLayoutEffect(() => {
    const el = ref.current;

    if (!isEditing || !el || CSS.supports('field-sizing', 'content')) {
      return;
    }

    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }, [isEditing, text]);

  // The keystroke debounce in `useValue` (`commitDebounce: 100ms`)
  // means the last typed character is still parked in a `setTimeout`
  // when the user exits the editor. The next interaction — back-to-back
  // rename, route change, reload — can run before the timer fires and
  // drop that last keystroke. Force-flush on every exit path (Enter,
  // Escape, blur) so the commit posts before the editor unmounts.
  // `save()` is a no-op when there are no dirty changes, so the still-
  // armed debounce timer that fires afterwards is harmless.
  const flushPending = () => {
    void resource.__internalObject.save().catch(() => undefined);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      flushPending();
      setIsEditing(false);
      onCommit?.();
    } else if (e.key === 'Escape') {
      flushPending();
      setIsEditing(false);
    }
  };

  const titleElement = isEditing ? (
    <EditingRow>
      <TitleIcon resource={resource} />
      <TitleInput
        ref={ref}
        data-testid='editable-title'
        rows={1}
        {...props}
        onFocus={() => setIsEditing(true)}
        placeholder={placeholder}
        // Titles are one line of text; a pasted newline becomes a space.
        onChange={e => setText(e.target.value.replace(/\s*\n\s*/g, ' '))}
        value={text || ''}
        onKeyDown={handleKeyDown}
        onBlur={() => {
          flushPending();
          setIsEditing(false);
          onCommit?.();
        }}
        className={className}
      />
    </EditingRow>
  ) : (
    <Title
      disabled={!canEdit}
      id={id}
      $canEdit={!!canEdit}
      title={canEdit ? 'Click to edit title' : (lockedReason ?? '')}
      data-testid='editable-title'
      onClick={handleClick}
      $subtle={!!canEdit && !text}
      $subject={resource.subject}
      $transitionTag={transitionTag}
      className={className}
    >
      <>
        <TitleIcon resource={resource} />
        <TitleText data-title-text>{text || placeholder}</TitleText>
        {canEdit && <Icon />}
      </>
    </Title>
  );

  if (!withDecorations || !inlineAffordances) {
    return titleElement;
  }

  return (
    <TitleWrapper>
      {titleElement}
      {/* Hidden while editing: the input's width differs from the rendered
          title, which would make these buttons jump around. */}
      {!isEditing && <TitleDecorationAffordances resource={resource} />}
    </TitleWrapper>
  );
}

const TitleShared = css`
  line-height: 1.1;
`;

interface TitleProps {
  $subtle: boolean;
  $canEdit: boolean;
  disabled: boolean;
  $transitionTag: string;
  $subject?: string;
}

/** Shrinks the title on narrow containers (phones) instead of letting the
 *  full-size heading force aggressive mid-word wrapping. */
const narrowTitleFontSize = css`
  @container ${LAYOUT_CONTAINER} (max-width: 500px) {
    font-size: 1.35rem;
  }
`;

const Title = styled.h1<TitleProps>`
  ${TitleShared}
  display: flex;
  align-items: center;
  gap: ${p => p.theme.size()};
  cursor: ${props => (props.$canEdit ? 'text' : 'initial')};
  opacity: ${props => (props.$subtle ? 0.5 : 1)};
  /* Hug the text: this element is a view-transition morph target, and a
     full-width box makes small titles (grid items, cards) stretch across
     the whole content width mid-morph before snapping back. */
  width: fit-content;
  max-width: 100%;
  /* Lets the flex children below actually shrink (and their text wrap)
     instead of overflowing at their max-content width. */
  min-width: 0;
  /* Wrap at word boundaries where possible; only break a word that
     genuinely doesn't fit. The global h1 word-break: break-word rule
     (styling.tsx) is the legacy alias for "break anywhere," which also
     shrinks min-content size — combined with a squeezed flex ancestor
     that produced the mid-word 3-line wraps, this overrides it. */
  overflow-wrap: break-word;
  word-break: normal;
  ${narrowTitleFontSize}

  ${props => transitionName(props.$transitionTag, props.$subject)};
`;

/** The rendered title text — needs its own `min-width: 0` so it can shrink
 *  inside `Title`'s flex row rather than staying at its max-content width. */
const TitleText = styled.span`
  min-width: 0;
`;

const TitleInput = styled.textarea`
  ${TitleShared}
  margin-bottom: ${props => props.theme.margin}rem;
  font-size: ${p => p.theme.fontSizeH1}rem;
  color: ${p => p.theme.colors.text};
  border: none;
  font-weight: bold;
  display: block;
  padding: 0;
  margin-top: 0;
  outline: none;
  background-color: transparent;
  margin-bottom: ${p => p.theme.margin}rem;
  font-family: ${p => p.theme.fontFamilyHeader};
  /* Wrap exactly like the rendered heading (see Title). */
  overflow-wrap: break-word;
  word-break: normal;
  white-space: pre-wrap;
  resize: none;
  overflow: hidden;
  width: 100%;
  ${narrowTitleFontSize}

  &:focus {
    outline: none;
  }

  ${Flex} & {
    // When rendered inside a flex container the margin is already provided by the gap.
    margin-bottom: 0;
  }
`;

const Icon = styled(FaPencil)`
  color: ${p => p.theme.colors.textLight};
  opacity: 0;
  font-size: 0.8em;
  ${transition('opacity', 'color')};

  ${Title}:hover & {
    opacity: 1;
  }
`;

/** Keeps the emoji next to the input while the title is being edited. */
const EditingRow = styled.div`
  display: flex;
  align-items: center;
  gap: ${p => p.theme.size()};
  font-size: ${p => p.theme.fontSizeH1}rem;
  ${narrowTitleFontSize}

  /* Hug the typed text like the rendered title does and grow with it
     (progressive enhancement; browsers without field-sizing keep the full
     width and get their height from a layout effect), and drop the
     textarea's legacy standalone margin — the box must match the rendered
     title exactly, whatever the surrounding view. */
  & > textarea {
    margin: 0;
    min-width: 8ch;
    max-width: 100%;

    @supports (field-sizing: content) {
      field-sizing: content;
      width: auto;
    }
  }
`;

const TitleWrapper = styled.div`
  display: flex;
  /* The affordances sit beside the title when there is room and drop
     below it when there is not (split views, side panels). Without this
     they keep their width and the heading is squeezed into breaking
     mid-word, even on a wide, hover-capable screen. */
  flex-wrap: wrap;
  align-items: center;
  gap: ${p => p.theme.size()};
  min-width: 0;

  /* Both modes must occupy the same box or everything below shifts when
     editing starts: the input has no margin, so the h1 must not either.
     Vertical rhythm comes from the surrounding Column gap. */
  & > h1 {
    margin-block: 0;
  }

  &:hover ${AffordanceRow} {
    opacity: 1;
  }
`;

/**
 * Character index in the rendered title under a pointer position, so the
 * editor can open with its caret there. Falls back to the end of the text
 * when the point is not over the title text (the icon, the gap) or the
 * browser has neither caret-from-point API.
 */
function caretOffsetAt(
  title: HTMLElement,
  x: number,
  y: number,
): number | 'end' {
  const textEl = title.querySelector<HTMLElement>('[data-title-text]');

  if (!textEl) {
    return 'end';
  }

  let node: Node | null = null;
  let offset = 0;

  if ('caretPositionFromPoint' in document) {
    const pos = document.caretPositionFromPoint(x, y);
    node = pos?.offsetNode ?? null;
    offset = pos?.offset ?? 0;
  } else if ('caretRangeFromPoint' in document) {
    const range = (
      document as Document & {
        caretRangeFromPoint(x: number, y: number): Range | null;
      }
    ).caretRangeFromPoint(x, y);
    node = range?.startContainer ?? null;
    offset = range?.startOffset ?? 0;
  }

  // Only the title's own text node counts: a hit on the unsaved indicator
  // or outside the span has no meaningful character index.
  if (node?.nodeType !== Node.TEXT_NODE || node.parentNode !== textEl) {
    return 'end';
  }

  return offset;
}
