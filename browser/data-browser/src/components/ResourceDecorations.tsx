import {
  Image,
  core,
  dataBrowser,
  useArray,
  useCanWrite,
  useNumber,
  useString,
  useSubject,
  type Resource,
} from '@tomic/react';
import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
  type JSX,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { styled, css } from 'styled-components';
import { FaFaceSmile, FaFolderOpen, FaImage } from 'react-icons/fa6';
import { FilePickerDialog } from './forms/FilePicker/FilePickerDialog';
import { useUpload } from '../hooks/useUpload';
import { atomicArgu } from '../ontologies/atomic-argu';
import { Button } from './Button';
import { Column, Row } from './Row';
import { ErrorBoundary } from '../views/ErrorPage';
import { Dialog, DialogContent, DialogTitle, useDialog } from './Dialog';
import { AvatarCropper } from './AvatarCropper';
import { ResourceGlyph } from './ResourceGlyph';
import { errorHandler } from '../handlers/errorHandler';

const EmojiPickerPanelAsync = lazy(() =>
  import('../chunks/EmojiInput/EmojiInput').then(m => ({
    default: m.EmojiPickerPanel,
  })),
);

// validate: false — the coverImage property is not (yet) resolvable at its
// canonical atomicdata.dev subject, so client-side datatype validation would
// fail on the fetch. The server validates commits against its local copy.
const valueOpts = {
  commit: true,
  validate: false,
};

/** Mimetypes the server can resize & re-encode, plus formats browsers render natively. */
const IMAGE_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/avif',
  'image/gif',
  'image/bmp',
  'image/tiff',
  'image/svg+xml',
]);

const NothingOnError = () => null;

/**
 * The resource's cover image value. Old Articles stored their cover under an
 * argu-specific property; reads fall back to it, writes migrate to the
 * canonical property.
 */
function useCoverImage(
  resource: Resource,
): [cover: string | undefined, applyCover: (subject?: string) => void] {
  const [cover, setCover] = useSubject(
    resource,
    dataBrowser.properties.coverImage,
    valueOpts,
  );
  const [legacyCover, setLegacyCover] = useSubject(
    resource,
    atomicArgu.properties.coverImage,
    valueOpts,
  );

  const applyCover = (subject?: string) => {
    setCover(subject);

    if (legacyCover) {
      setLegacyCover(undefined);
    }
  };

  return [cover ?? legacyCover, applyCover];
}

/**
 * The cover's vertical focal point (0–1, default 0.5/centered), rendered as
 * `object-position: 50% ${focus * 100}%`. Lives on the decorated resource,
 * not the File: framing is a property of the usage (the same photo can be
 * someone else's cover with different framing, and picking their file as a
 * cover mustn't require write rights on it), not the image.
 */
function useCoverFocus(
  resource: Resource,
): [focus: number, setFocus: (v: number) => void] {
  const [focus, setFocus] = useNumber(
    resource,
    dataBrowser.properties.coverImageFocus,
    valueOpts,
  );

  const setClamped = (v: number) => setFocus(Math.min(1, Math.max(0, v)));

  return [focus ?? 0.5, setClamped];
}

interface CoverPickerProps {
  resource: Resource;
  show: boolean;
  onShowChange: (show: boolean) => void;
  onPicked: (subject: string) => void;
}

/** Pick-or-upload dialog for a cover image. */
function CoverPicker({
  resource,
  show,
  onShowChange,
  onPicked,
}: CoverPickerProps): JSX.Element {
  const { upload } = useUpload(resource);

  const handleNewFilePicked = async (file: File) => {
    const [subject] = await upload([file]);

    if (subject) {
      onPicked(subject);
    }
  };

  return (
    <FilePickerDialog
      show={show}
      onShowChange={onShowChange}
      onResourcePicked={onPicked}
      onNewFilePicked={handleNewFilePicked}
      allowedMimes={IMAGE_MIMES}
    />
  );
}

export interface ResourceDecorationProps {
  resource: Resource;
}

/**
 * Full-bleed cover image banner. Mount directly under the page's Main, above
 * the padded content container, so it touches the edges.
 */
export function ResourceCoverImage({
  resource,
}: ResourceDecorationProps): JSX.Element | null {
  const canEdit = useCanWrite(resource);
  const [cover, applyCover] = useCoverImage(resource);
  const [focus, setFocus] = useCoverFocus(resource);
  const [showPicker, setShowPicker] = useState(false);
  const [repositioning, setRepositioning] = useState(false);
  // Live value while dragging; undefined outside a drag (renders `focus`).
  const [dragFocus, setDragFocus] = useState<number>();
  const wrapperRef = useRef<HTMLDivElement>(null);

  if (!cover) {
    return null;
  }

  const effectiveFocus = dragFocus ?? focus;

  const focusFromPointer = (e: ReactPointerEvent<HTMLDivElement>) => {
    const rect = wrapperRef.current?.getBoundingClientRect();
    if (!rect || rect.height === 0) return effectiveFocus;

    return Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height));
  };

  const handlePointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 || !e.isPrimary) return;
    // Native image dragging cancels pointer events after the first movement.
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    setDragFocus(focusFromPointer(e));
  };

  const handlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (dragFocus === undefined) return;
    setDragFocus(focusFromPointer(e));
  };

  const handlePointerUp = () => {
    if (dragFocus !== undefined) {
      setFocus(dragFocus);
    }

    setDragFocus(undefined);
    setRepositioning(false);
  };

  return (
    <CoverWrapper
      ref={wrapperRef}
      $repositioning={repositioning}
      onPointerDown={repositioning ? handlePointerDown : undefined}
      onPointerMove={repositioning ? handlePointerMove : undefined}
      onPointerUp={repositioning ? handlePointerUp : undefined}
      onPointerCancel={
        repositioning ? () => setDragFocus(undefined) : undefined
      }
    >
      <ErrorBoundary FallBackComponent={NothingOnError}>
        <CoverImage
          subject={cover}
          draggable={false}
          alt=''
          sizeIndication={100}
          style={{ objectPosition: `50% ${effectiveFocus * 100}%` }}
        />
      </ErrorBoundary>
      {canEdit && !repositioning && (
        <>
          <CoverActions gap='0.5rem'>
            <Button subtle onClick={() => setShowPicker(true)}>
              Change cover
            </Button>
            <Button subtle onClick={() => setRepositioning(true)}>
              Reposition
            </Button>
            <Button subtle onClick={() => applyCover(undefined)}>
              Remove cover
            </Button>
          </CoverActions>
          <CoverPicker
            resource={resource}
            show={showPicker}
            onShowChange={setShowPicker}
            onPicked={applyCover}
          />
        </>
      )}
      {repositioning && (
        <RepositionOverlay aria-hidden>
          Drag to reposition · release to save
        </RepositionOverlay>
      )}
    </CoverWrapper>
  );
}

export interface TitleIconProps extends ResourceDecorationProps {
  /** Opens the icon picker, which the caller mounts outside the title. */
  onPickIcon: () => void;
}

/**
 * The resource's icon (emoji or avatar image), rendered inline at title
 * size. Clicking it opens the icon picker (when the user can edit). Rendered
 * by EditableTitle.
 */
export function TitleIcon({
  resource,
  onPickIcon,
}: TitleIconProps): JSX.Element | null {
  const canEdit = useCanWrite(resource);
  const [emoji] = useString(resource, dataBrowser.properties.emoji, valueOpts);
  const [iconImage] = useSubject(
    resource,
    dataBrowser.properties.icon,
    valueOpts,
  );

  if (!emoji && !iconImage) {
    return null;
  }

  const display = <ResourceGlyph resource={resource} requireCustom />;

  if (!canEdit) {
    return <StaticGlyph aria-hidden>{display}</StaticGlyph>;
  }

  return (
    <GlyphTrigger
      type='button'
      title='Change icon'
      onClick={e => {
        // This sits inside the click-to-edit title; don't flip it to editing.
        e.stopPropagation();
        onPickIcon();
      }}
    >
      {display}
    </GlyphTrigger>
  );
}

/**
 * Ghost "Add icon" / "Add cover" buttons, revealed when hovering the title
 * area. Rendered by EditableTitle when `withDecorations` is set and the
 * viewport can hover and has the room (`useInlineTitleAffordances`).
 */
export function TitleDecorationAffordances({
  resource,
  onPickIcon,
}: TitleIconProps): JSX.Element | null {
  const canEdit = useCanWrite(resource);
  const [emoji] = useString(resource, dataBrowser.properties.emoji, valueOpts);
  const [iconImage] = useSubject(resource, dataBrowser.properties.icon);
  const [cover, applyCover] = useCoverImage(resource);
  const [showPicker, setShowPicker] = useState(false);

  const hasIcon = !!(emoji || iconImage);

  if (!canEdit || (hasIcon && cover)) {
    return null;
  }

  return (
    <>
      <AffordanceRow gap='0.5rem'>
        {!hasIcon && (
          <Button ghost onClick={onPickIcon}>
            <FaFaceSmile key='icon' aria-hidden /> Add icon
          </Button>
        )}
        {!cover && (
          <Button ghost onClick={() => setShowPicker(true)}>
            <FaImage key='cover' aria-hidden /> Add cover
          </Button>
        )}
      </AffordanceRow>
      {!cover && (
        <CoverPicker
          resource={resource}
          show={showPicker}
          onShowChange={setShowPicker}
          onPicked={applyCover}
        />
      )}
    </>
  );
}

interface PickerDialogProps {
  resource: Resource;
  show: boolean;
  onShowChange: (show: boolean) => void;
}

/**
 * The one icon picker: an emoji, an uploaded image (cropped to a small square
 * webp, then uploaded) or an existing File. Opened by the title icon, the
 * "Add icon" button and the resource menu alike. Picking an emoji clears the
 * image, picking an image clears the emoji, Remove clears both.
 *
 * Mount it OUTSIDE the click-to-edit title and keep it mounted while the
 * picker is in use: the dialog closes itself before the file input, cropper
 * or file picker takes over, and anything those are mounted in must survive
 * that. `Dialog` portals to its own root, but React events still bubble
 * through the component tree, so a mount inside the title also turns every
 * click in these dialogs into a title click.
 */
export function IconPickerDialog({
  resource,
  show,
  onShowChange,
}: PickerDialogProps): JSX.Element {
  const { upload } = useUpload(resource);
  const [emoji, setEmoji] = useString(
    resource,
    dataBrowser.properties.emoji,
    valueOpts,
  );
  const [iconImage, setIconImage] = useSubject(
    resource,
    dataBrowser.properties.icon,
    valueOpts,
  );
  const [isA] = useArray(resource, core.properties.isA);
  const [pendingFile, setPendingFile] = useState<File>();
  const [showFilePicker, setShowFilePicker] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dialogProps, showDialog, closeDialog] = useDialog({
    bindShow: onShowChange,
  });

  useEffect(() => {
    if (show) {
      showDialog();
    }
  }, [show, showDialog]);

  // The image `icon` replaces any emoji. Failures toast via errorHandler
  // (uploads via useUpload's own).
  const setImage = async (subject: string | undefined) => {
    try {
      await setIconImage(subject);
      await setEmoji(undefined);
    } catch (e) {
      errorHandler(e as Error);
    }
  };

  const handleCropped = async (cropped: File) => {
    const [subject] = await upload([cropped]);

    if (subject) {
      await setImage(subject);
    }
  };

  // No crop step for an existing file: `GlyphImage` renders icons with
  // `object-fit: cover`. No `onNewFilePicked` either, so the file picker's own
  // "Upload" button stays hidden; uploading goes through the cropper.
  return (
    <>
      <Dialog {...dialogProps}>
        {show && (
          <>
            <DialogTitle>
              <h1>Icon</h1>
            </DialogTitle>
            <DialogContent>
              <Column>
                <Row justify='flex-end' gap='0.5rem'>
                  <Button
                    subtle
                    onClick={() => {
                      closeDialog(true);
                      inputRef.current?.click();
                    }}
                  >
                    <FaImage aria-hidden /> Upload image
                  </Button>
                  <Button
                    subtle
                    onClick={() => {
                      closeDialog(true);
                      setShowFilePicker(true);
                    }}
                  >
                    <FaFolderOpen aria-hidden /> Pick existing
                  </Button>
                  {(emoji || iconImage) && (
                    <Button
                      subtle
                      onClick={() => {
                        setEmoji(undefined);
                        setIconImage(undefined);
                        closeDialog(true);
                      }}
                    >
                      Remove icon
                    </Button>
                  )}
                </Row>
                <Suspense fallback={null}>
                  <EmojiPickerPanelAsync
                    onEmojiSelect={e => {
                      setEmoji(e.native);
                      setIconImage(undefined);
                      closeDialog(true);
                    }}
                  />
                </Suspense>
              </Column>
            </DialogContent>
          </>
        )}
      </Dialog>
      <HiddenFileInput
        ref={inputRef}
        type='file'
        accept='image/*'
        onChange={e => {
          const file = e.currentTarget.files?.[0];

          if (file) {
            setPendingFile(file);
          }

          // Allow re-picking the same file.
          e.currentTarget.value = '';
        }}
      />
      {pendingFile && (
        <AvatarCropper
          file={pendingFile}
          show
          circle={isA.includes(core.classes.agent)}
          onShowChange={open => {
            if (!open) {
              setPendingFile(undefined);
            }
          }}
          onCropped={handleCropped}
        />
      )}
      <FilePickerDialog
        show={showFilePicker}
        onShowChange={setShowFilePicker}
        onResourcePicked={setImage}
        allowedMimes={IMAGE_MIMES}
      />
    </>
  );
}

/** Cover pick-or-upload dialog, for surfaces without an anchor (the ⌘M menu). */
export function CoverPickerDialog({
  resource,
  show,
  onShowChange,
}: PickerDialogProps): JSX.Element {
  const [, applyCover] = useCoverImage(resource);

  return (
    <CoverPicker
      resource={resource}
      show={show}
      onShowChange={onShowChange}
      onPicked={applyCover}
    />
  );
}

const HiddenFileInput = styled.input`
  display: none;
`;

const CoverWrapper = styled.div<{ $repositioning?: boolean }>`
  position: relative;
  width: 100%;
  flex-shrink: 0;

  ${p =>
    p.$repositioning &&
    css`
      cursor: ns-resize;
      touch-action: none;
      user-select: none;
    `}
`;

// The className ends up on the inner <img> element, so style it directly.
const CoverImage = styled(Image)`
  display: block;
  object-fit: cover;
  width: 100%;
  height: clamp(10rem, 25vh, 18rem);
`;

const CoverActions = styled(Row)`
  position: absolute;
  top: ${p => p.theme.size()};
  right: ${p => p.theme.size()};
  opacity: 0;
  transition: opacity 0.1s ease-in-out;

  ${CoverWrapper}:hover &,
  ${CoverWrapper}:focus-within & {
    opacity: 1;
  }

  & button {
    background-color: ${p => p.theme.colors.bg};
  }
`;

const RepositionOverlay = styled.div`
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: rgba(0, 0, 0, 0.25);
  color: white;
  font-size: 0.9rem;
  font-weight: 500;
  pointer-events: none;
`;

const glyphStyles = css`
  font-size: 1em;
  line-height: 1;
`;

const StaticGlyph = styled.span`
  ${glyphStyles}
`;

const GlyphTrigger = styled.button`
  ${glyphStyles}
  border: none;
  background: transparent;
  padding: 0;
  cursor: pointer;
  border-radius: ${p => p.theme.radius};
  transition: transform 0.1s ease-in-out;

  &:hover,
  &:focus-visible {
    transform: scale(1.1);
  }
`;

/**
 * Hidden until the title area is hovered or the buttons are focused.
 * EditableTitle's wrapper reveals it via a hover rule.
 */
export const AffordanceRow = styled(Row)`
  min-height: 2rem;
  /* The title beside us wraps; these labels must not, or a long heading
     squeezes "Add cover" into two lines and loses width to it. */
  flex-shrink: 0;
  white-space: nowrap;
  opacity: 0;
  transition: opacity 0.1s ease-in-out;

  &:focus-within {
    opacity: 1;
  }
`;
