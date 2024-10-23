import { useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useHotkeys } from 'react-hotkeys-hook';
import { FaTimes } from 'react-icons/fa';
import { styled, keyframes } from 'styled-components';
import * as CSS from 'csstype';
import { effectTimeout } from '../../helpers/effectTimeout';
import { Button } from '../Button';
import { DropdownContainer } from '../Dropdown/DropdownContainer';
import { PopoverContainer } from '../Popover';
import { Slot } from '../Slot';
import {
  DialogTreeContextProvider,
  useDialogTreeContext,
} from './dialogContext';
import { useDialog } from './useDialog';
import { useControlLock } from '../../hooks/useControlLock';
import { useDialogGlobalContext } from './DialogGlobalContextProvider';
import { DIALOG_CONTENT_CONTAINER } from '../../helpers/containers';

export interface InternalDialogProps {
  show: boolean;
  onClose: (success: boolean) => void;
  onClosed: () => void;
  width?: CSS.Property.Width;
}

export enum DialogSlot {
  Title = 'title',
  Content = 'content',
  Actions = 'actions',
}

export const DIALOG_MEDIA_BREAK_POINT = '640px';
export const VAR_DIALOG_INNER_WIDTH = '--dialog-inner-width';

const ANIM_MS = 80;
const ANIM_SPEED = `${ANIM_MS}ms`;

interface DialogSlotProps {
  className?: string;
}

type DialogSlotComponent = React.FC<React.PropsWithChildren<DialogSlotProps>>;

/**
 * Component to build a dialog. The content of this component are rendered in a
 * portal outside of the main tree. The children are rendered in slots. You can
 * use the following components or provide your own by using the {@link Slot}
 * component: `<Slot slot="title">` or {@link DialogTitle}, `<Slot
 * slot="content">` or {@link DialogContent}, `<Slot slot="actions">` or
 * {@link DialogActions}
 *
 * Example:
 *
 * ```jsx
 * const { props, show, close } = useDialog();
 * return (
 * <button onClick={show}>Open</button>
 * <Dialog {...props}>
 *    <DialogTitle>Title</DialogTitle>
 *    ...
 *  </Dialog>
 *  );
 * ```
 */
export function Dialog(props: React.PropsWithChildren<InternalDialogProps>) {
  const { portal } = useDialogGlobalContext(false);

  if (!portal.current) {
    return null;
  }

  return createPortal(
    <DialogTreeContextProvider>
      <InnerDialog {...props} />
    </DialogTreeContextProvider>,
    portal.current,
  );
}

const InnerDialog: React.FC<React.PropsWithChildren<InternalDialogProps>> = ({
  children,
  show,
  width,
  onClose,
  onClosed,
}) => {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const innerDialogRef = useRef<HTMLDivElement>(null);
  const { hasOpenInnerPopup } = useDialogTreeContext();
  const { isTopLevel } = useDialogGlobalContext(show);

  useControlLock(show);

  const cancelDialog = useCallback(() => {
    onClose(false);
  }, [onClose]);

  const handleOutSideClick = useCallback<
    React.MouseEventHandler<HTMLDialogElement>
  >(
    e => {
      if (!isTopLevel) {
        // Don't react to closing events if the dialog is not on top.

        return;
      }

      if (
        !innerDialogRef.current?.contains(e.target as HTMLElement) &&
        innerDialogRef.current !== e.target
      ) {
        cancelDialog();
      }
    },
    [innerDialogRef.current, cancelDialog, isTopLevel],
  );

  // Close the dialog when the escape key is pressed
  useHotkeys(
    'esc',
    () => {
      cancelDialog();
    },
    { enabled: show && !hasOpenInnerPopup && isTopLevel },
  );

  // When closing the `data-closing` attribute must be set before rendering so the animation has started when the regular useEffect is called.
  useLayoutEffect(() => {
    if (!show && dialogRef.current && dialogRef.current.hasAttribute('open')) {
      dialogRef.current.setAttribute('data-closing', 'true');
    }
  }, [show]);

  useEffect(() => {
    if (!dialogRef.current) {
      return;
    }

    if (show) {
      if (!dialogRef.current.hasAttribute('open'))
        // @ts-ignore
        dialogRef.current.showModal();
    }

    if (dialogRef.current.hasAttribute('data-closing')) {
      // TODO: Use getAnimations() api to wait for the animations to complete instead of a timeout.
      return effectTimeout(() => {
        // @ts-ignore
        dialogRef.current.close();
        dialogRef.current?.removeAttribute('data-closing');
        onClosed();
      }, ANIM_MS);
    }
  }, [show, onClosed]);

  return (
    <StyledDialog
      ref={dialogRef}
      onMouseDown={handleOutSideClick}
      $width={width}
      data-top-level={isTopLevel}
    >
      <StyledInnerDialog ref={innerDialogRef}>
        <PopoverContainer>
          <DropdownContainer>
            <CloseButtonSlot slot='close'>
              <Button icon onClick={cancelDialog} aria-label='close'>
                <FaTimes />
              </Button>
            </CloseButtonSlot>
            {children}
          </DropdownContainer>
        </PopoverContainer>
      </StyledInnerDialog>
    </StyledDialog>
  );
};

export const DialogTitle: DialogSlotComponent = ({ children, className }) => (
  <Slot slot={DialogSlot.Title} as='header' className={className}>
    {children}
  </Slot>
);

/**
 * Dialog section that is scrollable. Put your main content here. Should be no
 * larger than 4rem
 */
export const DialogContent: DialogSlotComponent = ({ children, className }) => (
  <DialogContentSlot slot={DialogSlot.Content} as='main' className={className}>
    {children}
  </DialogContentSlot>
);

/**
 * Bottom part of the Dialog that is always visible. Place your buttons here.
 * Should be no larger than 4rem
 */
export const DialogActions: DialogSlotComponent = ({ children, className }) => (
  <DialogActionsSlot
    slot={DialogSlot.Actions}
    as='footer'
    className={className}
  >
    {children}
  </DialogActionsSlot>
);

const CloseButtonSlot = styled(Slot)`
  justify-self: end;
`;

const DialogContentSlot = styled(Slot)`
  overflow-x: auto;
  overflow-y: visible;
  /* The main section should leave room for the footer */
  max-height: calc(80vh - 8rem);
  padding-bottom: ${p => p.theme.size()};
  // Position the scrollbar against the side of the dialog without any spacing inbetween.
  // This also fixes ugly horizontal shadow cutoff.
  margin-inline: -${p => p.theme.size()};
  padding-inline: ${p => p.theme.size()};

  container: ${DIALOG_CONTENT_CONTAINER} / inline-size;
  scrollbar-gutter: stable;
`;

const DialogActionsSlot = styled(Slot)`
  display: flex;
  gap: ${p => p.theme.size()};
  align-items: center;
  justify-content: flex-end;
  border-top: 1px solid ${props => props.theme.colors.bg2};
  padding-top: 1rem;
`;

const StyledInnerDialog = styled.div`
  display: grid;
  grid-template-columns: auto 2rem;
  grid-template-rows: 1fr auto auto;
  gap: 1rem;
  grid-template-areas: 'title close' 'content content' 'actions actions';
  max-block-size: calc(100vh - ${p => p.theme.size()} * 2);
`;

const fadeInForground = keyframes`
  from {
    opacity: 0;
    transform: translateY(5rem);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const fadeInBackground = keyframes`
  from {
    background-color: rgba(0, 0, 0, 0);
    backdrop-filter: blur(0px);
  }
  to {
    background-color: rgba(0, 0, 0, 0.383);
    backdrop-filter: blur(5px);
  }
`;

const StyledDialog = styled.dialog<{ $width?: CSS.Property.Width }>`
  --dialog-width: min(90vw, ${p => p.$width ?? '60ch'});

  ${VAR_DIALOG_INNER_WIDTH}: calc(
    var(--dialog-width) - 2 * ${p => p.theme.size()}
  );

  box-sizing: border-box;
  inset: 0px;
  position: relative;
  z-index: ${p => p.theme.zIndex.dialog};
  padding: ${p => p.theme.size()};
  color: ${props => props.theme.colors.text};
  background-color: ${props => props.theme.colors.bg};
  border-radius: ${props => props.theme.radius};
  border: solid 1px ${props => props.theme.colors.bg2};
  inline-size: var(--dialog-width);
  max-block-size: 100vh;
  height: fit-content;
  overflow: visible;
  box-shadow: ${p => p.theme.boxShadowSoft};

  // Animation props
  opacity: 0;
  transform: translateY(5rem);
  // Use a transition when animating out (for some reason keyframe animations don't work on outgoing dialog).
  transition:
    opacity ${ANIM_SPEED} ease-in-out,
    transform ${ANIM_SPEED} ease-in-out;

  &::backdrop {
    background-color: rgba(0, 0, 0, 0);
    backdrop-filter: blur(0px) grayscale(0%);
    transition:
      background-color ${ANIM_SPEED} ease-out,
      backdrop-filter ${ANIM_SPEED} ease-out;
    // Make sure the browser paints the backdrop on another layer so the animation is less expensive.
    will-change: background-color, backdrop-filter;
  }

  &[open] {
    opacity: 1;
    transform: translateY(0);
    // Use a keyframe animation when animating in (transitions don't work on incomming dialog for some reason).
    animation: ${fadeInForground} ${ANIM_SPEED} ease-in-out;
  }

  &[data-closing='true'] {
    opacity: 0;
    transform: translateY(5rem);
  }

  &[open]::backdrop {
    background-color: rgba(0, 0, 0, 0.383);
    backdrop-filter: blur(5px) grayscale(90%);
    animation: ${fadeInBackground} ${ANIM_SPEED} ease-out;
  }

  &[data-closing='true']::backdrop {
    background-color: rgba(0, 0, 0, 0);
    backdrop-filter: blur(0px) grayscale(0%);
  }

  @media (max-width: ${DIALOG_MEDIA_BREAK_POINT}) {
    max-inline-size: 100%;
    max-block-size: 100vh;
  }
`;

export { useDialog };
