import { useRootWelcomeLayout } from '../../context/RootWelcomeLayoutContext';
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
} from 'react';
import { createPortal } from 'react-dom';
import { useHotkeys } from 'react-hotkeys-hook';
import { FaXmark } from 'react-icons/fa6';
import { styled, keyframes } from 'styled-components';
import * as CSS from 'csstype';
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
import { CurrentBackgroundColor } from '../../globalCssVars';
import { timeoutEffect } from '@helpers/timeoutEffect';

// Feedback uses Dialog itself; defer its module to avoid a static import cycle.
const FeedbackMenuItem = lazy(() =>
  import('../SideBar/FeedbackMenuItem').then(module => ({
    default: module.FeedbackMenuItem,
  })),
);

export interface InternalDialogProps {
  show: boolean;
  /** Avoid offering another feedback dialog inside feedback itself. */
  hideOnboardingFeedback?: boolean;
  onClose: (success: boolean) => void;
  onClosed: () => void;
  /** Skip the exit animation (e.g. after a successful form save). */
  instantClose?: boolean;
  disableLightDismiss?: boolean;
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

type DialogSlotComponent = React.FC<
  React.PropsWithChildren<React.HTMLAttributes<HTMLDivElement>>
>;

/**
 * Component to build a dialog. The content of this component are rendered in a
 * portal outside of the main tree. The children are rendered in slots. You can
 * use the following components or provide your own by using the {@link Slot}
 * component: {@link Dialog.Title}, {@link Dialog.Content}, {@link Dialog.Actions}
 *
 * Example:
 *
 * ```jsx
 * import { Dialog } from '@components/Dialog';
 * import { useDialog } from '@components/Dialog/useDialog';
 * ...
 * const { props, show, close } = useDialog();
 * return (
 * <button onClick={show}>Open</button>
 * <Dialog {...props}>
 *    <Dialog.Title>Title</Dialog.Title>
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
  hideOnboardingFeedback = false,
  width,
  instantClose = false,
  disableLightDismiss = false,
  onClose,
  onClosed,
}) => {
  const { rootWelcomeChromeHidden } = useRootWelcomeLayout();
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
      if (disableLightDismiss) {
        return;
      }

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
    [cancelDialog, isTopLevel, disableLightDismiss],
  );

  // Prevent native dialog cancel event when disableLightDismiss is true
  // This must be set up before the dialog is shown
  // Only needed for safary right now because it doesn't support the closedby attribute.
  // https://caniuse.com/wf-dialog-closedby
  useEffect(() => {
    const dialog = dialogRef.current;

    if (!dialog) {
      return;
    }

    const handleCancel = (e: Event) => {
      if (disableLightDismiss) {
        e.preventDefault();
        e.stopPropagation();
      } else if (isTopLevel && !hasOpenInnerPopup) {
        // Only handle cancel if we're the top level dialog
        // The useHotkeys below will call cancelDialog
      }
    };

    // Use capture phase to ensure we get the event first
    dialog.addEventListener('cancel', handleCancel, true);

    return () => {
      dialog.removeEventListener('cancel', handleCancel, true);
    };
  }, [disableLightDismiss, isTopLevel, hasOpenInnerPopup]);

  // Close the dialog when the escape key is pressed
  useHotkeys(
    'esc',
    () => {
      if (!disableLightDismiss) {
        cancelDialog();
      }
    },
    {
      enabled: show && !hasOpenInnerPopup && isTopLevel,
    },
  );

  const finishClose = useCallback(() => {
    dialogRef.current?.close();
    dialogRef.current?.removeAttribute('data-closing');
    onClosed();
  }, [onClosed]);

  // When closing the `data-closing` attribute must be set before rendering so the animation has started when the regular useEffect is called.
  useLayoutEffect(() => {
    if (!show && dialogRef.current && dialogRef.current.hasAttribute('open')) {
      if (instantClose) {
        finishClose();

        return;
      }

      dialogRef.current.setAttribute('data-closing', 'true');
    }
  }, [show, instantClose, finishClose]);

  useEffect(() => {
    if (!dialogRef.current) {
      return;
    }

    if (show) {
      if (!dialogRef.current.hasAttribute('open')) {
        dialogRef.current.showModal();
      }

      const autoFocusElement = dialogRef.current.querySelector<HTMLElement>(
        '[data-dialog-autofocus]',
      );
      autoFocusElement?.focus();
    }

    if (dialogRef.current.hasAttribute('data-closing')) {
      // TODO: Use getAnimations() api to wait for the animations to complete instead of a timeout.
      return timeoutEffect(() => {
        finishClose();
      }, ANIM_MS);
    }
  }, [show, finishClose]);

  return (
    <StyledDialog
      ref={dialogRef}
      onMouseDown={handleOutSideClick}
      $width={width}
      data-top-level={isTopLevel}
      closedby={disableLightDismiss ? 'none' : 'closerequest'}
    >
      <StyledInnerDialog ref={innerDialogRef}>
        <PopoverContainer>
          <DropdownContainer>
            {!disableLightDismiss && (
              <CloseButtonSlot slot='close'>
                <Button icon onClick={cancelDialog} aria-label='close'>
                  <FaXmark />
                </Button>
              </CloseButtonSlot>
            )}
            {children}
            {show && rootWelcomeChromeHidden && !hideOnboardingFeedback && (
              <FeedbackCorner>
                <Suspense fallback={null}>
                  <FeedbackMenuItem floating />
                </Suspense>
              </FeedbackCorner>
            )}
          </DropdownContainer>
        </PopoverContainer>
      </StyledInnerDialog>
    </StyledDialog>
  );
};

export const DialogTitle: DialogSlotComponent = ({ children, ...props }) => (
  <TitleSlot slot={DialogSlot.Title} as='header' {...props}>
    {children}
  </TitleSlot>
);

/**
 * Dialog section that is scrollable. Put your main content here.
 */
export const DialogContent: DialogSlotComponent = ({ children, ...props }) => (
  <DialogContentSlot slot={DialogSlot.Content} as='main' {...props}>
    {children}
  </DialogContentSlot>
);

/**
 * Bottom part of the Dialog that is always visible. Place your buttons here.
 * Should be no larger than 4rem
 */
export const DialogActions: DialogSlotComponent = ({ children, ...props }) => (
  <DialogActionsSlot slot={DialogSlot.Actions} as='footer' {...props}>
    {children}
  </DialogActionsSlot>
);

Dialog.Title = DialogTitle;
Dialog.Content = DialogContent;
Dialog.Actions = DialogActions;

const CloseButtonSlot = styled(Slot)`
  align-self: center;
  justify-self: end;
`;

const DialogContentSlot = styled(Slot)`
  overflow-x: clip;
  overflow-y: auto;
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
  grid-template-columns: minmax(0, 1fr) 2.25rem;
  /* Title row auto height; main grows and scrolls; footer auto */
  grid-template-rows: auto minmax(0, 1fr) auto;
  column-gap: ${p => p.theme.size()};
  row-gap: ${p => p.theme.size()};
  grid-template-areas: 'title close' 'content content' 'actions actions';
  max-block-size: calc(100vh - ${p => p.theme.size()} * 2);
  /* Extra breathing room so the header matches side padding visually */
  padding-block-start: ${p => p.theme.size(2)};
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
  ${CurrentBackgroundColor.define(p => p.theme.colors.bg)}
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
  background-color: ${CurrentBackgroundColor.var()};
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

const TitleSlot = styled(Slot)`
  min-width: 0;
  align-self: center;

  & :is(h1, h2, h3, h4, h5, h6) {
    margin: 0;
    line-height: 1.25;
  }
`;

const FeedbackCorner = styled.div`
  position: fixed;
  bottom: max(1rem, env(safe-area-inset-bottom));
  left: max(1rem, env(safe-area-inset-left));
`;
