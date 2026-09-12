import {
  createContext,
  createRef,
  FC,
  PropsWithChildren,
  ReactNode,
  RefObject,
  useCallback,
  useContext,
  useEffect,
  useRef,
  type JSX,
} from 'react';
import * as RadixPopover from '@radix-ui/react-popover';
import { styled } from 'styled-components';
import { useDialogTreeInfo } from './Dialog/dialogContext';
import { useControlLock } from '../hooks/useControlLock';
import { floatingSurface, floatingSurfaceAppear } from './floatingSurface';

export interface PopoverProps {
  Trigger: ReactNode;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange: (open: boolean) => void;
  className?: string;
  noArrow?: boolean;
  noLock?: boolean;
  modal?: boolean;
  side?: 'top' | 'bottom' | 'left' | 'right';
  updatePositionStrategy?: 'optimized' | 'always';
}

export function Popover({
  children,
  className,
  open,
  defaultOpen,
  noArrow,
  noLock,
  modal,
  onOpenChange,
  Trigger,
  side = 'bottom',
  updatePositionStrategy = 'optimized',
}: PropsWithChildren<PopoverProps>): JSX.Element {
  const { setHasOpenInnerPopup } = useDialogTreeInfo();
  const containerRef = useContext(PopoverContainerContext);

  const container = containerRef.current ?? undefined;

  useControlLock(!noLock && !!open);

  const handleOpenChange = useCallback(
    (changedToOpen: boolean) => {
      setHasOpenInnerPopup(changedToOpen);
      onOpenChange(changedToOpen);
    },
    [onOpenChange, setHasOpenInnerPopup],
  );

  useEffect(() => {
    setHasOpenInnerPopup(!!open);
  }, [open, setHasOpenInnerPopup]);

  return (
    <RadixPopover.Root
      modal={modal}
      open={open}
      onOpenChange={handleOpenChange}
      defaultOpen={defaultOpen}
    >
      {Trigger}
      <RadixPopover.Portal container={container}>
        <Content
          collisionPadding={10}
          sticky='always'
          className={className}
          side={side}
          updatePositionStrategy={updatePositionStrategy}
        >
          {children}
          {!noArrow && <Arrow />}
        </Content>
      </RadixPopover.Portal>
    </RadixPopover.Root>
  );
}

const Content = styled(RadixPopover.Content)`
  --popover-close-offset: ${p => p.theme.size()};
  --popover-close-size: 25px;
  --popover-close-safe-area: calc(
    var(--popover-close-size) + (var(--popover-close-offset) * 2) -
      ${p => p.theme.size()}
  );
  ${floatingSurface}
  z-index: 10000000;
  transform-origin: var(--radix-popover-content-transform-origin);
  animation: ${floatingSurfaceAppear} ${p => p.theme.animation.duration}
    ease-in-out;

  &[data-state='closed'] {
    animation: ${floatingSurfaceAppear} ${p => p.theme.animation.duration}
      ease-in-out reverse;
  }
`;

const Arrow = styled(RadixPopover.Arrow)`
  fill: ${p => p.theme.colors.bg2};
`;

const PopoverContainerContext =
  createContext<RefObject<HTMLDivElement | null>>(createRef());

export const usePopoverContainer = () => {
  return useContext(PopoverContainerContext);
};

export const PopoverContainer: FC<PropsWithChildren> = ({ children }) => {
  const popoverContainerRef = useRef<HTMLDivElement>(null);

  return (
    <ContainerDiv ref={popoverContainerRef}>
      <PopoverContainerContext value={popoverContainerRef}>
        {children}
      </PopoverContainerContext>
    </ContainerDiv>
  );
};

const ContainerDiv = styled.div`
  display: contents;
`;
