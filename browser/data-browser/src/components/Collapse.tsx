import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { timeoutEffect } from '../helpers/timeoutEffect';
import { animationDuration } from '../styling';

interface CollapseProps {
  open?: boolean;
  className?: string;
}

// the styling file is not loaded at boot so we have to use a function here
const ANIMATION_DURATION = () => animationDuration * 1.5;

export function Collapse({
  open,
  className,
  children,
}: React.PropsWithChildren<CollapseProps>): JSX.Element {
  const [mountChildren, setMountChildren] = useState(open);
  const [enableOverflow, setEnableOverflow] = useState(false);

  useEffect(() => {
    if (!open) {
      setEnableOverflow(false);

      return timeoutEffect(() => {
        setMountChildren(false);
      }, ANIMATION_DURATION());
    }

    setMountChildren(true);

    return timeoutEffect(() => {
      setEnableOverflow(true);
    }, ANIMATION_DURATION());
  }, [open]);

  return (
    <GridCollapser open={open} className={className}>
      <InnerWrapper $overflow={enableOverflow}>
        {mountChildren && children}
      </InnerWrapper>
    </GridCollapser>
  );
}

interface GridCollapserProps {
  open?: boolean;
}

const GridCollapser = styled.div<GridCollapserProps>`
  display: grid;
  grid-template-rows: ${({ open }) => (open ? '1fr' : '0fr')};
  grid-template-columns: 100%;
  transition:
    grid-template-rows ${() => ANIMATION_DURATION()}ms ease-in-out,
    // In some cases, a margin is added. This needs to animate as well.
    margin-top ${() => ANIMATION_DURATION()}ms ease-in-out;

  @media (prefers-reduced-motion) {
    transition: unset;
  }
`;

const InnerWrapper = styled.div<{ $overflow: boolean }>`
  width: 100%;
  overflow: ${({ $overflow }) => ($overflow ? 'visible' : 'hidden')};
`;
