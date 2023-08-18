import React, { useEffect, useState } from 'react';
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

  useEffect(() => {
    if (!open) {
      return timeoutEffect(() => {
        setMountChildren(false);
      }, ANIMATION_DURATION());
    }

    setMountChildren(true);
  }, [open]);

  return (
    <GridCollapser open={open} className={className}>
      <CollapseInner>{mountChildren && children}</CollapseInner>
    </GridCollapser>
  );
}

interface GridCollapserProps {
  open?: boolean;
}

const GridCollapser = styled.div<GridCollapserProps>`
  display: grid;
  grid-template-rows: ${({ open }) => (open ? '1fr' : '0fr')};
  transition: grid-template-rows ${() => ANIMATION_DURATION()}ms ease-in-out;

  @media (prefers-reduced-motion) {
    transition: unset;
  }
`;

const CollapseInner = styled.div`
  overflow: hidden;
`;
