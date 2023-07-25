import React from 'react';
import styled from 'styled-components';
import { useSettings } from '../helpers/AppSettings';

const NAVBAR_HEIGHT = '2rem';
const NAVBAR_CALC_PART = ` + ${NAVBAR_HEIGHT}`;

export interface NavBarSpacerProps {
  position: 'top' | 'bottom';
  baseMargin?: string;
}

const size = (base = '0rem', withNav: boolean) =>
  `calc(${base}${withNav ? NAVBAR_CALC_PART : ''})`;

/** Makes room for the navbar when it is present at the given position. Animates its height. */
export function NavBarSpacer({
  position,
  baseMargin,
}: NavBarSpacerProps): JSX.Element {
  const { navbarFloating, navbarTop } = useSettings();

  const getSize = () => {
    if (position === 'top') {
      return size(baseMargin, navbarTop);
    }

    return size(baseMargin, !navbarFloating && !navbarTop);
  };

  return <Spacing size={getSize()} />;
}

interface SpacingProps {
  size: string;
}

const Spacing = styled.div<SpacingProps>`
  height: ${p => p.size};
  transition: height 0.2s ease-out;
`;
