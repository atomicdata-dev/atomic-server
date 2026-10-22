import { styled } from 'styled-components';
import { Logo } from './Logo';
import type { JSX, ReactNode } from 'react';
import { isEmbedded } from '../helpers/embedMode';

/** Height of the bar; the layout below it reserves the same space. */
export const SETUP_BAR_HEIGHT = '3.5rem';

/**
 * The one bar shown while someone is setting up: in the demo, in a template
 * preview, in the template gallery and on the naming step. Every step looks
 * the same: the logo and what this step is on the left, what you can do on
 * the right, secondary actions first and the primary one last. Where the
 * buttons are never depends on which step you are on.
 */
export function SetupBar({
  title,
  children,
}: {
  title: ReactNode;
  children?: ReactNode;
}): JSX.Element {
  // In the app's web view the bar is the page's own top row: no logo (the app
  // has its own chrome), no tinted band, no rule under it.
  const embedded = isEmbedded();

  return (
    <Bar $embedded={embedded} role='region' aria-label='Setup'>
      {!embedded && <BarLogo />}
      <Title $embedded={embedded}>{title}</Title>
      <Actions>{children}</Actions>
    </Bar>
  );
}

/** A label that shortens to `short` on a phone, where the bar is tight. */
export function ShortLabel({
  full,
  short,
}: {
  full: string;
  short: string;
}): JSX.Element {
  return (
    <>
      <Wide>{full}</Wide>
      <Narrow>{short}</Narrow>
    </>
  );
}

const Bar = styled.div<{ $embedded?: boolean }>`
  display: flex;
  align-items: center;
  gap: 1rem;
  height: ${SETUP_BAR_HEIGHT};
  box-sizing: border-box;
  padding: 0.5rem 1rem;
  background: ${p => (p.$embedded ? p.theme.colors.bg : p.theme.colors.bg1)};
  border-bottom: ${p =>
    p.$embedded ? 'none' : `1px solid ${p.theme.colors.bg2}`};
  button {
    white-space: nowrap;
  }
  @media (max-width: 600px) {
    padding: 0.5rem;
    button {
      font-size: 0.875rem;
    }
  }
`;

const BarLogo = styled(Logo)`
  /* Shrinks before the buttons do, so a phone keeps room for two of them. */
  flex: 0 1 9rem;
  min-width: 4.5rem;
`;

const Title = styled.div<{ $embedded?: boolean }>`
  flex: 1;
  padding-left: ${p => (p.$embedded ? '0' : '1rem')};
  border-left: ${p =>
    p.$embedded ? 'none' : `1px solid ${p.theme.colors.bg2}`};
  min-width: 0;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  @media (max-width: 600px) {
    /* The actions matter more than the name of the step on a phone. */
    display: none;
  }
`;

const Actions = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: auto;
`;

const Wide = styled.span`
  @media (max-width: 600px) {
    display: none;
  }
`;

const Narrow = styled.span`
  display: none;
  @media (max-width: 600px) {
    display: inline;
  }
`;
