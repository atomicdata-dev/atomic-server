import { styled } from 'styled-components';
import {
  RESOURCE_PAGE_TRANSITION_TAG,
  getTransitionStyle,
} from '../helpers/transitionName';
import { CARD_CONTAINER } from '../helpers/containers';

type CardProps = {
  /** Adds a colorful border */
  highlight?: boolean;
  /** Sets a maximum height */
  small?: boolean;
};

/** A Card with a border. */
export const Card = styled.div.attrs<CardProps>(p => ({
  // When we render a lot of cards it is more performant to use styles instead of classes when each card has a unique style
  style: getTransitionStyle(RESOURCE_PAGE_TRANSITION_TAG, p.about),
}))`
  background-color: ${p => p.theme.colors.bg};
  container: ${CARD_CONTAINER} / inline-size;
  border: solid 1px
    ${p => (p.highlight ? p.theme.colors.main : p.theme.colors.bg2)};
  box-shadow: ${p =>
    p.highlight
      ? `0 0 0 1px ${p.theme.colors.main}, ${p.theme.boxShadow}`
      : p.theme.boxShadow};

  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
  max-height: ${p => (p.small ? p.theme.size(12) : 'initial')};
  overflow: ${p => (p.small ? 'hidden' : 'visible')};
`;

export interface CardRowProps {
  noBorder?: boolean;
}

/** A Row in a Card. Should probably be used inside a CardInsideFull */
export const CardRow = styled.div<CardRowProps>`
  --border: solid 1px ${p => p.theme.colors.bg2};
  display: block;
  border-top: ${p => (p.noBorder ? 'none' : 'var(--border)')};
  padding: ${p => p.theme.size(2)} ${p => p.theme.size()};
  overflow-wrap: break-word;
`;

/** A block inside a Card which has full width */
export const CardInsideFull = styled.div`
  margin-left: -${p => p.theme.size()};
  margin-right: -${p => p.theme.size()};
`;

export const Margin = styled.div`
  display: block;
  height: ${p => p.theme.size()};
`;
