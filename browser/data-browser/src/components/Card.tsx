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

const Content = styled.div`
  padding: ${p => p.theme.size()};
`;

const CardBase = styled.div.attrs<CardProps>(p => ({
  // When we render a lot of cards it is more performant to use styles instead of classes when each card has a unique style
  style: getTransitionStyle(RESOURCE_PAGE_TRANSITION_TAG, p.about),
}))`
  background-color: ${p => p.theme.colors.bg};
  container: ${CARD_CONTAINER} / inline-size;
  border: solid 1px
    ${p => (p.highlight ? p.theme.colors.main : p.theme.colors.bg2)};

  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};
  max-height: ${p => (p.small ? p.theme.size(12) : 'initial')};
  overflow: ${p => (p.small ? 'hidden' : 'visible')};

  &:has(${Content}) {
    padding: 0;
  }
`;

export const CardList = styled.ul<{ maxHeight?: string; gap?: string }>`
  --card-list-gap: ${p => p.gap ?? p.theme.size(2)};
  display: flex;
  flex-direction: column;
  gap: 0px;
  /* row-rule: 1px solid ${p => p.theme.colors.bg2}; */
  max-height: ${p => p.maxHeight ?? 'initial'};
  overflow: ${p => (p.maxHeight ? 'scroll' : 'visible')};

  & > * {
    padding-block-start: calc(var(--card-list-gap) / 2);
    padding-block-end: calc(var(--card-list-gap) / 2);

    &:not(:last-child) {
      border-bottom: 1px solid ${p => p.theme.colors.bg2};
    }
  }
`;

/** A Card with a border.
 * By default the Card has padding but if you use `Card.Content` inside the card, only the content will have padding.
 */
export const Card = Object.assign(CardBase, { Content, List: CardList });

export interface CardRowProps {
  noBorder?: boolean;
}

/** A Row in a Card. Should probably be used inside a CardInsideFull */
export const CardRow = styled.div<CardRowProps>`
  --border: solid 1px ${p => p.theme.colors.bg2};
  display: block;
  border-top: ${p => (p.noBorder ? 'none' : 'var(--border)')};
  padding: ${p => p.theme.size(2)} ${p => p.theme.size()};
`;

/** A block inside a Card which has full width */
export const CardInsideFull = styled.div`
  margin-left: -${p => p.theme.size()};
  margin-right: -${p => p.theme.size()};
  padding-inline: ${p => p.theme.size()};
`;

export const Margin = styled.div`
  display: block;
  height: ${p => p.theme.size()};
`;
