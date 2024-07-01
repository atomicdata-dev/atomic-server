import { styled } from 'styled-components';
import {
  RESOURCE_PAGE_TRANSITION_TAG,
  getTransitionStyle,
} from '../helpers/transitionName';

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
  background-color: ${props => props.theme.colors.bg};

  border: solid 1px
    ${props =>
      props.highlight ? props.theme.colors.main : props.theme.colors.bg2};
  box-shadow: ${props =>
    props.highlight
      ? `0 0 0 1px ${props.theme.colors.main}, ${props.theme.boxShadow}`
      : props.theme.boxShadow};

  padding: ${props => props.theme.margin}rem;
  border-radius: ${props => props.theme.radius};
  max-height: ${props => (props.small ? '10rem' : 'none')};
  overflow: ${props => (props.small ? 'hidden' : 'visible')};
`;

export interface CardRowProps {
  noBorder?: boolean;
}

/** A Row in a Card. Should probably be used inside a CardInsideFull */
export const CardRow = styled.div<CardRowProps>`
  --border: solid 1px ${props => props.theme.colors.bg2};
  display: block;
  border-top: ${props => (props.noBorder ? 'none' : 'var(--border)')};
  padding: ${props => props.theme.margin / 3}rem
    ${props => props.theme.margin}rem;
`;

/** A block inside a Card which has full width */
export const CardInsideFull = styled.div`
  margin-left: -${props => props.theme.margin}rem;
  margin-right: -${props => props.theme.margin}rem;
`;

export const Margin = styled.div`
  display: block;
  height: ${props => props.theme.margin}rem;
`;
