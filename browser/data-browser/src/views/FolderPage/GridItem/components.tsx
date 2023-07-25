import styled from 'styled-components';
import { transitionName } from '../../../helpers/transitionName';
import { ViewTransitionProps } from '../../../helpers/ViewTransitionProps';

export const GridCard = styled.div<ViewTransitionProps>`
  grid-area: card;
  background-color: ${p => p.theme.colors.bg1};
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
  box-shadow: var(--shadow), var(--interaction-shadow);
  border: 1px solid ${p => p.theme.colors.bg2};
  transition: border 0.1s ease-in-out, box-shadow 0.1s ease-in-out;
  ${props => transitionName('resource-page', props.subject)};
`;

export const GridItemWrapper = styled.a`
  --shadow: 0px 0.7px 1.3px rgba(0, 0, 0, 0.06),
    0px 1.8px 3.2px rgba(0, 0, 0, 0.043), 0px 3.4px 6px rgba(0, 0, 0, 0.036),
    0px 6px 10.7px rgba(0, 0, 0, 0.03), 0px 11.3px 20.1px rgba(0, 0, 0, 0.024),
    0px 27px 48px rgba(0, 0, 0, 0.017);
  --interaction-shadow: 0px 0px 0px 0px ${p => p.theme.colors.main};
  --card-banner-padding: 1rem;
  --card-banner-height: calc(var(--card-banner-padding) * 2 + 1.5em);
  outline: none;
  text-decoration: none;
  color: ${p => p.theme.colors.text1};
  display: grid;
  grid-template-columns: 1fr;
  grid-template-rows: 1fr 2rem;
  grid-template-areas: 'card' 'title';
  width: 100%;
  aspect-ratio: 1 / 1;
  cursor: pointer;
  gap: 1rem;

  &:hover ${GridCard}, &:focus ${GridCard} {
    --interaction-shadow: 0px 0px 0px 1px ${p => p.theme.colors.main};
    border: 1px solid ${p => p.theme.colors.main};
  }

  &:hover,
  &:focus {
    color: ${p => p.theme.colors.main};
  }
`;

export const GridItemTitle = styled.div<ViewTransitionProps>`
  grid-area: title;
  font-size: 1rem;
  text-align: center;
  white-space: nowrap;
  overflow-x: hidden;
  text-overflow: ellipsis;
  padding-inline: 0.5rem;
  transition: color 0.1s ease-in-out;
  ${props => transitionName('page-title', props.subject)};
`;

export const GridItemDescription = styled.div`
  font-size: 1.1rem;
  color: ${p => p.theme.colors.textLight};
  margin: ${p => p.theme.margin}rem;
  overflow: hidden;
  height: calc(100% - ${p => p.theme.margin * 2}rem);
`;

export const InnerWrapper = styled.div`
  pointer-events: none;
  width: 100%;
  height: calc(100% - var(--card-banner-height));
`;
