import { css, styled } from 'styled-components';
import { LAYOUT_CONTAINER } from '../helpers/containers';

const common = css`
  margin: auto;
  padding: ${p => p.theme.size()};
  container: ${LAYOUT_CONTAINER} / inline-size;
  padding-bottom: 10rem;
`;

/** Centered column */
export const ContainerNarrow = styled.div`
  width: min(100%, ${p => p.theme.containerWidth}rem);
  ${common}
`;

export const ContainerWide = styled.div`
  width: min(100%, ${p => p.theme.containerWidthWide});
  ${common}
`;

/** Full-page wrapper */
export const ContainerFull = styled.div`
  container: ${LAYOUT_CONTAINER} / inline-size;
  padding: ${p => p.theme.size()};
  padding-bottom: 10rem;
`;
