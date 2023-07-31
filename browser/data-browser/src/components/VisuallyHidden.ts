import styled from 'styled-components';

/** Hides its content visually but not from assistive technology. */
export const VisuallyHidden = styled.div`
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  height: 1px;
  overflow: hidden;
  position: absolute;
  white-space: nowrap;
  width: 1px;
`;
