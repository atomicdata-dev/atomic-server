import { styled } from 'styled-components';
import { InputWrapper } from '@components/forms/InputStyles';

/**
 * Two option inputs side by side (min/max, low/high label, ...).
 *
 * A flex Row can't do this in the settings panel: the inputs' intrinsic width
 * exceeds half the sidebar, so they'd either wrap onto separate lines or
 * overflow. Equal grid tracks plus zeroed minimum widths let them shrink to
 * the track instead — `BasicSelect` brings its own `min-width` that has to be
 * relaxed too.
 */
export const FieldPair = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
  align-items: end;

  & > * {
    min-width: 0;
  }

  ${InputWrapper} {
    min-width: 0;
  }
`;
