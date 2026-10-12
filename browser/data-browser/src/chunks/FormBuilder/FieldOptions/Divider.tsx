import { styled } from 'styled-components';

/**
 * Thin rule that separates one setting/option from the next in the field
 * settings panel. Bleeds full width by countering the panel's own padding
 * (`SettingsSlot` in `FormBuilderPage`), so it reads as a break across the
 * whole sidebar rather than just the width of whichever option row it sits
 * between.
 */
export const Divider = styled.hr`
  border: none;
  border-top: 1px solid ${p => p.theme.colors.bg2};
  margin: 0px -${p => p.theme.size()};
`;
