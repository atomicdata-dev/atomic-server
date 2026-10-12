import { css, styled } from 'styled-components';
import { transition } from '../helpers/transition';

/**
 * A flat top-bar action button (Share, Comments, AI, Meet). Shared so the
 * meeting button matches the others exactly. When its sidebar panel is open,
 * `$active` tints it with the theme's main color — the same "current item"
 * cue the left sidebar uses — over a subtle background so the toggled-on
 * state reads clearly.
 */
export const NAV_BUTTON_HEIGHT = '1.75rem';
export const NAV_BUTTON_RADIUS = '6px';

/** Touch screens get 40px targets; labels are dropped there (see below). */
export const TOUCH_TARGET = '2.5rem';

/**
 * Viewport-based (not container-based) "compact" test, so it is true from the
 * very first paint, before the nav's container has been measured.
 */
export const COMPACT_MEDIA = '(max-width: 600px), (pointer: coarse)';

export const LabelButton = styled.button<{ $active?: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.5ch;
  padding: 0 0.5rem;
  /* Shorter than a regular button, with a tighter corner, so the hover and
   * active shape sits inside the narrow bar instead of filling it edge to
   * edge like a pill. The bar's icon buttons use the same shape
   * (NAV_BUTTON_HEIGHT / NAV_BUTTON_RADIUS). */
  height: ${NAV_BUTTON_HEIGHT};
  border: none;
  border-radius: ${NAV_BUTTON_RADIUS};
  background: ${p => (p.$active ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => (p.$active ? p.theme.colors.main : p.theme.colors.textLight)};
  cursor: pointer;
  font-size: 0.875rem;
  white-space: nowrap;
  ${transition('background-color', 'color')}

  /* Icons at the same size as the bar's IconButtons, while labels stay
   * slightly smaller than body text. */
  svg {
    font-size: 1rem;
  }

  @container breadcrumb-bar (max-width: 600px) {
    > span {
      display: none;
    }
  }

  @media ${COMPACT_MEDIA} {
    > span {
      display: none;
    }
  }

  @media (pointer: coarse) {
    min-width: ${TOUCH_TARGET};
    height: ${TOUCH_TARGET};
    justify-content: center;

    svg {
      font-size: 1.25rem;
    }
  }

  &[disabled] {
    opacity: 0.5;
    cursor: not-allowed;
  }

  &:not([disabled]) {
    &:hover,
    &:focus-visible {
      background: ${p => p.theme.colors.bg1};
      color: ${p => (p.$active ? p.theme.colors.main : p.theme.colors.text)};
    }

    &:active {
      background: ${p => p.theme.colors.bg2};
    }
  }
`;

export const ButtonArea = styled.div<{ $iconOnly: boolean }>`
  display: flex;
  margin-left: auto;
  color: ${p => p.theme.colors.textLight};
  gap: ${p => p.theme.size(1)};
  align-items: center;
  min-width: 0;
  overflow: hidden;

  @container breadcrumb-bar (max-width: 600px) {
    gap: 0;
  }

  @media ${COMPACT_MEDIA} {
    gap: 0;
  }

  /* Icon-only once the bar can no longer fit the labels (measured in JS, not a
   * fixed breakpoint). */
  ${p =>
    p.$iconOnly &&
    css`
      ${LabelButton} > span {
        display: none;
      }
    `}
`;
