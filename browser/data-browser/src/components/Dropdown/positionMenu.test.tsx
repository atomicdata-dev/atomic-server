// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';
import { DropdownMenu } from './index';
import { DropdownContainer } from './DropdownContainer';
import type { DropdownTriggerProps } from './DropdownTrigger';

const theme = buildTheme(false, '#1b50d8');

const MENU_WIDTH = 300;
const NARROW = 390;
const WIDE = 600;

const Trigger = ({ onClick, ref, id, menuId }: DropdownTriggerProps) => (
  <button id={id} aria-controls={menuId} ref={ref} onClick={onClick}>
    open
  </button>
);

beforeEach(() => {
  Element.prototype.scrollIntoView = () => undefined;
  // jsdom has no layout: give every element a fixed layout width and put the
  // trigger near the right edge, like the chevron after a long drive title.
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(
    MENU_WIDTH,
  );
  vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(200);
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
    function (this: HTMLElement) {
      const isTrigger = this.tagName === 'BUTTON';

      return {
        x: isTrigger ? 352 : 0,
        y: 16,
        left: isTrigger ? 352 : 0,
        top: 16,
        right: isTrigger ? 384 : MENU_WIDTH,
        bottom: 48,
        width: isTrigger ? 32 : MENU_WIDTH,
        height: 32,
        toJSON: () => ({}),
      } as DOMRect;
    },
  );
  // A page wider than the screen: the layout viewport (`innerWidth`) is
  // widened, the visual viewport is what the phone actually shows.
  vi.stubGlobal('innerWidth', WIDE);
  vi.stubGlobal('innerHeight', 844);
  vi.stubGlobal('visualViewport', {
    scale: 1,
    offsetTop: 0,
    offsetLeft: 0,
    width: NARROW,
    height: 844,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('keeps a menu opened near the right edge inside the visible viewport', async () => {
  const { getByText, findByRole } = render(
    <ThemeProvider theme={theme}>
      <DropdownContainer>
        <DropdownMenu
          Trigger={Trigger}
          items={[
            { id: 'a', label: 'A long drive name', onClick: () => undefined },
          ]}
        />
      </DropdownContainer>
    </ThemeProvider>,
  );

  fireEvent.click(getByText('open'));

  const menu = await findByRole('menu');

  await waitFor(() => expect(menu.style.left).not.toBe(''));

  const left = parseFloat(menu.style.left);

  expect(left).toBeGreaterThanOrEqual(8);
  expect(left + MENU_WIDTH).toBeLessThanOrEqual(NARROW - 8);
  expect(parseFloat(menu.style.maxWidth)).toBeLessThanOrEqual(NARROW - 16);
});
