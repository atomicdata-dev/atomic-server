// @vitest-environment jsdom
// @wc-ignore-file
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../styling';
import { ComboBox } from './ComboBox';

vi.mock('@oddbird/css-anchor-positioning/fn', () => ({ default: vi.fn() }));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('keeps an open menu on the visible side when its scroll container moves', async () => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  );
  let bottom = 700;
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
    () => ({
      x: 10,
      y: bottom - 40,
      top: bottom - 40,
      bottom,
      left: 10,
      right: 510,
      width: 500,
      height: 40,
      toJSON() {},
    }),
  );
  Object.defineProperties(HTMLElement.prototype, {
    showPopover: { configurable: true, value: vi.fn() },
    hidePopover: { configurable: true, value: vi.fn() },
  });
  const { getByTestId } = render(
    <ThemeProvider theme={buildTheme(false, '#336699')}>
      <div data-testid='scroll-container'>
        <ComboBox
          options={[
            {
              label: 'Alternate model',
              searchLabel: 'alternate',
              value: 'alternate',
            },
          ]}
          selectedItem={undefined}
          onSelect={vi.fn()}
        />
      </div>
    </ThemeProvider>,
  );
  fireEvent.change(screen.getByRole('combobox'), {
    target: { value: 'Alternate' },
  });
  const menu = screen.getByRole('listbox', { hidden: true });
  await waitFor(() =>
    expect(menu.classList.contains('menu-above-input')).toBe(true),
  );
  // Scrolling changes the anchor's position without changing its size, so a
  // ResizeObserver alone cannot keep the open menu in view.
  bottom = 80;
  fireEvent.scroll(getByTestId('scroll-container'));
  await waitFor(() =>
    expect(menu.classList.contains('menu-above-input')).toBe(false),
  );
  bottom = 700;
  fireEvent.resize(window);
  await waitFor(() =>
    expect(menu.classList.contains('menu-above-input')).toBe(true),
  );
});
