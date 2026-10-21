// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';

let showSidebarIcons = true;

vi.mock('../../helpers/AppSettings', () => ({
  useSettings: () => ({ showSidebarIcons }),
}));

const { SideBarMenuRowIcon } = await import('./SideBarMenuItem');

afterEach(cleanup);

const renderIcon = () =>
  render(
    <ThemeProvider theme={buildTheme(false, '#4C6FA5')}>
      <SideBarMenuRowIcon>
        <span data-testid='icon' />
      </SideBarMenuRowIcon>
    </ThemeProvider>,
  );

it('renders a menu row icon by default', () => {
  showSidebarIcons = true;
  renderIcon();
  expect(screen.getByTestId('icon')).toBeTruthy();
});

it('renders no icon slot when the setting is off', () => {
  showSidebarIcons = false;
  const { container } = renderIcon();
  expect(screen.queryByTestId('icon')).toBeNull();
  expect(container.innerHTML).toBe('');
});
