// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';
import { IntegrationSettings } from './IntegrationSettings';
import { defaultIntegrationProxy } from '@helpers/integrationProxy';
import { defaultPluginCatalogUrl } from '@helpers/pluginCatalogUrl';

vi.mock('@hooks/useIntegrationVisibility', () => ({
  useIntegrationVisibility: () => ({
    showExperimentalPlugins: false,
    ready: true,
    pending: false,
    error: undefined,
    setVisibility: () => undefined,
  }),
}));

vi.mock('./SettingsSection', () => ({
  SettingsSection: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

beforeEach(() => localStorage.clear());
afterEach(cleanup);

const renderSettings = () =>
  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <IntegrationSettings />
    </ThemeProvider>,
  );

const proxyInput = () =>
  screen.getByLabelText('Integration proxy URL') as HTMLInputElement;
const catalogInput = () =>
  screen.getByLabelText('Plugin catalog URL') as HTMLInputElement;
const resetButtons = () => screen.queryAllByRole('button', { name: 'Reset' });

it('shows only Save buttons, and no Reset while values are the defaults', () => {
  renderSettings();

  expect(proxyInput().value).toBe(defaultIntegrationProxy);
  expect(catalogInput().value).toBe(defaultPluginCatalogUrl);
  expect(screen.getAllByRole('button', { name: 'Save' })).toHaveLength(2);
  expect(resetButtons()).toHaveLength(0);
  expect(screen.queryByText('Reset to default')).toBeNull();
});

it('shows an inline Reset once the value differs, and resets it', () => {
  renderSettings();

  fireEvent.change(proxyInput(), {
    target: { value: 'https://proxy.example.com' },
  });
  expect(resetButtons()).toHaveLength(1);

  fireEvent.click(resetButtons()[0]);
  expect(proxyInput().value).toBe(defaultIntegrationProxy);
  expect(resetButtons()).toHaveLength(0);
});

it('resets a saved value back to the default', () => {
  localStorage.setItem(
    'plugin-catalog-url',
    'https://catalog.example.com/catalog.json',
  );
  renderSettings();

  expect(catalogInput().value).toBe('https://catalog.example.com/catalog.json');
  expect(resetButtons()).toHaveLength(1);

  fireEvent.click(resetButtons()[0]);
  expect(localStorage.getItem('plugin-catalog-url')).toBeNull();
  expect(catalogInput().value).toBe(defaultPluginCatalogUrl);
  expect(resetButtons()).toHaveLength(0);
});
