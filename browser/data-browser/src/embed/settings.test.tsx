// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../styling';
import {
  embedAppearanceOptions,
  embedSettingsSections,
  showAppearanceOption,
  showSettingsSection,
  type SettingsSectionId,
} from './settings';
import * as embedMode from '../helpers/embedMode';

vi.mock('@tanstack/react-router', () => ({
  createRoute: (options: object) => ({ ...options, useSearch: () => ({}) }),
}));
vi.mock('../routes/RootRoutes', () => ({ appRoute: {} }));
vi.mock('../helpers/AppSettings', () => ({
  useSettings: () => ({
    darkModeSetting: 'auto',
    setDarkMode: () => undefined,
    colorfulMode: false,
    setColorfulMode: () => undefined,
    hideTemplates: false,
    setHideTemplates: () => undefined,
    navbarTop: false,
    setNavbarTop: () => undefined,
    mainColor: '#4C6FA5',
    setMainColor: () => undefined,
    viewTransitionsEnabled: false,
    setViewTransitionsEnabled: () => undefined,
    sidebarKeyboardDndEnabled: false,
    setSidebarKeyboardDndEnabled: () => undefined,
  }),
}));
vi.mock('@components/LocaleContext', () => ({
  SUPPORTED_LOCALES: ['en'],
  useLocale: () => ({ locale: 'en', setLocale: () => undefined }),
}));
vi.mock('../components/SideBar/usePanelList', () => ({
  Panel: {
    Messages: 'm',
    Favorites: 'f',
    SharedWithMe: 's',
    Ontologies: 'o',
    AIChats: 'a',
  },
  usePanelList: () => ({
    enabledPanels: new Set(),
    enablePanel: () => undefined,
    disablePanel: () => undefined,
  }),
}));
vi.mock('@components/Settings', () => ({
  SettingsGroup: ({ children }: React.PropsWithChildren) => <>{children}</>,
  SettingsSearchProvider: ({ children }: React.PropsWithChildren) => (
    <>{children}</>
  ),
  SettingsSection: ({
    label,
    children,
  }: React.PropsWithChildren<{ label: string }>) => (
    <section aria-label={label}>{children}</section>
  ),
}));
vi.mock('@components/Settings/IntegrationSettings', () => ({
  IntegrationSettings: () => <section aria-label='Integration' />,
}));
vi.mock('@components/Settings/NotificationSettings', () => ({
  NotificationSettings: () => <p>notification settings</p>,
}));
vi.mock('@components/Settings/VirtualDriveSettings', () => ({
  VirtualDriveSettings: () => null,
}));
vi.mock('@components/AI/AISettings', () => ({
  default: () => <section aria-label='AI' />,
}));
vi.mock('../helpers/virtualDrive', () => ({
  isVirtualDriveAvailable: () => false,
}));

const { AppSettingsRoute } = await import('../routes/AppSettings');

const renderPage = () => {
  const Page = (AppSettingsRoute as unknown as { component: React.FC })
    .component;

  return render(
    <ThemeProvider theme={buildTheme(false, '#4C6FA5')}>
      <Page />
    </ThemeProvider>,
  );
};

beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it('shows every section outside the embed', () => {
  const ids: SettingsSectionId[] = [
    'appearance',
    'accessibility',
    'notifications',
    'virtualDrive',
    'ai',
    'integration',
  ];

  for (const id of ids) expect(showSettingsSection(id, false)).toBe(true);

  expect(showAppearanceOption('navbarPosition', false)).toBe(true);
  expect(showAppearanceOption('panels', false)).toBe(true);
});

it('shows only the allow-listed sections and options in the embed', () => {
  expect(showSettingsSection('appearance', true)).toBe(true);

  for (const id of [
    'accessibility',
    'notifications',
    'virtualDrive',
    'ai',
    'integration',
  ] as const) {
    expect(showSettingsSection(id, true)).toBe(false);
  }

  expect([...embedSettingsSections]).toEqual(['appearance']);
  expect(showAppearanceOption('theme', true)).toBe(true);
  expect(showAppearanceOption('navbarPosition', true)).toBe(false);
  expect(showAppearanceOption('colorfulMode', true)).toBe(false);
  expect(showAppearanceOption('panels', true)).toBe(false);
  expect(embedAppearanceOptions.has('language')).toBe(true);
});

it('renders the full page outside the embed', () => {
  renderPage();

  for (const label of ['Appearance', 'Accessibility', 'Notifications', 'AI']) {
    expect(screen.getByLabelText(label)).toBeTruthy();
  }

  expect(screen.getByLabelText('Integration')).toBeTruthy();
  expect(screen.getByLabelText('Panels & Templates')).toBeTruthy();
  expect(screen.getByText('NavBar position')).toBeTruthy();
});

it('renders only Appearance, without the chrome options, in the embed', () => {
  vi.spyOn(embedMode, 'isEmbedded').mockReturnValue(true);
  renderPage();

  expect(screen.getByLabelText('Appearance')).toBeTruthy();
  expect(screen.getByText('Theme')).toBeTruthy();
  expect(screen.getByText('Main color')).toBeTruthy();
  expect(screen.getByText('Language')).toBeTruthy();
  expect(screen.getByText('Hide templates on new resource page')).toBeTruthy();

  for (const label of ['Accessibility', 'Notifications', 'AI', 'Integration']) {
    expect(screen.queryByLabelText(label)).toBeNull();
  }

  expect(screen.queryByText('NavBar position')).toBeNull();
  expect(screen.queryByText('Colorful mode')).toBeNull();
  expect(screen.queryByText('Show Messages panel')).toBeNull();
});
