// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import {
  Store,
  StoreContext,
  core,
  dataBrowser,
  notifications,
} from '@tomic/react';
import { NotificationList } from './NotificationList';

const fixture = vi.hoisted(() => ({
  items: [] as unknown[],
  navigate: vi.fn(),
  panel: vi.fn(),
}));
vi.mock('../../hooks/useInbox', () => ({
  useInbox: () => ({ items: fixture.items, unread: 0, loading: false }),
}));
vi.mock('../../hooks/useNavigateWithTransition', () => ({
  useNavigateWithTransition: () => fixture.navigate,
}));
vi.mock('../RightPanel/RightPanelContext', () => ({
  useRightPanel: () => ({ setPanelOpen: fixture.panel }),
}));
vi.mock('../Row', () => ({
  Row: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('../Presence/AgentAvatar', () => ({ AgentAvatar: () => null }));
vi.mock('../../helpers/notifications/inbox', async original => ({
  ...(await original<object>()),
  markRead: vi.fn(),
}));
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it.each([true, false])(
  'opens the source thread for a reply (comment=%s)',
  async isComment => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    store.hydrateResourceFromJsonAd(
      'atomic:source',
      JSON.stringify({
        '@id': 'atomic:source',
        [core.properties.isA]: [dataBrowser.classes.message],
        [isComment ? dataBrowser.properties.about : core.properties.parent]:
          'atomic:target',
      }),
    );
    store.hydrateResourceFromJsonAd(
      'atomic:notification',
      JSON.stringify({
        '@id': 'atomic:notification',
        [core.properties.isA]: [notifications.classes.notification],
        [notifications.properties.notificationSource]: 'atomic:source',
        [notifications.properties.notificationKind]: 'reply',
        [notifications.properties.occurredAt]: Date.now(),
        [dataBrowser.properties.about]: 'atomic:target',
        [core.properties.description]: 'Reply body',
      }),
    );
    let finishNavigation!: () => void;
    fixture.navigate.mockReturnValue(
      new Promise<void>(resolve => {
        finishNavigation = resolve;
      }),
    );
    fixture.items = [await store.getResource('atomic:notification')];
    const { getByRole } = render(
      <StoreContext.Provider value={store}>
        <ThemeProvider
          theme={
            {
              size: () => '4px',
              colors: {},
              animation: {},
            } as unknown as DefaultTheme
          }
        >
          <NotificationList />
        </ThemeProvider>
      </StoreContext.Provider>,
    );
    fireEvent.click(getByRole('button', { name: /Reply body/ }));
    await waitFor(() => expect(fixture.navigate).toHaveBeenCalled());
    expect(fixture.panel).not.toHaveBeenCalled();
    finishNavigation();
    if (isComment)
      await waitFor(() =>
        expect(fixture.panel).toHaveBeenCalledWith('comments', true),
      );
    else expect(fixture.panel).not.toHaveBeenCalled();
  },
);
