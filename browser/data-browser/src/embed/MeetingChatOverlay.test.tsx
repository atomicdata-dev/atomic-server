// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import { MeetingChatOverlay } from './MeetingChatOverlay';
import { closeTopOverlay } from './overlayBack';
import { showMeetingStart } from './settings';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../styling';

const state = vi.hoisted(() => ({
  selected: 'https://x/meeting' as string | undefined,
  open: true,
  closePanel: vi.fn(),
}));

vi.mock('../components/RightPanel/RightPanelContext', () => ({
  useRightPanel: () => ({
    selectedMeeting: state.selected,
    closePanel: state.closePanel,
  }),
}));
const host = vi.hoisted(() => ({ handled: false, openNative: vi.fn() }));

vi.mock('./hostActions', () => ({
  openNative: (...args: unknown[]) => host.openNative(...args),
}));
vi.mock('../components/RightPanel/useContextualPanel', () => ({
  useContextualPanel: () => state.open,
}));
vi.mock('../components/Presence/FollowContext', () => ({
  useFollow: () => ({}),
}));
vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useResource: () => ({}),
}));
vi.mock('../views/ChatRoom/ChatRoomView', () => ({
  ChatRoomView: () => <div>chat</div>,
}));
vi.mock('../components/EditableTitle', () => ({
  EditableTitle: () => <h1>Title</h1>,
}));
beforeEach(() => {
  host.handled = false;
  host.openNative.mockImplementation(async () => host.handled);
});
afterEach(() => {
  cleanup();
  host.openNative.mockReset();
  state.closePanel.mockClear();
  state.open = true;
});

const renderOverlay = () =>
  render(
    <ThemeProvider theme={buildTheme(false, '#4C6FA5')}>
      <MeetingChatOverlay />
    </ThemeProvider>,
  );

it('shows the chat when the meeting panel is open', async () => {
  renderOverlay();
  expect(await screen.findByTestId('meeting-chat-overlay')).toBeTruthy();
  expect(screen.getByText('chat')).toBeTruthy();
});

it('renders nothing when the panel is closed', () => {
  state.open = false;
  renderOverlay();
  expect(screen.queryByTestId('meeting-chat-overlay')).toBeNull();
});

it('closes with the close button', async () => {
  renderOverlay();
  await screen.findByTestId('meeting-chat-overlay');
  fireEvent.click(screen.getByTitle('Close chat'));
  expect(state.closePanel).toHaveBeenCalledWith('followSession');
});

it('closes on back and reports it handled it', async () => {
  renderOverlay();
  await screen.findByTestId('meeting-chat-overlay');
  let handled = false;

  act(() => {
    handled = closeTopOverlay();
  });
  expect(handled).toBe(true);
  expect(state.closePanel).toHaveBeenCalledWith('followSession');
  expect(closeTopOverlay()).toBe(false);
});

it('asks the app to open its native chat first, and shows no overlay when it does', async () => {
  host.handled = true;
  renderOverlay();
  await vi.waitFor(() =>
    expect(state.closePanel).toHaveBeenCalledWith('followSession'),
  );
  expect(host.openNative).toHaveBeenCalledTimes(1);
  expect(host.openNative.mock.calls[0].slice(0, 2)).toEqual([
    'chatroom',
    'https://x/meeting',
  ]);
  expect(screen.queryByTestId('meeting-chat-overlay')).toBeNull();
});

it('falls back to the overlay when the app declines', async () => {
  renderOverlay();
  expect(await screen.findByTestId('meeting-chat-overlay')).toBeTruthy();
  expect(host.openNative).toHaveBeenCalledTimes(1);
  expect(state.closePanel).not.toHaveBeenCalled();
});

it('hides "Start meeting" only embedded', () => {
  expect(showMeetingStart(true)).toBe(false);
  expect(showMeetingStart(false)).toBe(true);
});
