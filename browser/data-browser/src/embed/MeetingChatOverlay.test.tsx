// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
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
afterEach(() => {
  cleanup();
  state.closePanel.mockClear();
  state.open = true;
});

const renderOverlay = () =>
  render(
    <ThemeProvider theme={buildTheme(false, '#4C6FA5')}>
      <MeetingChatOverlay />
    </ThemeProvider>,
  );

it('shows the chat when the meeting panel is open', () => {
  renderOverlay();
  expect(screen.getByTestId('meeting-chat-overlay')).toBeTruthy();
  expect(screen.getByText('chat')).toBeTruthy();
});

it('renders nothing when the panel is closed', () => {
  state.open = false;
  renderOverlay();
  expect(screen.queryByTestId('meeting-chat-overlay')).toBeNull();
});

it('closes with the close button', () => {
  renderOverlay();
  fireEvent.click(screen.getByTitle('Close chat'));
  expect(state.closePanel).toHaveBeenCalledWith('followSession');
});

it('closes on back and reports it handled it', () => {
  renderOverlay();
  let handled = false;

  act(() => {
    handled = closeTopOverlay();
  });
  expect(handled).toBe(true);
  expect(state.closePanel).toHaveBeenCalledWith('followSession');
  expect(closeTopOverlay()).toBe(false);
});

it('hides "Start meeting" only embedded', () => {
  expect(showMeetingStart(true)).toBe(false);
  expect(showMeetingStart(false)).toBe(true);
});
