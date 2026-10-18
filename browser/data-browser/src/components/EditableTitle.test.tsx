// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { EditableTitle } from './EditableTitle';

vi.mock('@tomic/react', () => ({
  StoreEvents: { ResourceManuallyCreated: 'created' },
  useCanWrite: () => true,
  useStore: () => ({
    consumeRecentlyCreated: () => false,
    on: () => () => undefined,
  }),
  useTitle: () => ['Title', vi.fn()],
}));
vi.mock('../hooks/useInlineTitleAffordances', () => ({
  useInlineTitleAffordances: () => true,
}));
// Referred to by selector in EditableTitle's styles, so it must be styled.
vi.mock('./Row', async () => ({
  Flex: (await import('styled-components')).styled.div``,
}));
// The picker is mounted by EditableTitle, outside the title it is opened from.
vi.mock('./ResourceDecorations', async () => ({
  AffordanceRow: (await import('styled-components')).styled.div``,
  TitleIcon: ({ onPickIcon }: { onPickIcon: () => void }) => (
    <button
      onClick={e => {
        // Like the real one (see ResourceDecorations.test.tsx).
        e.stopPropagation();
        onPickIcon();
      }}
    >
      icon
    </button>
  ),
  TitleDecorationAffordances: ({ onPickIcon }: { onPickIcon: () => void }) => (
    <button onClick={onPickIcon}>Add icon</button>
  ),
  IconPickerDialog: ({ show }: { show: boolean }) => (
    <div data-testid='picker'>{show ? 'open' : 'closed'}</div>
  ),
}));

afterEach(cleanup);

const theme = {
  size: () => '1rem',
  margin: 1,
  fontSizeH1: 2,
  radius: '4px',
  fontFamilyHeader: 'sans-serif',
  animation: { duration: '0s' },
  colors: new Proxy({}, { get: () => '#000' }),
} as unknown as DefaultTheme;

const renderTitle = () =>
  render(
    <ThemeProvider theme={theme}>
      <EditableTitle resource={resource} withDecorations />
    </ThemeProvider>,
  );

const resource = { subject: 'did:ad:page', __internalObject: {} } as never;

describe('EditableTitle icon picker', () => {
  it('mounts no picker until one is asked for', () => {
    renderTitle();

    expect(screen.queryByTestId('picker')).toBeNull();
  });

  it.each(['icon', 'Add icon'])(
    'opens one picker from the "%s" button, outside the title, without editing it',
    name => {
      renderTitle();

      fireEvent.click(screen.getByText(name, { selector: 'button' }));

      const picker = screen.getByTestId('picker');
      expect(picker.textContent).toBe('open');
      expect(picker.closest('h1')).toBeNull();
      expect(screen.queryByRole('textbox')).toBeNull();
      expect(screen.getAllByTestId('picker')).toHaveLength(1);
    },
  );
});
