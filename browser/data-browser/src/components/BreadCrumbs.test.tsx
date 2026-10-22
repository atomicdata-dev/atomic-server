// @vitest-environment jsdom
// @wc-ignore-file
import { cleanup, fireEvent, render } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { BreadCrumbs } from './BreadCrumbs';

const tree: Record<string, { title: string; parent?: string }> = {
  'https://x/drive': { title: 'My drive' },
  'https://x/folder': { title: 'Folder', parent: 'https://x/drive' },
  'https://x/doc': { title: 'A document', parent: 'https://x/folder' },
};

vi.mock('@tomic/react', () => ({
  core: { properties: { parent: 'parent' } },
  useResource: (subject: string) => ({
    subject,
    error: undefined,
    isUnauthorized: () => false,
  }),
  useTitle: (r: { subject: string }) => [tree[r.subject]?.title ?? ''],
  useString: (r: { subject: string }) => [tree[r.subject]?.parent],
}));

const theme = {
  size: () => '1rem',
  fontFamily: 'sans-serif',
  radius: '4px',
  colors: { text: '#000', textLight: '#666', bg2: '#ddd' },
} as unknown as DefaultTheme;

afterEach(cleanup);

it('shows the chain from the drive to the resource', () => {
  const { container } = render(
    <ThemeProvider theme={theme}>
      <BreadCrumbs subject='https://x/doc' />
    </ThemeProvider>,
  );

  expect(container.textContent).toBe('My drive/Folder/A document');
});

it('makes ancestors tappable but not the current resource', () => {
  const onNavigate = vi.fn();
  const { getByText, container } = render(
    <ThemeProvider theme={theme}>
      <BreadCrumbs subject='https://x/doc' onNavigate={onNavigate} />
    </ThemeProvider>,
  );

  fireEvent.click(getByText('Folder'));
  expect(onNavigate).toHaveBeenCalledWith('https://x/folder');
  expect(container.querySelectorAll('button')).toHaveLength(2);
});

it('shows only the name for a drive', () => {
  const { container } = render(
    <ThemeProvider theme={theme}>
      <BreadCrumbs subject='https://x/drive' />
    </ThemeProvider>,
  );

  expect(container.textContent).toBe('My drive');
});
