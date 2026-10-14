// @vitest-environment jsdom
// @wc-ignore-file
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it, vi } from 'vitest';
import { StorageView } from './StorageView';
import { buildStorageTree } from '../helpers/storageMap';
import { buildTheme } from '../styling';
afterEach(cleanup);
it('keeps folder drilldown and resource navigation through the shared size map', () => {
  const root = buildStorageTree(
    [
      {
        subject: 'drive',
        name: 'Workspace',
        parent: null,
        isA: null,
        loroBytes: 0,
        blobBytes: 0,
      },
      {
        subject: 'folder',
        name: 'Folder',
        parent: 'drive',
        isA: null,
        loroBytes: 0,
        blobBytes: 0,
      },
      {
        subject: 'note',
        name: 'Note',
        parent: 'folder',
        isA: null,
        loroBytes: 1024,
        blobBytes: 0,
      },
    ],
    'drive',
  );
  const open = vi.fn();
  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <StorageView loaded={{ state: 'ready', root }} onOpen={open} />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByTestId('storage-tile'));
  expect(open).not.toHaveBeenCalled();
  expect(screen.getByTestId('storage-tile').textContent).toContain('Note');
  fireEvent.click(screen.getByTestId('storage-tile'));
  expect(open).toHaveBeenCalledWith('note');
  fireEvent.click(screen.getByRole('button', { name: 'Workspace' }));
  expect(screen.getByTestId('storage-tile').textContent).toContain('Folder');
});
