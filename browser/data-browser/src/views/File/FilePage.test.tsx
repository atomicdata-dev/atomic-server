// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import { Resource, Store, StoreContext, server } from '@tomic/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';
import { FilePage } from './FilePage';

const viewport = vi.hoisted(() => ({ wide: true }));
vi.mock('../../hooks/useMediaQuery', () => ({
  useMediaQuery: () => viewport.wide,
}));
vi.mock('@tomic/react', async original => ({
  ...(await original<typeof import('@tomic/react')>()),
  useCanWrite: () => false,
}));
vi.mock('../../components/EditableTitle', () => ({
  EditableTitle: () => <h1>Recovered file</h1>,
}));
vi.mock('../../components/forms/ValueForm', () => ({ ValueForm: () => null }));
vi.mock('./FilePreview', () => ({ FilePreview: () => null }));
vi.mock('./ConvertToDocumentButton', () => ({
  ConvertToDocumentButton: () => null,
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('recovered file download', () => {
  it.each([true, false])(
    'waits for local bytes before accepting a click (wide: %s)',
    async wide => {
      viewport.wide = wide;
      let resolveBytes!: (bytes: Uint8Array) => void;
      const pending = new Promise<Uint8Array>(resolve => {
        resolveBytes = resolve;
      });
      const store = new Store({
        serverUrl: 'https://example.com',
        connect: false,
      });
      vi.spyOn(store, 'getClientDb').mockReturnValue({
        getBlob: () => pending,
      } as NonNullable<ReturnType<Store['getClientDb']>>);
      const resource = new Resource('atomic:recovered-file');
      const values = new Map<string, string | number>([
        [server.properties.downloadUrl, 'https://example.com/download/file'],
        [server.properties.mimetype, 'application/octet-stream'],
        [server.properties.filesize, 3],
        [
          'https://atomicdata.dev/properties/blob',
          `atomic:blob:${'ab'.repeat(32)}`,
        ],
      ]);
      vi.spyOn(resource, 'get').mockImplementation(property =>
        values.get(property),
      );
      vi.stubGlobal(
        'URL',
        class extends URL {
          static createObjectURL = vi.fn(
            () => 'blob:https://example.com/recovered',
          );
          static revokeObjectURL = vi.fn();
        },
      );
      const open = vi.spyOn(window, 'open').mockReturnValue(null);
      render(
        <StoreContext value={store}>
          <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
            <FilePage resource={resource} />
          </ThemeProvider>
        </StoreContext>,
      );
      const button = screen.getByRole('button') as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      fireEvent.click(button);
      expect(open).not.toHaveBeenCalled();
      await act(async () => {
        resolveBytes(new Uint8Array([1, 2, 3]));
        await pending;
      });
      expect(button.disabled).toBe(false);
      fireEvent.click(button);
      expect(open).toHaveBeenCalledWith('blob:https://example.com/recovered');
    },
  );
});
