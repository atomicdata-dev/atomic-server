// @vitest-environment jsdom
// @wc-ignore-file
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Store } from '@tomic/lib';
import { StoreContext } from '@tomic/react';
import {
  RouterProvider,
  createMemoryHistory,
  createRootRoute,
  createRouter,
} from '@tanstack/react-router';
import { afterEach, expect, it, vi } from 'vitest';
import { Providers } from './Providers';
import { hostOnPortalNudge } from './helpers/hostOnPortalNudge';

vi.mock('./helpers/managedServer', async importOriginal => ({
  ...(await importOriginal<typeof import('./helpers/managedServer')>()),
  fetchManagedInfo: vi.fn(async () => ({ managed: false })),
}));
vi.mock('./helpers/managed/cloudSync', async importOriginal => ({
  ...(await importOriginal<typeof import('./helpers/managed/cloudSync')>()),
  driveHasCloudEnrollment: vi.fn(async () => false),
}));
vi.mock('./helpers/managed/hostOnPortal', async importOriginal => ({
  ...(await importOriginal<typeof import('./helpers/managed/hostOnPortal')>()),
  knownPortalUrl: () => 'https://atomic.place',
}));

// jsdom has no modal <dialog>; opening one is all this test needs from it.
HTMLDialogElement.prototype.showModal = function showModal() {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function close() {
  this.removeAttribute('open');
  this.dispatchEvent(new Event('close'));
};

window.matchMedia ??= (query: string) =>
  ({
    matches: false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
    onchange: null,
  }) as MediaQueryList;

class NoopObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= NoopObserver as never;
globalThis.IntersectionObserver ??= NoopObserver as never;

afterEach(cleanup);

it('opens the hosting consent dialog from the toast offer', async () => {
  const store = new Store({ serverUrl: 'http://localhost:9883' });

  const root = createRootRoute({
    component: () => (
      <Providers>
        <button onClick={() => hostOnPortalNudge('did:ad:test')}>nudge</button>
      </Providers>
    ),
  });
  const router = createRouter({
    routeTree: root,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });

  render(
    <StoreContext.Provider value={store}>
      <RouterProvider router={router} />
    </StoreContext.Provider>,
  );

  fireEvent.click(await screen.findByText('nudge', {}, { timeout: 5000 }));
  fireEvent.click(await screen.findByTestId('host-on-portal'));

  expect(await screen.findByText('Agree and host')).toBeTruthy();
});
