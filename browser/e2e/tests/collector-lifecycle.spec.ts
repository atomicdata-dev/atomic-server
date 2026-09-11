import { EventEmitter } from 'node:events';
import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { DiagnosticCollector } from './diagnostic-collector';
import { TransportCollector } from './transport-collector';

function surfaces() {
  const page = new EventEmitter();
  const context = Object.assign(new EventEmitter(), { pages: () => [page] });

  return {
    page,
    context,
    browserContext: context as unknown as BrowserContext,
  };
}

const warning = (text: string) => ({
  type: () => 'warning',
  text: () => text,
  location: () => ({ url: 'https://example.test/' }),
});

test('diagnostic collector start and disposal are idempotent and preserve snapshots', () => {
  const { context, browserContext } = surfaces();
  const collector = new DiagnosticCollector();
  collector.expect(
    'warning',
    /^Expected$/g,
    'Exercise lifecycle',
    2,
    /example/g,
  );
  collector.start(browserContext);
  collector.start(browserContext);
  context.emit('console', warning('Expected'));
  const first = collector.snapshot();
  expect(first.entries).toHaveLength(1);
  expect(first.missing[0].seen).toBe(1);
  collector.dispose();
  collector.dispose();
  expect(context.listenerCount('console')).toBe(0);
  expect(context.listenerCount('weberror')).toBe(0);
  context.emit('console', warning('Detached'));
  expect(collector.snapshot()).toEqual(first);
  collector.start(browserContext);
  context.emit('console', warning('Expected'));
  context.emit('console', warning('Expected'));
  const last = collector.snapshot();
  expect(last.missing).toEqual([]);
  expect(last.unexpected).toHaveLength(1);
  expect(first.entries).toHaveLength(1);
  expect(first.missing[0].seen).toBe(1);
  collector.dispose();
});

test('transport collector bounds metadata and detaches context, page and socket listeners', () => {
  const { context, page, browserContext } = surfaces();
  const collector = new TransportCollector();
  const socket = new EventEmitter();
  collector.start(browserContext);
  collector.start(browserContext);
  page.emit('websocket', socket);

  for (let i = 0; i < 40; i++) {
    socket.emit('framesent', { payload: 'DO_NOT_ATTACH' });
  }

  const handle = page as unknown as Page;
  expect(collector.snapshot(handle)).toHaveLength(30);
  expect(JSON.stringify(collector.snapshot(handle))).not.toContain(
    'DO_NOT_ATTACH',
  );
  expect(socket.listenerCount('framesent')).toBe(1);
  socket.emit('close');
  expect(socket.listenerCount('framesent')).toBe(0);
  expect(socket.listenerCount('framereceived')).toBe(0);
  expect(socket.listenerCount('close')).toBe(0);
  expect(collector.snapshot(handle).at(-1)?.direction).toBe('closed');
  const liveSocket = new EventEmitter();
  page.emit('websocket', liveSocket);
  page.emit('close');
  const evidence = collector.snapshot(handle);
  expect(collector.pages()).toContain(handle);
  collector.dispose();
  collector.dispose();
  expect(context.listenerCount('page')).toBe(0);
  expect(page.listenerCount('websocket')).toBe(0);

  for (const event of ['framesent', 'framereceived', 'close']) {
    expect(liveSocket.listenerCount(event)).toBe(0);
  }

  liveSocket.emit('framesent', { payload: 'Detached' });
  expect(collector.snapshot(handle)).toEqual(evidence);
  collector.start(browserContext);
  expect(page.listenerCount('websocket')).toBe(1);
  collector.dispose();
});
