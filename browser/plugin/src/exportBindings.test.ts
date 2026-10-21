import { afterEach, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { ViewStore } from './store';
import { generateExportBindings } from './exportBindings';
import {
  statementRead,
  type StatementReadResult,
} from '../../../plugin-examples/host-abi-statement/bindings';

afterEach(() => {
  vi.unstubAllGlobals();
});

const example = (file: string) =>
  readFileSync(
    new URL(
      `../../../plugin-examples/host-abi-statement/${file}`,
      import.meta.url,
    ),
    'utf8',
  );

it('keeps the checked-in bindings in step with the manifest', () => {
  // Regenerate: pnpm generate-bindings <manifest.json> <bindings.ts>
  expect(generateExportBindings(JSON.parse(example('manifest.json')))).toBe(
    example('bindings.ts'),
  );
});

it('calls a Rust component through a typed frame store, over /host/call', async () => {
  const listeners: Array<(event: MessageEvent) => void> = [];
  const parent = { postMessage: vi.fn() };
  vi.stubGlobal('window', {
    parent,
    addEventListener: (type: string, listener: (typeof listeners)[number]) =>
      type === 'message' && listeners.push(listener),
    removeEventListener: vi.fn(),
  });
  const store = new ViewStore();

  const pending = statementRead(store, {
    statement: '2026-01-03,Coffee,-12.5',
  });
  const request = parent.postMessage.mock.calls[0][0];
  // The frame never loads the component: the host routes this to the server.
  expect(request).toMatchObject({
    op: 'call',
    args: {
      interface: 'atomic:example/statement@1',
      function: 'read',
      args: { statement: '2026-01-03,Coffee,-12.5' },
    },
  });

  const result: StatementReadResult = {
    count: 1,
    totalMinor: -1250,
    transactions: [
      { date: '2026-01-03', description: 'Coffee', amountMinor: -1250 },
    ],
  };
  listeners.forEach(listener =>
    listener({
      source: parent,
      data: {
        type: 'atomic.view.response',
        version: 1,
        id: request.id,
        result,
      },
    } as unknown as MessageEvent),
  );

  const typed = await pending;
  // `typed` has the manifest's types: this line fails `tsc` if they drift.
  expect(typed.transactions.map(t => t.amountMinor)).toEqual([-1250]);
  expect(typed).toEqual(result);

  // @ts-expect-error `statement` is a string, the manifest says so.
  void statementRead(store, { statement: 5 });
});
