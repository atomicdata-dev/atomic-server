import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { HOST_ERROR_CODES, HostError, toHostErrorCode } from './hostAbi';

it('uses the error codes the Rust host uses', () => {
  const source = readFileSync(
    new URL('../../../server/src/plugins/host_abi/mod.rs', import.meta.url),
    'utf8',
  );
  const block = /pub mod code \{([\s\S]*?)\n\}/.exec(source)?.[1] ?? '';
  const rust = [...block.matchAll(/pub const \w+: &str = "([^"]+)"/g)]
    .map(m => m[1])
    .sort();

  expect(rust.length).toBeGreaterThan(0);
  expect([...HOST_ERROR_CODES].sort()).toEqual(rust);
});

it('maps unknown codes to internal', () => {
  expect(toHostErrorCode('forbidden')).toBe('forbidden');
  expect(toHostErrorCode('new-code')).toBe('internal');
  expect(new HostError('not-found', 'x')).toMatchObject({
    code: 'not-found',
    message: 'x',
    name: 'HostError',
  });
});
