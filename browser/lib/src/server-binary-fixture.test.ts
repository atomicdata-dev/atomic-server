import { afterEach, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { serverBinaryPath } from '../tests/server-fixture.js';

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
  spawn: vi.fn(),
}));
afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetAllMocks();
});

it('uses the mounted CI binary without requiring Cargo', () => {
  vi.stubEnv('ATOMIC_SERVER_BINARY', '/repo/target/debug/atomic-server');
  expect(serverBinaryPath()).toBe('/repo/target/debug/atomic-server');
  expect(execFileSync).not.toHaveBeenCalled();
});

it('resolves the configured Cargo target directory for local builds', () => {
  vi.stubEnv('ATOMIC_SERVER_BINARY', '');
  vi.mocked(execFileSync).mockReturnValue(
    JSON.stringify({ target_directory: '/custom/target' }),
  );
  expect(serverBinaryPath()).toBe('/custom/target/debug/atomic-server');
  expect(execFileSync).toHaveBeenCalledWith(
    'cargo',
    ['metadata', '--format-version=1', '--no-deps'],
    expect.objectContaining({ encoding: 'utf8' }),
  );
});
