import { describe, expect, it } from 'vitest';
import { driveHostingState } from './driveHostingState';

describe('drive hosting states', () => {
  it('only labels explicit device-only storage Local', () => {
    expect(driveHostingState(true)).toEqual(['Local']);
    expect(driveHostingState(false)).toEqual(['Remote']);
  });
  it.each(['Pending', 'Active'])(
    'does not claim an empty %s placement is hosted',
    status => {
      expect(driveHostingState(false, { status, resource_count: 0 })).toEqual([
        'Server setup',
      ]);
    },
  );
  it('shows readable hosting and encrypted backup as separate services', () => {
    expect(
      driveHostingState(
        false,
        { status: 'Active', resource_count: 5 },
        { status: 'active', last_backup_at: 123 },
      ),
    ).toEqual(['Server', 'Vault']);
    expect(
      driveHostingState(true, undefined, {
        status: 'active',
        last_backup_at: null,
      }),
    ).toEqual(['Local', 'Vault setup']);
  });
  it.each([
    ['Suspended', 'Server paused'],
    ['Error', 'Server error'],
    ['unrecognized', 'Server unknown'],
  ])('preserves %s instead of showing a healthy server', (status, label) => {
    expect(driveHostingState(false, { status, resource_count: 5 })).toEqual([
      label,
    ]);
  });
  it('does not show disabled services as enabled', () => {
    expect(
      driveHostingState(
        true,
        { status: 'Disabled' },
        { status: 'disabled', last_backup_at: 123 },
      ),
    ).toEqual(['Local']);
  });
});
