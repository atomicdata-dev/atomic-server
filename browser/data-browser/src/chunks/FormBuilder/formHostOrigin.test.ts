import { describe, it, expect, afterEach } from 'vitest';
import { resolveFormHostOrigin } from './formHostOrigin';
import { rememberOriginWithoutNode } from '@helpers/originNode';
import type { ManagedEnrollmentSummary } from '@helpers/managed/enrollmentApi';

const DRIVE = 'did:ad:drive';

function enrollment(
  over: Partial<ManagedEnrollmentSummary>,
): ManagedEnrollmentSummary {
  return {
    drive_subject: DRIVE,
    agent_subject: null,
    status: 'Active',
    resource_count: 5,
    http_origin: 'https://node1.example',
    ...over,
  };
}

describe('resolveFormHostOrigin', () => {
  afterEach(() => rememberOriginWithoutNode(undefined));

  it('prefers the enrollment node over the store server URL', () => {
    expect(
      resolveFormHostOrigin(DRIVE, 'https://app.example', [enrollment({})]),
    ).toBe('https://node1.example');
  });

  it('ignores enrollments of other drives, empty placements and suspended ones', () => {
    for (const e of [
      enrollment({ drive_subject: 'did:ad:other' }),
      enrollment({ resource_count: 0 }),
      enrollment({ status: 'Disabled' }),
    ]) {
      expect(resolveFormHostOrigin(DRIVE, undefined, [e])).toBeUndefined();
    }
  });

  it('falls back to the store server URL when it is a node', () => {
    expect(resolveFormHostOrigin(DRIVE, 'https://my.node/', [])).toBe(
      'https://my.node',
    );
  });

  it('returns undefined when the server URL is the static origin without a node', () => {
    rememberOriginWithoutNode('https://app.example');
    expect(
      resolveFormHostOrigin(DRIVE, 'https://app.example', []),
    ).toBeUndefined();
  });

  it('returns undefined without any server', () => {
    expect(resolveFormHostOrigin(DRIVE, undefined, [])).toBeUndefined();
    expect(resolveFormHostOrigin(DRIVE, 'not a url', [])).toBeUndefined();
  });
});
