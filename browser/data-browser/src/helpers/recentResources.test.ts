// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import {
  addRecentResource,
  getRecentResources,
  removeRecentResource,
} from './recentResources';

const DRIVE = 'did:ad:drive:one';
const OTHER_DRIVE = 'did:ad:drive:two';

describe('recentResources', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('lists opened resources most recent first, without duplicates', () => {
    addRecentResource(DRIVE, 'did:ad:resource:a');
    addRecentResource(DRIVE, 'did:ad:resource:b');
    addRecentResource(DRIVE, 'did:ad:resource:a');

    expect(getRecentResources(DRIVE)).toEqual([
      'did:ad:resource:a',
      'did:ad:resource:b',
    ]);
  });

  it('keeps drives apart and leaves the drive itself out', () => {
    addRecentResource(DRIVE, DRIVE);
    addRecentResource(DRIVE, 'did:ad:resource:a');
    addRecentResource(OTHER_DRIVE, 'did:ad:resource:b');

    expect(getRecentResources(DRIVE)).toEqual(['did:ad:resource:a']);
    expect(getRecentResources(OTHER_DRIVE)).toEqual(['did:ad:resource:b']);
  });

  it('caps the list', () => {
    for (let i = 0; i < 30; i++) {
      addRecentResource(DRIVE, `did:ad:resource:${i}`);
    }

    expect(getRecentResources(DRIVE)).toHaveLength(20);
    expect(getRecentResources(DRIVE)[0]).toBe('did:ad:resource:29');
  });

  it('forgets a removed resource, in that drive only', () => {
    addRecentResource(DRIVE, 'did:ad:resource:a');
    addRecentResource(DRIVE, 'did:ad:resource:b');
    addRecentResource(OTHER_DRIVE, 'did:ad:resource:a');

    removeRecentResource(DRIVE, 'did:ad:resource:a');
    removeRecentResource(DRIVE, 'did:ad:resource:unknown');

    expect(getRecentResources(DRIVE)).toEqual(['did:ad:resource:b']);
    expect(getRecentResources(OTHER_DRIVE)).toEqual(['did:ad:resource:a']);
  });

  it('survives corrupt storage', () => {
    window.localStorage.setItem('recentResources', '[not json');

    expect(getRecentResources(DRIVE)).toEqual([]);
    addRecentResource(DRIVE, 'did:ad:resource:a');
    expect(getRecentResources(DRIVE)).toEqual(['did:ad:resource:a']);
  });
});
