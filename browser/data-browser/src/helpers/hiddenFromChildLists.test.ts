import { describe, expect, it } from 'vitest';
import { ai, dataBrowser } from '@tomic/lib';
import { isHiddenFromChildLists } from './hiddenFromChildLists';

const agent = 'did:ad:agent:abc';

describe('isHiddenFromChildLists', () => {
  it('hides AI chats and meetings', () => {
    expect(isHiddenFromChildLists([ai.classes.aiChat])).toBe(true);
    expect(isHiddenFromChildLists([dataBrowser.classes.meeting])).toBe(true);
  });

  it('hides a private note on an agent', () => {
    expect(isHiddenFromChildLists([dataBrowser.classes.plainText], agent)).toBe(
      true,
    );
  });

  it('keeps a document that merely has an about value', () => {
    expect(
      isHiddenFromChildLists([dataBrowser.classes.plainText], 'did:ad:abc'),
    ).toBe(false);
    expect(
      isHiddenFromChildLists([dataBrowser.classes.documentV2], agent),
    ).toBe(false);
  });
});
