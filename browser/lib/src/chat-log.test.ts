import { describe, it } from 'vitest';
import type { Commit } from './commit.js';
import { decodeB64 } from './base64.js';
import { core, dataBrowser } from './index.js';
import { LoroLoader } from './loro-loader.js';
import { testStore } from './test-store.js';
import {
  CHAT_LOG_ENTRIES,
  newChatLogEntryKey,
  type ChatLogEntry,
} from './chat-log.js';

const alice = 'did:ad:agent:alice';

async function chatLogPage() {
  const { store, postCommitSpy, agentDID } = await testStore();
  const drive = await store.newResource({
    isA: core.classes.drive,
    propVals: { [core.properties.name]: 'Home' },
    noParent: true,
  });
  await drive.save();
  const page = await store.newResource({
    isA: dataBrowser.classes.chatLog,
    parent: drive.subject,
  });
  await page.save();
  // The genesis the page was created with; later commits are deltas on it.
  const genesis = postCommitSpy.mock.calls
    .map(c => c[0] as Commit)
    .find(c => c.subject === page.subject)!;
  postCommitSpy.mockClear();

  return { store, page, postCommitSpy, agentDID, genesis };
}

const bytesOf = (c: Commit) => {
  const u = c.loroUpdate as unknown;

  return typeof u === 'string' ? decodeB64(u) : (u as Uint8Array);
};

/** The entries the server would hold after applying `commits` in order. */
function entriesAfter(...commits: Commit[]): Record<string, ChatLogEntry> {
  const doc = new LoroLoader.Loro.LoroDoc();

  for (const commit of commits) {
    doc.import(bytesOf(commit));
  }

  return doc.getMap(CHAT_LOG_ENTRIES).toJSON() as Record<string, ChatLogEntry>;
}

describe('chat log entries', () => {
  it('makes keys that sort by time', ({ expect }) => {
    const early = newChatLogEntryKey(0x1000);
    const late = newChatLogEntryKey(0x1001);
    expect(early).toMatch(/^1000-[0-9a-f]{8}$/);
    expect(early < late).toBe(true);
  });

  it('adds, edits, removes and lists entries', async ({ expect }) => {
    const { page } = await chatLogPage();
    const first = page.addChatLogEntry({ a: alice, t: 'hello', c: 1000 })!;
    const second = page.addChatLogEntry({
      a: alice,
      t: 'second',
      c: 2000,
      r: first,
      role: 'user',
      skipped: undefined,
    })!;
    expect(page.listChatLogEntries().map(e => e.entry.t)).toEqual([
      'hello',
      'second',
    ]);
    expect(page.listChatLogEntries()[1].entry).toEqual({
      a: alice,
      t: 'second',
      c: 2000,
      r: first,
      role: 'user',
    });

    page.putChatLogEntry(first, { a: alice, t: 'hello!', c: 1000, e: 3000 });
    page.removeChatLogEntry(second);
    expect(page.listChatLogEntries()).toEqual([
      { key: first, entry: { a: alice, t: 'hello!', c: 1000, e: 3000 } },
    ]);
  });

  it('reads and counts single entries', async ({ expect }) => {
    const { page } = await chatLogPage();
    const key = page.addChatLogEntry({ a: alice, t: 'one', c: 1000 })!;
    page.addChatLogEntry({ a: alice, t: 'two', c: 2000 });
    expect(page.countChatLogEntries()).toBe(2);
    expect(page.getChatLogEntry(key)).toEqual({ a: alice, t: 'one', c: 1000 });
    expect(page.getChatLogEntry('missing')).toBeUndefined();
    page.removeChatLogEntry(key);
    expect(page.getChatLogEntry(key)).toBeUndefined();
    expect(page.countChatLogEntries()).toBe(1);
  });

  it('defaults author and time, and is not a property', async ({ expect }) => {
    const { page, agentDID } = await chatLogPage();
    const before = Date.now();
    page.addChatLogEntry({ t: 'mine' });
    const [{ entry }] = page.listChatLogEntries();
    expect(entry.a).toBe(agentDID);
    expect(entry.c).toBeGreaterThanOrEqual(before);
    expect(Object.keys(page.getPropVals())).not.toContain(CHAT_LOG_ENTRIES);
  });

  it('saves entry changes as normal commits', async ({ expect }) => {
    const { store, page, postCommitSpy, agentDID, genesis } =
      await chatLogPage();

    const first = page.addChatLogEntry({ t: 'one', c: 1000 })!;
    expect(page.hasUnsavedChanges()).toBe(true);
    await page.save();
    await store.syncDirtyResources();
    expect(postCommitSpy.mock.calls.length).toBe(1);
    const commit1 = postCommitSpy.mock.calls[0][0] as Commit;
    expect(commit1.subject).toBe(page.subject);
    expect(commit1.isGenesis).not.toBe(true);
    expect(entriesAfter(genesis, commit1)).toEqual({
      [first]: { a: agentDID, t: 'one', c: 1000 },
    });

    const second = page.addChatLogEntry({ t: 'two', c: 2000 })!;
    page.removeChatLogEntry(first);
    await page.save();
    await store.syncDirtyResources();
    const commit2 = postCommitSpy.mock.calls.at(-1)![0] as Commit;
    expect(commit2).not.toBe(commit1);
    // The delta only carries what changed; on the first commit's state it
    // gives the current log.
    expect(Object.keys(entriesAfter(genesis, commit1, commit2))).toEqual([
      second,
    ]);
  });
});
