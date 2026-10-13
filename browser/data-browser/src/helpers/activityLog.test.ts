// @wc-ignore-file
import { describe, expect, it } from 'vitest';
import {
  COALESCE_MS,
  MAX_ACTIVITY_ENTRIES,
  groupActivity,
  mergeActivity,
  parseActivityLog,
  type ActivityEntry,
} from './activityLog';

const T = new Date(2026, 9, 8, 12, 0, 0).getTime();
const DAY = 86_400_000;
const e = (
  subject: string,
  at: number,
  kind: ActivityEntry['kind'] = 'edited',
  agent = 'a',
): ActivityEntry => ({ subject, agent, at, kind });

describe('mergeActivity', () => {
  it('adds new entries newest first', () => {
    const out = mergeActivity([e('x', T)], [e('y', T + 1000)]);
    expect(out.map(i => i.subject)).toEqual(['y', 'x']);
  });

  it('coalesces the same agent + subject inside the window', () => {
    const out = mergeActivity([e('x', T)], [e('x', T + 5 * 60_000)]);
    expect(out).toHaveLength(1);
    expect(out[0].at).toBe(T + 5 * 60_000);
  });

  it('keeps created when later edited', () => {
    const out = mergeActivity([e('x', T, 'created')], [e('x', T + 120_000)]);
    expect(out[0].kind).toBe('created');
  });

  it('does not coalesce across agents or outside the window', () => {
    expect(
      mergeActivity([e('x', T)], [e('x', T + 1000, 'edited', 'b')]),
    ).toHaveLength(2);
    expect(
      mergeActivity([e('x', T)], [e('x', T + COALESCE_MS + 1)]),
    ).toHaveLength(2);
  });

  it('returns the same array for tiny timestamp refreshes', () => {
    const log = [e('x', T)];
    expect(mergeActivity(log, [e('x', T + 10_000)])).toBe(log);
  });

  it('is bounded', () => {
    const many = Array.from({ length: 60 }, (_, i) => e(`s${i}`, T + i * 1000));
    const out = mergeActivity([], many);
    expect(out).toHaveLength(MAX_ACTIVITY_ENTRIES);
    expect(out[0].subject).toBe('s59');
  });
});

describe('parseActivityLog', () => {
  it('accepts arrays and JSON strings, drops junk', () => {
    const good = e('x', T);
    expect(parseActivityLog([good, { nope: 1 }])).toEqual([good]);
    expect(parseActivityLog(JSON.stringify([good]))).toEqual([good]);
    expect(parseActivityLog('{bad')).toEqual([]);
    expect(parseActivityLog(undefined)).toEqual([]);
  });
});

describe('groupActivity', () => {
  it('groups into Today / This week / Earlier', () => {
    const groups = groupActivity(
      [e('a', T - 1000), e('b', T - 3 * DAY), e('c', T - 30 * DAY)],
      T,
    );
    expect(groups.map(g => g.label)).toEqual(['Today', 'This week', 'Earlier']);
  });
});

describe('activity log persistence shape', () => {
  it('round-trips through the json datatype tag', async () => {
    const { datatypeTag, Datatype } = await import('@tomic/react');
    const log = [e('x', T)];
    expect(datatypeTag(Datatype.JSON, log)).toBe('json');
    expect(parseActivityLog(JSON.parse(JSON.stringify(log)))).toEqual(log);
  });
});
