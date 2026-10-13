import { describe, expect, it } from 'vitest';
import {
  lateFinishContext,
  stallContext,
  stallWaitMs,
  stepDurations,
} from './demoSetupReport';

describe('stepDurations', () => {
  it('runs each step to the start of the next one', () => {
    expect(
      stepDurations({ storage: 0, identity: 400, cleanup: 900 }, 1500),
    ).toEqual({ storage: 400, identity: 500, cleanup: 600 });
  });

  it('runs the step in progress to now', () => {
    expect(stepDurations({ storage: 0, identity: 1200 }, 45_000)).toEqual({
      storage: 1200,
      identity: 43_800,
    });
  });

  it('leaves out steps that never began', () => {
    expect(stepDurations({}, 45_000)).toEqual({});
  });

  it('follows the order of the steps, not the order they were recorded in', () => {
    expect(
      stepDurations({ workspace: 900, storage: 0, identity: 300 }, 2000),
    ).toEqual({ storage: 300, identity: 600, workspace: 1100 });
  });
});

describe('stallContext', () => {
  it('records whether the tab was in the background and where the time went', () => {
    expect(
      stallContext({ storage: 0, identity: 800 }, 45_000, 'hidden'),
    ).toEqual({
      tags: { demo_visibility: 'hidden' },
      extra: {
        elapsedMs: 45_000,
        stepMs: { storage: 800, identity: 44_200 },
      },
    });
  });
});

describe('lateFinishContext', () => {
  it('names the step that took longest', () => {
    const { tags, extra } = lateFinishContext(
      { storage: 0, identity: 500, cleanup: 30_500, workspace: 31_000 },
      52_000,
    );

    expect(tags).toEqual({ demo_slowest_step: 'identity' });
    expect(extra.elapsedMs).toBe(52_000);
    expect(extra.stepMs).toEqual({
      storage: 500,
      identity: 30_000,
      cleanup: 500,
      workspace: 21_000,
    });
  });

  it('copes with a run that never reported a step', () => {
    expect(lateFinishContext({}, 50_000).tags).toEqual({
      demo_slowest_step: 'none',
    });
  });
});

describe('stallWaitMs', () => {
  it('waits out the rest of the deadline when the timer fired after two seconds', () => {
    expect(stallWaitMs(2188, 45_000)).toBe(42_812);
  });

  it('reports once the deadline has passed', () => {
    expect(stallWaitMs(45_000, 45_000)).toBe(0);
    expect(stallWaitMs(60_000, 45_000)).toBe(0);
  });

  it('allows five seconds of tolerance below the deadline', () => {
    expect(stallWaitMs(40_000, 45_000)).toBe(0);
    expect(stallWaitMs(39_999, 45_000)).toBe(5001);
  });
});
