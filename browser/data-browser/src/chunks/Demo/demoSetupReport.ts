import type { DemoSetupStep } from './startDemo';

/** When each setup step began, in milliseconds since the run started. */
export type StepStarts = Partial<Record<DemoSetupStep, number>>;

const STEP_ORDER: DemoSetupStep[] = [
  'storage',
  'identity',
  'cleanup',
  'workspace',
];

/**
 * How long each step took. The step in progress has no end yet, so it runs to
 * `now`. Steps that never began are left out.
 */
export function stepDurations(
  starts: StepStarts,
  now: number,
): Partial<Record<DemoSetupStep, number>> {
  const begun = STEP_ORDER.filter(step => starts[step] !== undefined);
  const durations: Partial<Record<DemoSetupStep, number>> = {};

  begun.forEach((step, i) => {
    const next = begun[i + 1];
    durations[step] = (next ? starts[next]! : now) - starts[step]!;
  });

  return durations;
}

/** How early the stall timer may fire, by the wall clock, and still count. */
export const STALL_TOLERANCE_MS = 5_000;

/**
 * How much longer to wait before declaring a stall, given the time elapsed
 * since setup began. Zero means the deadline has really passed: report. A
 * timer can fire long before its deadline (a bot running on virtual time, a
 * clock jump), and those reports said "stalled" after about two seconds.
 */
export function stallWaitMs(elapsed: number, stalledAfter: number): number {
  if (elapsed >= stalledAfter - STALL_TOLERANCE_MS) return 0;

  return stalledAfter - elapsed;
}

/**
 * What a "setup stalled" report says besides the step it stopped on. A stall
 * fires at a fixed deadline, so on its own it cannot tell a machine that is
 * slow from one that is stuck; the durations and whether the tab was in the
 * background can.
 */
export function stallContext(
  starts: StepStarts,
  elapsed: number,
  visibility: string,
) {
  return {
    tags: { demo_visibility: visibility },
    extra: { elapsedMs: elapsed, stepMs: stepDurations(starts, elapsed) },
  };
}

/**
 * What a "finished after a stall" report says. Setup carries on past the
 * stall notice, so this is the other half of that report: with it, a stall
 * that ends a few seconds later reads as a slow machine, and a stall with no
 * such follow-up reads as a hang.
 */
export function lateFinishContext(starts: StepStarts, elapsed: number) {
  const durations = stepDurations(starts, elapsed);
  const [slowest] = Object.entries(durations).sort(([, a], [, b]) => b - a);

  return {
    tags: { demo_slowest_step: slowest?.[0] ?? 'none' },
    extra: { elapsedMs: elapsed, stepMs: durations },
  };
}
