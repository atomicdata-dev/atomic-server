import { afterEach, expect, it, vi } from 'vitest';
import { DiagnosticRecorder, DiagnosticCode } from '@tomic/lib';
import { currentDiagnosticText, previewDiagnostics } from './diagnostic-report';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('exports only a frozen preview with build identity, never private input', () => {
  vi.stubGlobal('__APP_VERSION__', 'test');
  vi.stubGlobal('__GIT_COMMIT__', 'abc123');
  const recorder = new DiagnosticRecorder();
  recorder.start();
  recorder.beginSave({ subject: 'SECRET_URL', content: 'PRIVATE_TEXT' })(
    'error',
  );
  const preview = previewDiagnostics(recorder);
  recorder.connection(false);
  const report = currentDiagnosticText(recorder, preview)!;
  expect(report).toContain('test+abc123');
  expect(report).toContain('save-error');
  expect(report).not.toMatch(/SECRET_URL|PRIVATE_TEXT/);
  expect(
    JSON.parse(report).events.some(
      (event: { code: string }) => event.code === 'disconnected',
    ),
  ).toBe(false);
  recorder.clear();
  expect(currentDiagnosticText(recorder, preview)).toBeUndefined();
  recorder.start();
  expect(currentDiagnosticText(recorder, preview)).toBeUndefined();
  recorder.clear();
});

it('rejects an expired preview even when background timers did not run', () => {
  vi.useFakeTimers();
  vi.stubGlobal('__APP_VERSION__', 'test');
  vi.stubGlobal('__GIT_COMMIT__', 'abc123');
  const recorder = new DiagnosticRecorder();
  recorder.start();
  const preview = previewDiagnostics(recorder);
  vi.setSystemTime(Date.now() + 31 * 60_000);
  expect(currentDiagnosticText(recorder, preview)).toBeUndefined();
  expect(recorder.active).toBe(false);
});

it('exports a meaning for every event and explicit evidence limits', () => {
  vi.stubGlobal('__APP_VERSION__', 'test');
  vi.stubGlobal('__GIT_COMMIT__', 'abc123');
  const recorder = new DiagnosticRecorder();
  recorder.start();
  for (let i = 0; i < 600; i++) recorder.beginSave({})('error');
  const report = JSON.parse(previewDiagnostics(recorder).text);
  expect(report.schema).toBe(3);
  expect(Object.keys(report.eventMeanings).sort()).toEqual(
    Object.values(DiagnosticCode).sort(),
  );
  expect(report.completeness.droppedCapacity).toBe(700);
  expect(report.completeness.firstRetainedSequence).toBe(701);
  expect(report.completeness.unfinishedOperations).toBe(0);
  expect(report.unavailable).toContain('raw errors and stacks');
  recorder.clear();
});
