import { useSyncExternalStore } from 'react';
import {
  loadAtomicWasm,
  type AtomicWasmModule,
} from '@helpers/managed/recovery';
import { calendarDateToLocalDate } from '@helpers/dates/calendarDate';
import type { Expression } from '@tomic/react';

/**
 * The formula evaluator is the Rust crate behind `atomic_wasm`, the same code the
 * store runs for totals and filters — a cell must show what a filter on it
 * matches. Cells render synchronously, so the bundle is loaded once on first use
 * and they show empty until it is there (`useFormulaReady` re-renders them).
 */
let engine:
  | Pick<AtomicWasmModule, 'evaluateFormula' | 'validateFormula'>
  | undefined;
let started = false;
const listeners = new Set<() => void>();

/** Hands over an already-instantiated module (tests, where nothing can fetch). */
export function provideFormulaEngine(module: typeof engine): void {
  engine = module;
  listeners.forEach(listener => listener());
}

function start(): void {
  if (started) {
    return;
  }

  started = true;
  loadAtomicWasm().then(provideFormulaEngine, () => {
    started = false;
  });
}

/** True once formulas can be evaluated; subscribing starts the load. */
export function useFormulaReady(): boolean {
  start();

  return useSyncExternalStore(
    listener => {
      listeners.add(listener);

      return () => listeners.delete(listener);
    },
    () => engine !== undefined,
  );
}

/** The value for one row, or undefined when it has none (or the engine is loading). */
export function evaluateFormula(
  expression: Expression,
  values: Record<string, unknown>,
  now: number,
): number | undefined {
  start();

  // Only what the evaluator can read as a number: a list or an object is no input.
  // A civil date has no zone: it reads as local midnight, as the date a row
  // action stamps (`localCalendarDate`) does, not as the UTC midnight the
  // evaluator would parse, which made "today" read as tomorrow east of UTC.
  const cells = Object.fromEntries(
    Object.entries(values)
      .filter(([, value]) =>
        ['number', 'string', 'boolean'].includes(typeof value),
      )
      .map(([key, value]) => [
        key,
        typeof value === 'string'
          ? (calendarDateToLocalDate(value)?.getTime() ?? value)
          : value,
      ]),
  );

  try {
    return engine?.evaluateFormula(expression, cells, now) ?? undefined;
  } catch {
    return undefined;
  }
}

/** The formula's error message, or null when it is valid (undefined while loading). */
export function validateFormula(
  expression: Expression,
): string | null | undefined {
  start();

  try {
    // wasm-bindgen hands a Rust `None` back as undefined.
    return engine && (engine.validateFormula(expression) ?? null);
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}
