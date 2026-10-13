import {
  Datatype,
  type JSONValue,
  type Property,
  type Resource,
} from '@tomic/react';
import { localCalendarDate } from '@helpers/dates/calendarDate';

/**
 * The verbs a row action can perform.
 *
 * A closed set, on purpose, and the same rule the derived-column generators
 * follow: a person can edit one in a dialog and an LLM can write one, because it
 * is configuration rather than code. The moment an action can run arbitrary code
 * it stops being config and becomes the plugin platform, which is a different
 * document ([[llm-wasm-gui-plugins]]).
 *
 * These four came out of walking the thirteen table templates (see
 * `planning/dashboards.md`): "Watered" and "Log contact" stamp now, "Mark done"
 * and "Yes/No" set a value, a grocery list toggles, and an inventory counts up
 * and down. Nothing in the catalogue needed a fifth *per-row* verb.
 */
export type RowActionKind = 'setNow' | 'setValue' | 'toggle' | 'increment';

/** One configured action, stored on the View in `view-row-actions`. */
export interface RowActionSpec {
  /** Stable identity within the view — part of the grid column key. */
  id: string;
  /** The button's label, and its column heading. */
  label: string;
  kind: RowActionKind;
  /** The property this action writes. */
  property: string;
  /**
   * What to write, for the verbs that need it: the literal for `setValue` (a tag
   * subject for a select column), the step for `increment`.
   */
  value?: string | number;
}

/** What a verb needs from its configuration, so the dialog can build its form. */
interface RowActionGenerator {
  /** Name in the "add action" picker. */
  title: string;
  /** One line saying what pressing it does. */
  description: string;
  /** Prefills the action's label. */
  defaultLabel: string;
  /** Which of the class's properties this verb can write. */
  accepts: (property: Property) => boolean;
  /**
   * What the `value` field means, or undefined when the verb needs none.
   * `select` offers the property's own options; `number` a step; `text` a string.
   */
  valueInput?: 'select' | 'number' | 'text';
  /** Label of the value field in the dialog. */
  valueLabel?: string;
  /** Default column width in px. */
  width: number;
  /**
   * The value to write, given the row's current value. Returning undefined means
   * "remove the value" — how `toggle` clears rather than writing `false`, so an
   * unticked row reads the same as one never ticked.
   */
  next: (
    current: JSONValue | undefined,
    spec: RowActionSpec,
    /** The property being written, when the caller knows it — a select column
     *  holds an array, and only its datatype says so. */
    property?: Property,
  ) => JSONValue | undefined;
  /**
   * How the button reads for this row. `active` renders it as engaged (a ticked
   * checkbox, a stamped date), so the button doubles as the state readout.
   */
  isActive?: (current: JSONValue | undefined) => boolean;
}

function isNumeric(property: Property): boolean {
  return (
    property.datatype === Datatype.INTEGER ||
    property.datatype === Datatype.FLOAT
  );
}

function isInstant(property: Property): boolean {
  return (
    property.datatype === Datatype.DATE ||
    property.datatype === Datatype.TIMESTAMP
  );
}

/** A select column is a resource-array constrained to a set of tags. */
function isSelect(property: Property): boolean {
  return property.datatype === Datatype.RESOURCEARRAY;
}

function toNumber(value: JSONValue | undefined): number {
  const parsed = typeof value === 'number' ? value : Number(value);

  return Number.isFinite(parsed) ? parsed : 0;
}

export const ROW_ACTION_GENERATORS: Record<RowActionKind, RowActionGenerator> =
  {
    setNow: {
      title: 'Stamp with now',
      description:
        'Writes the current time to a date column. "Watered", "Log contact", "Followed up".',
      defaultLabel: 'Done',
      accepts: isInstant,
      width: 90,
      // A TIMESTAMP holds millis, a DATE holds an ISO day — and nothing coerces
      // between them, so writing millis into a date column stored a value that
      // rendered as an empty cell and computed as no date at all.
      next: (_current, _spec, property) =>
        property?.datatype === Datatype.DATE ? localCalendarDate() : Date.now(),
      isActive: current => current !== undefined && current !== '',
    },
    setValue: {
      title: 'Set a value',
      description:
        'Writes one fixed value. "Mark done" (Status = Done), an RSVP of Yes or No.',
      defaultLabel: 'Set',
      accepts: property =>
        isSelect(property) ||
        property.datatype === Datatype.STRING ||
        property.datatype === Datatype.SLUG ||
        isNumeric(property),
      valueInput: 'select',
      valueLabel: 'To',
      width: 90,
      next: (_current, spec, property) =>
        // A select column holds an array of tag subjects, so the one value goes in
        // as a single-element array. Decided by the property's datatype rather
        // than by what the value looks like.
        property && isSelect(property)
          ? [spec.value as string]
          : (spec.value as JSONValue),
    },
    toggle: {
      title: 'Toggle',
      description:
        'Flips a checkbox column on and off. A grocery list’s "bought", a "starred".',
      defaultLabel: 'Toggle',
      accepts: property => property.datatype === Datatype.BOOLEAN,
      width: 70,
      // Unset rather than `false`: a row that was never ticked and one that was
      // un-ticked should read the same, and an unset boolean is the datatype's
      // own idea of false.
      next: current => (current === true ? undefined : true),
      isActive: current => current === true,
    },
    increment: {
      title: 'Add to a number',
      description:
        'Adds a fixed amount to a number column. Use −1 for a "one fewer" button.',
      defaultLabel: '+1',
      accepts: isNumeric,
      valueInput: 'number',
      valueLabel: 'By',
      width: 70,
      next: (current, spec) => toNumber(current) + toNumber(spec.value ?? 1),
    },
  };

export const ROW_ACTION_KINDS: RowActionKind[] = [
  'setNow',
  'setValue',
  'toggle',
  'increment',
];

/** The column key an action occupies, in the same `<kind>:<id>` convention
 *  `derived:` uses for the columns that aren't properties. */
export function rowActionKey(id: string): string {
  return `action:${id}`;
}

/** Whether a configured action has everything it needs to run. */
export function isRowActionComplete(spec: RowActionSpec): boolean {
  const generator = ROW_ACTION_GENERATORS[spec.kind];

  if (!generator || !spec.property) {
    return false;
  }

  // A verb that writes a literal is not configured until it has one; `0` is a
  // perfectly good step, so only empty and undefined disqualify.
  if (generator.valueInput !== undefined) {
    return spec.value !== undefined && spec.value !== '';
  }

  return true;
}

function isSpec(value: unknown): value is RowActionSpec {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const spec = value as Record<string, unknown>;

  return (
    typeof spec.id === 'string' &&
    typeof spec.label === 'string' &&
    typeof spec.kind === 'string' &&
    spec.kind in ROW_ACTION_GENERATORS &&
    typeof spec.property === 'string'
  );
}

/**
 * Reads the View's stored actions. Anything malformed is dropped rather than
 * thrown on: a person or an LLM writes this, and one bad entry must not take the
 * table down.
 */
export function parseRowActions(value: JSONValue | undefined): RowActionSpec[] {
  const parsed =
    typeof value === 'string'
      ? (() => {
          try {
            return JSON.parse(value) as JSONValue;
          } catch {
            return undefined;
          }
        })()
      : value;

  if (!Array.isArray(parsed)) {
    return [];
  }

  return (parsed as unknown[]).filter(isSpec);
}

/**
 * Applies an action to one row and saves it.
 *
 * Deliberately a single commit on a single resource: that is what makes every
 * press rights-checked, synced, undoable and visible in history for free.
 */
export async function applyRowAction(
  row: Resource,
  spec: RowActionSpec,
  property?: Property,
): Promise<void> {
  const generator = ROW_ACTION_GENERATORS[spec.kind];

  if (!generator || !isRowActionComplete(spec)) {
    return;
  }

  const next = generator.next(
    row.get(spec.property) as JSONValue,
    spec,
    property,
  );

  if (next === undefined) {
    row.remove(spec.property);
  } else {
    // `false` skips the client-side property fetch; the server validates the
    // commit against its own definitions. Every value here is a primitive or an
    // array, so it is stored natively either way.
    await row.set(spec.property, next as never, false);
  }

  await row.save();
}

/** Which of the class's properties a verb can be pointed at. */
export function propertiesForRowAction(
  properties: Property[],
  kind: RowActionKind,
): Property[] {
  const generator = ROW_ACTION_GENERATORS[kind];

  return generator ? properties.filter(generator.accepts) : [];
}

/** The value field a verb needs, if any. */
export function rowActionValueInput(
  kind: RowActionKind,
): { input: 'select' | 'number' | 'text'; label: string } | undefined {
  const generator = ROW_ACTION_GENERATORS[kind];

  return generator?.valueInput
    ? { input: generator.valueInput, label: generator.valueLabel ?? 'Value' }
    : undefined;
}
