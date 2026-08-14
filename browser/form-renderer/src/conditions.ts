/**
 * Visibility evaluator for FormCondition predicates. Mirrors
 * `server/src/forms.rs` (`evaluate_condition` / `compute_visibility` /
 * the hidden-field skip in `validate_submission`). Keep the two in
 * lockstep — both are tested against `testdata/form-conditions.json`.
 *
 * AND semantics: every condition on a page/block must match. An empty
 * list means always visible. Evaluation walks the form in document
 * order; a referenced field that is itself hidden (or unanswered) fails
 * the condition, so later questions cannot be unlocked by submitting a
 * value for a hidden predecessor.
 */
import type {
  FormBlock,
  FormCondition,
  FormDefinition,
  FormPageDefinition,
  FormValues,
} from './types.js';

export function blockConditions(block: FormBlock): FormCondition[] {
  return block.conditions ?? [];
}

export function pageConditions(page: FormPageDefinition): FormCondition[] {
  return page.conditions ?? [];
}

export function isEmptyValue(value: unknown): boolean {
  if (value === undefined || value === null) {
    return true;
  }

  if (typeof value === 'string') {
    return value.length === 0;
  }

  if (Array.isArray(value)) {
    return value.length === 0;
  }

  return false;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && !Number.isNaN(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);

    if (!Number.isNaN(n)) return n;
  }

  return undefined;
}

/** Numeric equality when both sides look like numbers; otherwise
 * string/boolean/JSON equality. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  const na = asNumber(a);
  const nb = asNumber(b);

  if (na !== undefined && nb !== undefined) {
    return na === nb;
  }

  if (typeof a === 'boolean' && typeof b === 'boolean') {
    return a === b;
  }

  if (typeof a === 'string' && typeof b === 'string') {
    return a === b;
  }

  return JSON.stringify(a) === JSON.stringify(b);
}

function contains(answer: unknown, expected: unknown): boolean {
  if (typeof answer === 'string') {
    return answer.toLowerCase().includes(String(expected).toLowerCase());
  }

  if (Array.isArray(answer)) {
    return answer.some(item => jsonEqual(item, expected));
  }

  return false;
}

function compare(answer: unknown, expected: unknown): number | undefined {
  const na = asNumber(answer);
  const nb = asNumber(expected);

  if (na !== undefined && nb !== undefined) {
    return na - nb;
  }

  if (typeof answer === 'string' && typeof expected === 'string') {
    if (answer < expected) return -1;

    if (answer > expected) return 1;

    return 0;
  }

  return undefined;
}

/** A single predicate. Unanswered / hidden referenced fields fail
 * (the dependent stays hidden). Unknown operators fail closed. */
export function evaluateCondition(
  condition: FormCondition,
  answer: unknown,
): boolean {
  if (isEmptyValue(answer)) {
    return false;
  }

  switch (condition.operator) {
    case 'equals':
      return jsonEqual(answer, condition.value);
    case 'not-equals':
      return !jsonEqual(answer, condition.value);
    case 'contains':
      return contains(answer, condition.value);

    case 'greater-than': {
      const cmp = compare(answer, condition.value);

      return cmp !== undefined && cmp > 0;
    }

    case 'less-than': {
      const cmp = compare(answer, condition.value);

      return cmp !== undefined && cmp < 0;
    }

    default:
      return false;
  }
}

function conditionsMatch(
  conditions: FormCondition[],
  values: FormValues,
  visibleFields: Set<string>,
): boolean {
  if (conditions.length === 0) return true;

  return conditions.every(condition => {
    const answer =
      condition.field && visibleFields.has(condition.field)
        ? values[condition.field]
        : undefined;

    return evaluateCondition(condition, answer);
  });
}

export interface FormVisibility {
  /** `mapsTo` of every visible input field, in document order. */
  fields: Set<string>;
  /** Indices of pages whose own conditions match. */
  pageIndices: number[];
  /** Per page, which block indices are visible (page-hidden → empty). */
  blocks: Set<number>[];
}

/** Walk the definition in document order and decide what's shown. */
export function computeVisibility(
  definition: FormDefinition,
  values: FormValues,
): FormVisibility {
  const fields = new Set<string>();
  const pageIndices: number[] = [];
  const blocks: Set<number>[] = [];

  for (let p = 0; p < definition.pages.length; p++) {
    const page = definition.pages[p];
    const visibleBlocks = new Set<number>();

    if (!conditionsMatch(pageConditions(page), values, fields)) {
      blocks.push(visibleBlocks);
      continue;
    }

    pageIndices.push(p);

    for (let b = 0; b < page.blocks.length; b++) {
      const block = page.blocks[b];

      if (!conditionsMatch(blockConditions(block), values, fields)) {
        continue;
      }

      visibleBlocks.add(b);

      if (block.kind === 'field') {
        fields.add(block.mapsTo);
      }
    }

    blocks.push(visibleBlocks);
  }

  return { fields, pageIndices, blocks };
}

export function visibleFieldMaps(
  definition: FormDefinition,
  values: FormValues,
): Set<string> {
  return computeVisibility(definition, values).fields;
}
