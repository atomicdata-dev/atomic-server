/**
 * Mirrors `atomic_lib::forms::build_form_summary` (`lib/src/forms.rs`) — the
 * ephemeral `form-submission-summary` JSON the Form class extender adds on
 * server GETs. Keep field names and shapes in lockstep with the Rust side;
 * there is no code generation between them (same convention as
 * `FormDefinition`).
 */

export interface FieldSummaryBase {
  mapsTo: string;
  label: string;
  type: string;
  answered: number;
  skipped: number;
}

/** Every type the server aggregates as `counts` — the choice questions, plus
 * `country`, whose pairs are ISO codes counted by popularity rather than
 * configured options. */
export const COUNTS_SUMMARY_TYPES = [
  'radio',
  'dropdown',
  'picture-choice',
  'multi-select',
  'dropdown-multi',
  'country',
] as const;

export interface ChoiceFieldSummary extends FieldSummaryBase {
  type: (typeof COUNTS_SUMMARY_TYPES)[number];
  /** `[option, count]` pairs in the field's configured order (+ "Other"). */
  counts: Array<[string, number]>;
}

export interface CheckboxFieldSummary extends FieldSummaryBase {
  type: 'checkbox';
  checked: number;
  unchecked: number;
}

export interface HistogramBin {
  min: number;
  max: number;
  count: number;
}

export interface NumberFieldSummary extends FieldSummaryBase {
  type: 'number';
  /** Absent when no numeric answers exist yet. */
  bins?: HistogramBin[];
  min?: number;
  max?: number;
  mean?: number;
}

export interface TextFieldSummary extends FieldSummaryBase {
  /** Sample of answers, capped server-side (currently 100). */
  answers: Array<string | number>;
}

export type FieldSummary =
  | ChoiceFieldSummary
  | CheckboxFieldSummary
  | NumberFieldSummary
  | TextFieldSummary;

export interface FormSummary {
  responses: number;
  fields: FieldSummary[];
}

export function isChoiceSummary(f: FieldSummary): f is ChoiceFieldSummary {
  return (COUNTS_SUMMARY_TYPES as readonly string[]).includes(f.type);
}

export function isCheckboxSummary(f: FieldSummary): f is CheckboxFieldSummary {
  return f.type === 'checkbox';
}

export function isNumberSummary(f: FieldSummary): f is NumberFieldSummary {
  return f.type === 'number';
}

/** Parses the raw propval into a `FormSummary`, tolerating older servers
 * (missing prop) and stringified JSON. */
export function parseFormSummary(value: unknown): FormSummary | undefined {
  const parsed = typeof value === 'string' ? safeJsonParse(value) : value;

  if (
    parsed &&
    typeof parsed === 'object' &&
    typeof (parsed as FormSummary).responses === 'number' &&
    Array.isArray((parsed as FormSummary).fields)
  ) {
    return parsed as FormSummary;
  }

  return undefined;
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}
