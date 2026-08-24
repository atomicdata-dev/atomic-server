import { forms, Resource, useValue, type JSONValue } from '@tomic/react';
import { useCallback } from 'react';

export type FieldOptionsBag = Record<string, JSONValue>;

/**
 * Reads and writes a FormField's `form-field-options` JSON bag — the
 * type-specific settings every question type stores its configuration in.
 *
 * Writes commit immediately; editors that write per keystroke should debounce
 * (see `StringListEditor`), because `form-field-options` validates against a
 * Property fetch that can be slow enough for an earlier commit to land after
 * a later one.
 */
export function useFieldOptions(
  field: Resource,
): [FieldOptionsBag, (next: FieldOptionsBag) => void] {
  const [raw, setRaw] = useValue(field, forms.properties.formFieldOptions, {
    commit: true,
  });

  const setOptions = useCallback(
    (next: FieldOptionsBag) => setRaw(next as JSONValue),
    [setRaw],
  );

  return [parseFieldOptions(raw), setOptions];
}

/**
 * A JSON-datatype value written while its Property resource was unresolvable
 * rehydrates as the raw serialized *string* rather than an object — spreading
 * that string would corrupt the next write into indexed characters. Same
 * hazard `parseStylingValue` guards against for `form-styling`.
 */
export function parseFieldOptions(raw: JSONValue | undefined): FieldOptionsBag {
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);

      return typeof parsed === 'object' &&
        parsed !== null &&
        !Array.isArray(parsed)
        ? (parsed as FieldOptionsBag)
        : {};
    } catch {
      return {};
    }
  }

  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
    return raw as FieldOptionsBag;
  }

  return {};
}
