import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { computeVisibility } from './conditions.js';
import { validateAll } from './validation.js';
import type {
  FormDefinition,
  FormPageDefinition,
  FormValues,
} from './types.js';

const fixturePath = join(
  dirname(fileURLToPath(import.meta.url)),
  '../../../testdata/form-conditions.json',
);

interface FixtureCase {
  name: string;
  pages: FormPageDefinition[];
  values: FormValues;
  visibleFields: string[];
  visiblePages: number[];
  storedFields: string[];
  valid: boolean;
}

interface FixtureFile {
  cases: FixtureCase[];
}

const fixtures: FixtureFile = JSON.parse(readFileSync(fixturePath, 'utf8'));

function asDefinition(pages: FormPageDefinition[]): FormDefinition {
  return {
    version: 1,
    id: '',
    name: 'fixture',
    settings: {},
    styling: {},
    honeypotField: 'hp',
    pages,
  };
}

describe('form conditions (shared fixtures with server/src/forms.rs)', () => {
  it.each(fixtures.cases)('$name', ({ pages, values, ...expected }) => {
    const definition = asDefinition(pages);
    const visibility = computeVisibility(definition, values);

    expect([...visibility.fields]).toEqual(expected.visibleFields);
    expect(visibility.pageIndices).toEqual(expected.visiblePages);

    const result = validateAll(definition, values);
    const stored = Object.keys(result.values);

    expect(stored.sort()).toEqual([...expected.storedFields].sort());
    expect(Object.keys(result.errors).length === 0).toBe(expected.valid);
  });
});
