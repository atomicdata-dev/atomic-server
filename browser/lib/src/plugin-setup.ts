import type { DeclaredAction } from './plugin-manifest.js';

/** Setup uses the same bounded action input vocabulary; credentials are not arguments. */
export type SetupField = DeclaredAction['inputSchema']['properties'][string] & {
  title?: string;
  minLength?: number;
  enum?: string[];
  /** Optional host presentation, never execution authority. */
  'x-atomic'?: { widget: 'choice'; lookup: string; emptyLabel?: string };
};
export interface SetupDeclaration {
  title: string;
  description: string;
  inputSchema: Omit<DeclaredAction['inputSchema'], 'properties'> & {
    properties: Record<string, SetupField>;
  };
}
export type SetupArguments = Record<string, string | number | boolean>;

/** Decode package-owned JSON before it reaches forms or model discovery.
 * This declares presentation only: lookup names do not grant host capabilities.
 * Unsupported JSON Schema keywords fail visibly rather than being ignored.
 */
export function parseSetupDeclaration(raw: unknown): SetupDeclaration {
  const fail = (): never => {
    throw new Error('Unsupported setup declaration');
  };

  const object = (value: unknown, keys?: string[]): Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
    const result = value as Record<string, unknown>;
    if (
      Object.getPrototypeOf(result) !== Object.prototype &&
      Object.getPrototypeOf(result) !== null
    )
      fail();
    if (
      Object.keys(result).some(
        key =>
          ['__proto__', 'constructor', 'prototype'].includes(key) ||
          (keys && !keys.includes(key)),
      )
    )
      fail();

    return result;
  };

  const text = (value: unknown): value is string =>
    typeof value === 'string' && value.trim().length > 0;
  const declaration = object(raw, ['title', 'description', 'inputSchema']);
  if (!text(declaration.title) || !text(declaration.description)) fail();
  const schema = object(declaration.inputSchema, [
    'type',
    'additionalProperties',
    'required',
    'properties',
  ]);
  if (schema.type !== 'object' || schema.additionalProperties !== false) fail();
  const properties = object(schema.properties);
  if (Object.keys(properties).length > 100) fail();

  if (schema.required !== undefined) {
    if (
      !Array.isArray(schema.required) ||
      schema.required.some(
        key => typeof key !== 'string' || !Object.hasOwn(properties, key),
      ) ||
      new Set(schema.required).size !== schema.required.length
    )
      fail();
  }

  for (const [name, rawField] of Object.entries(properties)) {
    if (!text(name)) fail();
    const field = object(rawField, [
      'type',
      'description',
      'title',
      'minLength',
      'enum',
      'x-atomic',
    ]);
    if (
      typeof field.type !== 'string' ||
      !['string', 'integer', 'boolean'].includes(field.type) ||
      !text(field.description)
    )
      fail();
    if (field.title !== undefined && !text(field.title)) fail();
    if (
      field.minLength !== undefined &&
      (field.type !== 'string' ||
        !Number.isSafeInteger(field.minLength) ||
        (field.minLength as number) < 0)
    )
      fail();
    if (
      field.enum !== undefined &&
      (field.type !== 'string' ||
        !Array.isArray(field.enum) ||
        field.enum.length === 0 ||
        field.enum.some(value => typeof value !== 'string') ||
        new Set(field.enum).size !== field.enum.length)
    )
      fail();

    if (field['x-atomic'] !== undefined) {
      const hint = object(field['x-atomic'], [
        'widget',
        'lookup',
        'emptyLabel',
      ]);
      if (
        field.type !== 'string' ||
        hint.widget !== 'choice' ||
        !text(hint.lookup) ||
        (hint.emptyLabel !== undefined && !text(hint.emptyLabel))
      )
        fail();
    }
  }

  // Detach validated metadata from the caller; never retain mutable package objects.
  const json = JSON.stringify(raw);
  if (json.length > 65536) fail();

  return JSON.parse(json) as SetupDeclaration;
}

/** Fail closed for both model drafts and submitted forms. Never coerce credentials or types. */
export function validateSetupArguments(
  setup: SetupDeclaration,
  raw: unknown,
  partial = false,
): SetupArguments {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('Setup arguments must be an object');
  if (JSON.stringify(raw).length > 65536)
    throw new Error('Setup arguments are too large');
  // Discovery entries also carry a host-owned app ID. Decode the declaration
  // portion; package ingestion itself uses the strict parser on the full JSON.
  const schema = parseSetupDeclaration({
    title: setup.title,
    description: setup.description,
    inputSchema: setup.inputSchema,
  }).inputSchema;
  const result: SetupArguments = Object.create(null);

  for (const [key, value] of Object.entries(raw)) {
    if (
      !Object.hasOwn(schema.properties, key) ||
      ['__proto__', 'constructor', 'prototype'].includes(key)
    )
      throw new Error('Unknown setup argument');
    const field = schema.properties[key];
    if (
      (field.type === 'string' && typeof value !== 'string') ||
      (field.type === 'boolean' && typeof value !== 'boolean') ||
      (field.type === 'integer' && !Number.isSafeInteger(value)) ||
      !['string', 'boolean', 'integer'].includes(field.type)
    )
      throw new Error(`Invalid type for ${field.title ?? key}`);
    if (
      typeof value === 'string' &&
      (value.trim().length < (field.minLength ?? 0) ||
        (field.enum && !field.enum.includes(value)))
    )
      throw new Error(`Choose a valid ${field.title ?? key}`);
    result[key] = value as string | number | boolean;
  }

  if (!partial)
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(result, key))
        throw new Error(`${schema.properties[key]?.title ?? key} is required`);
    }

  return result;
}
