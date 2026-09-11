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
  const schema = setup.inputSchema;
  if (schema.type !== 'object' || schema.additionalProperties !== false)
    throw new Error('Unsupported setup schema');
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
