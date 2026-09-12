import { describe, expect, it } from 'vitest';
import {
  parseSetupDeclaration,
  validateSetupArguments,
  type SetupDeclaration,
} from './plugin-setup.js';
const declaration: SetupDeclaration = {
  title: 'Connect',
  description: 'Connect a source',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['repository'],
    properties: {
      repository: { type: 'string', description: 'Repository', minLength: 1 },
      enabled: { type: 'boolean', description: 'Enabled' },
      count: { type: 'integer', description: 'Count' },
    },
  },
};
describe('setup arguments shared by forms and assistant', () => {
  it('preserves typed values and permits partial assistant drafts', () => {
    expect(
      validateSetupArguments(declaration, {
        repository: 'a/b',
        enabled: false,
        count: 2,
      }),
    ).toEqual({ repository: 'a/b', enabled: false, count: 2 });
    expect(validateSetupArguments(declaration, {}, true)).toEqual({});
  });
  it('rejects missing, blank, mistyped and undeclared arguments including credentials', () => {
    for (const value of [
      {},
      { repository: ' ' },
      { repository: 2 },
      { repository: 'a/b', count: 1.2 },
      { repository: 'a/b', token: 'secret' },
    ]) {
      expect(() => validateSetupArguments(declaration, value)).toThrow();
    }

    expect(() =>
      validateSetupArguments(declaration, { token: 'secret' }, true),
    ).toThrow();
  });
  it('rejects prototype keys and oversized inputs', () => {
    expect(() =>
      validateSetupArguments(declaration, JSON.parse('{"__proto__":{}}'), true),
    ).toThrow();
    expect(() =>
      validateSetupArguments(declaration, { repository: 'a'.repeat(65537) }),
    ).toThrow();
  });
});

describe('setup declarations from resource JSON', () => {
  it('round-trips portable metadata and detaches it from the package', () => {
    const raw = JSON.parse(JSON.stringify(declaration));
    const parsed = parseSetupDeclaration(raw);
    expect(parsed).toEqual(declaration);
    raw.inputSchema.properties.repository.type = 'object';
    expect(parsed.inputSchema.properties.repository.type).toBe('string');
    expect(
      validateSetupArguments(parsed, { repository: 'ontola/atomic-server' }),
    ).toEqual({ repository: 'ontola/atomic-server' });
  });

  it.each([
    { type: 'object' },
    { type: 'number' },
    { format: 'uri' },
    { pattern: '^x' },
    { default: 'hidden' },
    { minLength: -1 },
    { minLength: 1.5 },
    { enum: [] },
    { enum: ['x', 'x'] },
    { enum: [42] },
    { 'x-atomic': { widget: 'password', lookup: 'secrets' } },
    {
      'x-atomic': {
        widget: 'choice',
        lookup: 'tables',
        url: 'https://example.com',
      },
    },
  ])('rejects unsupported field semantics %j', patch => {
    const raw = structuredClone(declaration);
    Object.assign(raw.inputSchema.properties.repository, patch);
    expect(() => parseSetupDeclaration(raw)).toThrow(
      'Unsupported setup declaration',
    );
    expect(() => validateSetupArguments(raw, {}, true)).toThrow();
  });

  it('rejects malformed schemas before any form or partial assistant draft uses them', () => {
    for (const inputSchema of [
      null,
      [],
      {},
      { ...declaration.inputSchema, additionalProperties: true },
      { ...declaration.inputSchema, required: ['missing'] },
      { ...declaration.inputSchema, required: ['repository', 'repository'] },
      {
        ...declaration.inputSchema,
        properties: JSON.parse(
          '{"__proto__":{"type":"string","description":"x"}}',
        ),
      },
      {
        ...declaration.inputSchema,
        properties: {
          enabled: { type: 'boolean', description: 'Enabled', minLength: 1 },
        },
      },
    ]) {
      expect(() =>
        parseSetupDeclaration({ ...declaration, inputSchema }),
      ).toThrow();
    }

    expect(() =>
      parseSetupDeclaration({ ...declaration, permissions: ['admin'] }),
    ).toThrow();
    expect(() =>
      parseSetupDeclaration({ ...declaration, description: 'x'.repeat(65537) }),
    ).toThrow();
    expect(() => parseSetupDeclaration(null)).toThrow();
  });

  it('preserves choice hints and checks static choices', () => {
    const raw = structuredClone(declaration);
    raw.inputSchema.properties.repository.enum = ['one', 'two'];
    raw.inputSchema.properties.repository['x-atomic'] = {
      widget: 'choice',
      lookup: 'repositories',
      emptyLabel: 'Choose a repository',
    };
    const parsed = parseSetupDeclaration(raw);
    expect(parsed).toEqual(raw);
    expect(validateSetupArguments(parsed, { repository: 'one' })).toEqual({
      repository: 'one',
    });
    expect(() =>
      validateSetupArguments(parsed, { repository: 'three' }),
    ).toThrow();
  });
});
