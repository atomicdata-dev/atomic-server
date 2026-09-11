import { describe, expect, it } from 'vitest';
import {
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
