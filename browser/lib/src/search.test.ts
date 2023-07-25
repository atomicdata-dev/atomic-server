import { escapeTantivyKey } from './search.js';

const testTuples = [
  ['https://test', 'https\\://test'],
  ['https://test.com', 'https\\://test\\.com'],
];

describe('search.ts', () => {
  it('Handles resources without an ID', () => {
    for (const [input, output] of testTuples) {
      expect(escapeTantivyKey(input)).toBe(output);
    }
  });
});
