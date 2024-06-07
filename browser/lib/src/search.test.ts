import { describe, it } from 'vitest';
import { escapeTantivyKey, buildSearchSubject, SearchOpts } from './search.js';

const testTuples = [
  ['https://test', 'https\\://test'],
  ['https://test.com', 'https\\://test\\.com'],
];

describe('search.ts', () => {
  it('Handles resources without an ID', ({ expect }) => {
    for (const [input, output] of testTuples) {
      expect(escapeTantivyKey(input)).toBe(output);
    }
  });

  it('Builds a good search URL', ({ expect }) => {
    const serverURL = 'https://test.com';
    const query = 'test';
    const searchOpts: SearchOpts = {
      include: true,
      limit: 30,
      parents: 'https://test.com/parent',
      filters: {
        age: '10',
      },
    };
    const built = buildSearchSubject(serverURL, query, searchOpts);
    expect(built).toBe(
      'https://test.com/search?q=test&include=true&limit=30&filters=age%3A%2210%22&parents=https%3A%2F%2Ftest.com%2Fparent',
    );
  });
});
