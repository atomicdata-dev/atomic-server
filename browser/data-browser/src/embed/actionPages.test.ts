// @vitest-environment jsdom
// @wc-ignore-file
import { expect, it } from 'vitest';
import { actionPages } from './actionPages';

it('mounts the new drive page, the template picker, under /app/new-drive', () => {
  const entry = actionPages.find(([path]) => path === '/app/new-drive');

  expect(entry).toBeDefined();
  expect(entry![1].options.component).toBeTypeOf('function');
});

it('mounts every page once', () => {
  const all = actionPages.map(([path]) => path);

  expect(new Set(all).size).toBe(all.length);
});
