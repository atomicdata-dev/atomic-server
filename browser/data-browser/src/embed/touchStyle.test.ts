// @vitest-environment jsdom
import { expect, it } from 'vitest';
import { embedTouchCss } from './touchStyle';

it('hides the tap highlight and shows a pressed state instead', () => {
  expect(embedTouchCss).toContain('-webkit-tap-highlight-color: transparent');
  expect(embedTouchCss).toContain(':focus:not(:focus-visible)');
  expect(embedTouchCss).toMatch(/a:active[^{]*\{[^}]*background-image/);
});

it('is valid CSS the page can inject', () => {
  const style = document.createElement('style');

  style.textContent = embedTouchCss;
  document.head.append(style);
  expect(document.styleSheets.length).toBeGreaterThan(0);
});
