import { describe, it, expect } from 'vitest';
import { isSafeHref } from './safeHref.js';

describe('isSafeHref', () => {
  it('accepts ordinary link targets', () => {
    expect(isSafeHref('https://example.com/page')).toBe(true);
    expect(isSafeHref('http://localhost:9883/x')).toBe(true);
    expect(isSafeHref('mailto:a@b.c')).toBe(true);
    expect(isSafeHref('blob:https://example.com/uuid')).toBe(true);
    expect(isSafeHref('/relative/path')).toBe(true);
    expect(isSafeHref('#anchor')).toBe(true);
  });

  it('refuses script and document schemes', () => {
    expect(isSafeHref('javascript:alert(1)')).toBe(false);
    expect(isSafeHref('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(isSafeHref('vbscript:MsgBox(1)')).toBe(false);
  });

  it('is not fooled by case, whitespace or control characters', () => {
    expect(isSafeHref('JavaScript:alert(1)')).toBe(false);
    expect(isSafeHref('  javascript:alert(1)')).toBe(false);
    expect(isSafeHref('\tjavascript:alert(1)')).toBe(false);
    expect(isSafeHref('java\nscript:alert(1)')).toBe(false);
    expect(isSafeHref('data:text/html,x')).toBe(false);
  });

  it('refuses empty and non-string values', () => {
    expect(isSafeHref('')).toBe(false);
    expect(isSafeHref('   ')).toBe(false);
    expect(isSafeHref(undefined as unknown as string)).toBe(false);
    expect(isSafeHref(null as unknown as string)).toBe(false);
  });
});
