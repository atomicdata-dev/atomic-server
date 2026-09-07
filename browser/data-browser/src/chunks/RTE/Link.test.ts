import { describe, expect, it, vi } from 'vitest';
import { find } from 'linkifyjs';
import { Link } from './Link';

describe('shared editor link parser', () => {
  it('keeps telephone and web links working across editor lifecycles', () => {
    const warning = vi.spyOn(console, 'warn');
    const text = 'https://example.com mailto:hello@example.com tel:31201234567';
    const expected = find(text).map(link => link.href);
    expect(expected).toEqual([
      'https://example.com',
      'mailto:hello@example.com',
      'tel:31201234567',
    ]);

    for (let i = 0; i < 3; i++) {
      Reflect.apply(Link.config.onCreate!, {}, []);
      Reflect.apply(Link.config.onDestroy!, {}, []);
      expect(find(text).map(link => link.href)).toEqual(expected);
    }

    expect(warning).not.toHaveBeenCalled();
    warning.mockRestore();
  });
});
