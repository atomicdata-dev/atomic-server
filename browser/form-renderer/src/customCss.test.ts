import { describe, expect, it } from 'vitest';
import { wrapCustomCss } from './FormShell.js';

describe('wrapCustomCss', () => {
  it('returns undefined for nothing to inject', () => {
    expect(wrapCustomCss(undefined)).toBeUndefined();
    expect(wrapCustomCss('')).toBeUndefined();
    expect(wrapCustomCss('   \n\t ')).toBeUndefined();
  });

  it('puts the CSS in the custom layer, after the base layer', () => {
    const wrapped = wrapCustomCss('.atomic-form-card { color: red }')!;

    expect(wrapped).toContain('@layer atomic-form-custom');
    // The layer must be the one `style.css` declares second, or the base
    // stylesheet would win on every rule.
    expect(wrapped).not.toContain('atomic-form-base');
    expect(wrapped).toContain('.atomic-form-card { color: red }');
  });

  it('scopes the CSS to the form root', () => {
    const wrapped = wrapCustomCss('body { display: none }')!;

    expect(wrapped).toContain('@scope (.atomic-form-shell)');
    // The @scope wrapper is what stops a preview's CSS repainting the builder
    // around it.
    expect(wrapped.indexOf('@scope')).toBeLessThan(
      wrapped.indexOf('body { display: none }'),
    );
  });

  it('leaves the owner CSS byte-identical inside the wrapper', () => {
    const css =
      '@media (width < 40rem) {\n  .atomic-form-card { padding: 0 }\n}';

    expect(wrapCustomCss(`\n${css}\n`)).toContain(css);
  });
});
