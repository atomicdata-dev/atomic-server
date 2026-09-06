import { describe, expect, it } from 'vitest';
import { handlerMatchesModifier } from './keyboardHandlers';

const noMod = { metaKey: false, ctrlKey: false };
const ctrl = { metaKey: false, ctrlKey: true };
const meta = { metaKey: true, ctrlKey: false };

describe('handlerMatchesModifier', () => {
  it('matches unmodified keys when mod is omitted, and ignores Ctrl/Cmd', () => {
    expect(handlerMatchesModifier({}, noMod, false)).toBe(true);
    expect(handlerMatchesModifier({}, ctrl, false)).toBe(false);
    expect(handlerMatchesModifier({}, meta, true)).toBe(false);
  });

  it('matches Ctrl on non-Mac and Cmd on Mac when mod is true', () => {
    expect(handlerMatchesModifier({ mod: true }, ctrl, false)).toBe(true);
    expect(handlerMatchesModifier({ mod: true }, noMod, false)).toBe(false);
    expect(handlerMatchesModifier({ mod: true }, meta, true)).toBe(true);
    expect(handlerMatchesModifier({ mod: true }, ctrl, true)).toBe(false);
  });
});
