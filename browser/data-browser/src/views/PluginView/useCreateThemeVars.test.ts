import { describe, expect, it } from 'vitest';
import { buildTheme } from '../../styling';
import { frameColorScheme, frameStylesheet } from './useCreateThemeVars';

describe('the theme frames get', () => {
  it.each([
    [false, 'light'],
    [true, 'dark'],
  ] as const)(
    'names the host scheme (dark mode %s) instead of leaving it to be guessed',
    (darkMode, scheme) => {
      const theme = buildTheme(darkMode, '#1b50d8');
      expect(frameColorScheme(theme)).toBe(scheme);
      // So native controls and scrollbars in the frame match, and a script
      // loaded before any message can read it back.
      expect(frameStylesheet(theme)).toContain(`color-scheme: ${scheme};`);
    },
  );

  it('sends a success colour next to alert and warning', () => {
    for (const darkMode of [false, true]) {
      const theme = buildTheme(darkMode, '#1b50d8');
      expect(frameStylesheet(theme)).toContain(
        `--t-color-success: ${theme.colors.success};`,
      );
    }

    expect(buildTheme(false, '#1b50d8').colors.success).not.toBe(
      buildTheme(true, '#1b50d8').colors.success,
    );
  });
});
