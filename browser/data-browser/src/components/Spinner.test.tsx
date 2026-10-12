// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { Spinner } from './Spinner';

afterEach(cleanup);

const theme = { colors: { text: '#000' } } as unknown as DefaultTheme;

const renderSpinner = (props: Parameters<typeof Spinner>[0]) =>
  render(
    <ThemeProvider theme={theme}>
      <Spinner {...props} />
    </ThemeProvider>,
  );

describe('Spinner', () => {
  it('is a bare decorative mark by default', () => {
    const { queryByRole } = renderSpinner({});

    expect(queryByRole('status')).toBeNull();
  });

  it('draws the logo sweep around the orb, with no separate dot', () => {
    const { container } = renderSpinner({});
    const path = container.querySelector('svg path');

    expect(path?.getAttribute('d')).toBe('M74 50 A 24 24 0 1 1 50 26');
    expect(path?.getAttribute('stroke-linecap')).toBe('round');
    expect(path?.getAttribute('stroke')).toBe('currentColor');
    expect(container.querySelectorAll('svg circle')).toHaveLength(0);
  });

  it('centered fills its parent: stretches in a flex column, never collapses', () => {
    const { getByRole } = renderSpinner({ centered: true });
    const wrapper = getByRole('status');
    const style = getComputedStyle(wrapper);

    expect(wrapper.getAttribute('aria-label')).toBe('Loading');
    expect(style.display).toBe('flex');
    expect(style.alignItems).toBe('center');
    expect(style.justifyContent).toBe('center');
    expect(style.alignSelf).toBe('stretch');
    expect(style.height).toBe('100%');
    expect(style.minHeight).toBe('192px');
  });
});
