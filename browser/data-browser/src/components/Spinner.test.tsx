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

  it('draws the fading trail with a dot at its head', () => {
    const { container } = renderSpinner({});
    const paths = container.querySelectorAll('svg path');
    const circles = container.querySelectorAll('svg circle');

    expect(paths.length).toBeGreaterThan(10);
    expect(paths[0].getAttribute('stroke-linecap')).toBe('round');
    expect(paths[0].getAttribute('stroke')).toBe('currentColor');
    expect(Number(paths[0].getAttribute('stroke-opacity'))).toBeLessThan(0.1);
    expect(circles).toHaveLength(1);
    expect(circles[0].getAttribute('cy')).toBe('26');
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
