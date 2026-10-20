// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render } from '@testing-library/react';
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

  it('with a delay is an empty status until the delay has passed', () => {
    vi.useFakeTimers();

    try {
      const { container, getByRole } = renderSpinner({
        centered: true,
        delay: 1000,
      });

      expect(getByRole('status').childElementCount).toBe(0);
      expect(container.querySelector('svg')).toBeNull();

      act(() => vi.advanceTimersByTime(1000));

      expect(container.querySelector('svg')).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
