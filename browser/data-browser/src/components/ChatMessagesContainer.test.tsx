// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { act, cleanup, fireEvent, render } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../styling';
import { ChatMessagesContainer } from './ChatMessagesContainer';

vi.mock('@components/ScrollArea', async () => {
  const { forwardRef } = await import('react');

  return {
    ScrollArea: forwardRef<
      HTMLDivElement,
      React.HTMLAttributes<HTMLDivElement>
    >(({ children, ...props }, ref) => (
      <div>
        <div {...props} ref={ref} data-testid='viewport'>
          {children}
        </div>
      </div>
    )),
    ScrollViewPort: 'div',
  };
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it.each(['viewport grows', 'content shrinks'])(
  'keeps the reader position when %s before the scroll event arrives',
  change => {
    let resized: ResizeObserverCallback;
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(callback: ResizeObserverCallback) {
          resized = callback;
        }
        observe() {}
        disconnect() {}
      },
    );
    const { getByTestId } = render(
      <ThemeProvider theme={buildTheme(false, '#336699', false)}>
        <ChatMessagesContainer enableAutoScroll>Messages</ChatMessagesContainer>
      </ThemeProvider>,
    );
    const viewport = getByTestId('viewport');
    let height = 200;
    let content = 1000;
    let top = 800;
    Object.defineProperties(viewport, {
      clientHeight: { get: () => height },
      scrollHeight: { get: () => content },
      scrollTop: {
        get: () => top,
        set: value => {
          top = Math.min(value, content - height);
        },
      },
    });
    viewport.scrollTo = vi.fn((options?: ScrollToOptions | number) => {
      top = (options as ScrollToOptions).top!;
    });
    fireEvent.scroll(viewport);
    fireEvent.wheel(viewport, { deltaY: -300 });
    top = 100;
    if (change === 'viewport grows') height = 300;
    else content = 900;
    fireEvent.scroll(viewport);
    act(() =>
      resized(
        [
          {
            target: viewport,
            contentRect: viewport.getBoundingClientRect(),
            borderBoxSize: [],
            contentBoxSize: [],
            devicePixelContentBoxSize: [],
          },
        ],
        {} as ResizeObserver,
      ),
    );
    expect(viewport.scrollTop).toBe(100);
  },
);
