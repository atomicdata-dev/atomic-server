// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it } from 'vitest';
import { AvatarImg } from './AvatarImg';

afterEach(cleanup);

const theme = { colors: { bg2: '#ddd' } } as never;

function show(src: string | undefined) {
  return render(
    <ThemeProvider theme={theme}>
      <div style={{ width: 40, height: 40 }}>
        <AvatarImg src={src} alt='Polle' fallback={<b>P</b>} />
      </div>
    </ThemeProvider>,
  );
}

const status = (c: HTMLElement) =>
  c.querySelector('[data-avatar-status]')?.getAttribute('data-avatar-status');

it('reserves its box and shows a placeholder while the address is unknown', () => {
  const { container } = show(undefined);

  expect(status(container)).toBe('loading');
  expect(container.querySelector('img')).toBeNull();
});

it('shows the image once it loads', () => {
  const { container } = show('blob:a');

  expect(status(container)).toBe('loading');
  fireEvent.load(container.querySelector('img')!);
  expect(status(container)).toBe('loaded');
});

it('falls back on error and requests the image again on pageshow', () => {
  const { container } = show('https://x.test/a.png');

  fireEvent.error(container.querySelector('img')!);
  expect(container.querySelector('b')).not.toBeNull();
  expect(container.querySelector('img')).toBeNull();

  act(() => {
    window.dispatchEvent(new Event('pageshow'));
  });
  expect(container.querySelector('img')).not.toBeNull();
  fireEvent.load(container.querySelector('img')!);
  expect(status(container)).toBe('loaded');
});

it('does not reload an image that loaded', () => {
  const { container } = show('blob:a');
  const img = container.querySelector('img')!;

  fireEvent.load(img);
  act(() => {
    window.dispatchEvent(new Event('pageshow'));
  });
  expect(container.querySelector('img')).toBe(img);
});
