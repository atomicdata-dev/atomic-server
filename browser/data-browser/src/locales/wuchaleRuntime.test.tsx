// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { Composite } from 'wuchale';
import Message from '@wuchale/jsx/runtime.jsx';

afterEach(cleanup);

// browser/patches/@wuchale__jsx@0.12.5.patch: the runtime returns the pieces
// of a message as an array, and React dev builds warned that the elements in
// it (an icon next to a label, for example) have no key.
it('renders a message that mixes text and an element without a key warning', () => {
  const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);

  render(
    <button>
      <Message
        x={[[0], ' Add icon'] as unknown as Composite}
        t={[() => <svg data-testid='icon' />]}
        a={[]}
      />
    </button>,
  );

  expect(screen.getByTestId('icon')).toBeTruthy();
  expect(screen.getByRole('button').textContent).toBe(' Add icon');
  expect(errors).not.toHaveBeenCalled();
  errors.mockRestore();
});
