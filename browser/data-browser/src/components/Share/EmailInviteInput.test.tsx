// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { EmailInviteInput } from './EmailInviteInput';
import type { ShareRole } from './RoleSelect';

afterEach(cleanup);

const theme = { colors: {} } as unknown as DefaultTheme;
const writeRole: ShareRole = 'write';

const renderInput = () =>
  render(
    <ThemeProvider theme={theme}>
      <EmailInviteInput
        emails={[]}
        onEmailsChange={() => undefined}
        draft=''
        onDraftChange={() => undefined}
        role={writeRole}
        onRoleChange={() => undefined}
      />
    </ThemeProvider>,
  );

it('leaves focus on the role switch when it is clicked', () => {
  const { getByLabelText, getByRole } = renderInput();
  const input = getByLabelText('Add people by email');
  const read = getByRole('radio', { name: 'Read' });

  read.focus();
  fireEvent.click(read);

  expect(document.activeElement).toBe(read);
  expect(document.activeElement).not.toBe(input);
});

it('focuses the input when the empty part of the field is clicked', () => {
  const { getByLabelText } = renderInput();
  const input = getByLabelText('Add people by email');
  const field = input.closest('div')!.parentElement!;

  fireEvent.click(field);

  expect(document.activeElement).toBe(input);
});

it('asks password managers not to fill the invite field', () => {
  const { getByLabelText } = renderInput();
  const input = getByLabelText('Add people by email');

  expect(input.getAttribute('type')).toBe('email');
  expect(input.getAttribute('autocomplete')).toBe('off');
  expect(input.hasAttribute('data-bwignore')).toBe(true);
  expect(input.hasAttribute('data-1p-ignore')).toBe(true);
  expect(input.getAttribute('data-lpignore')).toBe('true');
});
