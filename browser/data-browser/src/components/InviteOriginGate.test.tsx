// @vitest-environment jsdom
// @wc-ignore-file
import React, { useEffect } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { InviteOriginGate } from './InviteOriginGate';
vi.mock('./Button', async importOriginal => ({
  ...(await importOriginal<typeof import('./Button')>()),
  Button: (props: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props} />
  ),
}));
afterEach(cleanup);

it('does not mount invite network effects until the exact foreign origin is confirmed', () => {
  const connect = vi.fn();

  function Invite() {
    useEffect(connect, []);

    return <p>Invitation loaded</p>;
  }

  const { rerender } = render(
    <InviteOriginGate
      origin='https://evil.example/app/invite'
      trustedOrigins={['https://app.example']}
    >
      <Invite />
    </InviteOriginGate>,
  );
  expect(connect).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole('button', { name: 'Continue to invitation' }),
  );
  expect(connect).toHaveBeenCalledTimes(1);
  rerender(
    <InviteOriginGate
      origin='https://sibling.evil.example'
      trustedOrigins={['https://app.example']}
    >
      <Invite />
    </InviteOriginGate>,
  );
  expect(screen.queryByText('Invitation loaded')).toBeNull();
});

it('allows a configured exact origin without promoting sibling subdomains', () => {
  render(
    <InviteOriginGate
      origin='https://team.example'
      trustedOrigins={['https://team.example/']}
    >
      <p>Invitation loaded</p>
    </InviteOriginGate>,
  );
  expect(screen.getByText('Invitation loaded')).toBeTruthy();
});
