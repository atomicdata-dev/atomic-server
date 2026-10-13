import { useState, type ReactNode } from 'react';
import { inviteOrigin } from '../helpers/inviteNode';
import { Button } from './Button';
import { Column } from './Row';

/** Do not mount invite readers or change the signing destination before trust. */
export function InviteOriginGate({
  origin,
  trustedOrigins,
  children,
}: {
  origin: string | null;
  trustedOrigins: string[];
  children: ReactNode;
}) {
  const candidate = inviteOrigin(origin);
  const [confirmed, setConfirmed] = useState<string>();
  const trusted =
    !candidate ||
    trustedOrigins.some(value => inviteOrigin(value) === candidate);
  if (trusted || confirmed === candidate) return children;

  return (
    <Column>
      <h1>Open an invitation from another server?</h1>
      <p>
        This invitation connects to <strong>{candidate}</strong>. Continuing
        shares your public identity with this server. Only continue if you trust
        the person who sent it.
      </p>
      <Button onClick={() => setConfirmed(candidate)}>
        Continue to invitation
      </Button>
    </Column>
  );
}
