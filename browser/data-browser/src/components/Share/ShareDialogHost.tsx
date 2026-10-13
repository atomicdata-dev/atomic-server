import { useEffect, useState, type JSX } from 'react';
import { OpenShareDialog } from './ShareDialog';
import { subscribeShareDialog } from './shareDialogState';

/**
 * Shows the Share dialog when something calls `openShareDialog(subject)`: the
 * "Share" action in the resource menu and the command palette, and the AI
 * tool that opens sharing settings.
 */
export function ShareDialogHost(): JSX.Element | null {
  const [subject, setSubject] = useState<string>();
  // A new key per request, so asking again while it is open starts afresh.
  const [request, setRequest] = useState(0);

  useEffect(
    () =>
      subscribeShareDialog(next => {
        setSubject(next);
        setRequest(r => r + 1);
      }),
    [],
  );

  if (!subject) return null;

  return (
    <OpenShareDialog
      key={request}
      subject={subject}
      onClosed={() => setSubject(undefined)}
    />
  );
}
