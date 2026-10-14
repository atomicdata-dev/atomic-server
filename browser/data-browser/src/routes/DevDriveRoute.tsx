import { createLazyRoute } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { useDevDrive } from '../hooks/useDevDrive';

// Module-level guard: React 19 StrictMode in dev mode mounts effects twice
// (mount → fake-unmount → remount), and concurrent rendering can re-mount
// the route again on rapid navigation. Without this guard each mount fires
// `createDevDrive()` and we end up with 2-4 fresh agents + drives stacked
// in the local store on a single visit. The ref short-circuits anything
// past the first invocation in this page's lifetime.
let inFlight: Promise<void> | null = null;

const DevDriveRoute: React.FC = () => {
  const { createDevDrive } = useDevDrive();
  const startedRef = useRef(false);
  // A dev-only route: say why it is stuck instead of leaving the splash up, so
  // an e2e run that never reaches the drive shows the reason in its snapshot.
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    if (inFlight) return;
    inFlight = createDevDrive()
      .catch(e => {
        console.error('[DevDrive] failed:', e);
        setFailure(
          /* @wc-ignore */ `Dev drive failed: ${e instanceof Error ? e.message : String(e)}`,
        );
      })
      .finally(() => {
        inFlight = null;
      });
  }, []);

  if (failure) {
    return (
      <p role='alert' style={{ padding: '1rem' }}>
        {failure}
      </p>
    );
  }

  return <p style={{ padding: '1rem' }}>Setting up dev drive...</p>;
};

export const devDriveRouteLazy = createLazyRoute('/app/dev-drive')({
  component: DevDriveRoute,
});
