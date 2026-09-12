import { createLazyRoute } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import { useSettings } from '../helpers/AppSettings';
import { SIDEBAR_TOGGLE_WIDTH } from '../components/SideBar';
import { useStore } from '@tomic/react';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { isClientDbEnabled, setClientDbEnabled } from '../helpers/clientDbMode';
import { isRunningInTauri } from '../helpers/tauri';
import { Shell } from '../views/getting-started/chrome';
import { Spinner } from '../components/Spinner';

// React 19 StrictMode mounts effects twice and rapid navigation can
// remount the route; without this module-level guard each mount would
// build a whole demo workspace (see DevDriveRoute for the same pattern).
let inFlight: Promise<void> | null = null;

/**
 * Starts the demo workspace immediately: mints a guest agent when
 * nobody is signed in, builds a FRESH drive (cleaning up a previous
 * demo run), starts the scripted scenario, and navigates to the
 * welcome doc. No interstitial — "Try the live demo" means the demo
 * starts.
 */
const DemoRoute: React.FC = () => {
  const store = useStore();
  const { setSideBarLocked } = useSettings();
  const navigate = useNavigateWithTransition();
  const [error, setError] = useState<Error | undefined>();
  const startedRef = useRef(false);

  const supported = isClientDbEnabled();

  useEffect(() => {
    if (!supported) {
      // Under Tauri the ClientDb is merely off by default (the embedded
      // server covers normal persistence), but the demo's local-only drives
      // need it. Opt in and reboot the webview — the worker only spawns at
      // app boot, and this route re-runs with it enabled.
      if (isRunningInTauri()) {
        setClientDbEnabled(true);
        window.location.reload();
      }

      return;
    }

    if (startedRef.current) return;
    startedRef.current = true;
    if (inFlight) return;

    inFlight = (async () => {
      const { startDemoWorkspace } = await import('../chunks/Demo/startDemo');
      const manifest = await startDemoWorkspace(store);
      if (window.innerWidth < SIDEBAR_TOGGLE_WIDTH) setSideBarLocked(true);
      navigate(constructOpenURL(manifest.welcomeDoc));
    })()
      .catch(e => {
        setError(
          e instanceof Error ? e : new Error('Could not start the demo'),
        );
      })
      .finally(() => {
        inFlight = null;
      });
  }, []);

  return (
    <Shell>
      <DemoStatus>
        {!error && <Spinner size='3.5rem' />}
        <DemoTitle>
          {error ? 'The demo could not start' : 'Setting up your demo…'}
        </DemoTitle>
        {!supported && !isRunningInTauri() && (
          <p>
            The demo needs the local database, which is disabled in this
            browser. Enable it on the Sync page and try again.
          </p>
        )}
        {error && <p role='alert'>{error.message}</p>}
      </DemoStatus>
    </Shell>
  );
};

const DemoStatus = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: ${p => p.theme.size(5)};
  max-width: 24rem;
  text-align: center;

  p {
    margin: 0;
    color: ${p => p.theme.colors.textLight};
  }
`;

const DemoTitle = styled.h1`
  margin: 0;
  font-size: 1.4rem;
  font-weight: 700;
  line-height: 1.25;
`;

export const demoRouteLazy = createLazyRoute('/app/demo')({
  component: DemoRoute,
});
