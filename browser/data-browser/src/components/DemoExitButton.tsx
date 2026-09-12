import { Button } from './Button';
import { useState } from 'react';
import { styled } from 'styled-components';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';
import { readTemplateDemo } from '../chunks/Templates/demoSession';
import { paths } from '../routes/paths';

/**
 * The shared action bar above navigation, shown whenever
 * the demo drive is active. Returns to the template gallery and stops
 * the scripted scenario.
 * Reads the demo manifest straight from localStorage — cheap, and it
 * keeps the heavy demo chunk out of the main bundle (only the click
 * loads it, to stop the director).
 */
export function DemoActionsBar(): React.JSX.Element | null {
  const store = useStore();
  const { drive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [leaving, setLeaving] = useState(false);

  const templateDemo = readTemplateDemo();
  const demoDrive = templateDemo?.drive ?? readDemoDrive();

  if (!demoDrive || drive !== demoDrive) return null;

  async function handleExit(adopt = false) {
    if (leaving) return;
    setLeaving(true);

    // Nothing in here may leave the user stranded in the demo with a stuck
    // "Leaving…" button: `finally` always resets, a `catch` always navigates
    // out, and the personal-drive lookup is time-boxed (a guest's DID isn't
    // on the server, so that fetch can stall indefinitely).
    try {
      if (templateDemo) {
        if (adopt) {
          navigate(
            `/app/new-drive?template=${encodeURIComponent(templateDemo.template)}&keep_preview=1`,
          );

          return;
        }

        store.setDrive(templateDemo.previousDrive);
        const { cleanupDemoDrive } = await import('../chunks/Demo/startDemo');
        await cleanupDemoDrive(store, templateDemo.drive);
        localStorage.removeItem('atomic.templateDemo');
        navigate(
          adopt
            ? `/app/new-drive?template=${encodeURIComponent(templateDemo.template)}`
            : '/app/new-drive',
        );

        return;
      }

      try {
        const { stopDemoDirector } = await import('../chunks/Demo/startDemo');
        stopDemoDirector();
      } catch {
        // The demo chunk failing to load must not trap the user here.
      }

      const agent = store.getAgent();
      const home = agent
        ? await withTimeout(
            fetchPrivateDriveSubject(store, agent).catch(() => undefined),
            2500,
          )
        : undefined;

      store.setDrive(home && home !== demoDrive ? home : '');
      const { cleanupDemoDrive } = await import('../chunks/Demo/startDemo');
      await cleanupDemoDrive(store, demoDrive!);
      localStorage.removeItem('atomic.demoWorkspace');
      navigate(paths.newDrive);
    } catch {
      // Last resort — return to the gallery, never a deleted demo drive.
      store.setDrive('');
      navigate(paths.newDrive);
    } finally {
      setLeaving(false);
    }
  }

  return (
    <PreviewBar role='region' aria-label='Template preview'>
      <Button subtle disabled={leaving} onClick={() => void handleExit()}>
        <BackLabel>Back to template selection</BackLabel>
        <ShortBackLabel>Back</ShortBackLabel>
      </Button>
      {templateDemo && (
        <Button disabled={leaving} onClick={() => void handleExit(true)}>
          Use this template
        </Button>
      )}
    </PreviewBar>
  );
}

/** Resolve `p`, but give up with `undefined` after `ms` — so a hung fetch
 *  can't freeze the caller. */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | undefined> {
  return Promise.race([
    p,
    new Promise<undefined>(resolve => setTimeout(() => resolve(undefined), ms)),
  ]);
}

export function readDemoDrive(): string | undefined {
  try {
    const raw = localStorage.getItem('atomic.demoWorkspace');

    return raw ? (JSON.parse(raw) as { drive?: string }).drive : undefined;
  } catch {
    return undefined;
  }
}

const PreviewBar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  height: 100%;
  box-sizing: border-box;
  padding: 0.5rem 1rem;
  button {
    white-space: nowrap;
  }
  @media (max-width: 600px) {
    padding: 0.5rem;
    button {
      font-size: 0.875rem;
    }
  }
  background: ${p => p.theme.colors.bg1};
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
`;

const BackLabel = styled.span`
  @media (max-width: 600px) {
    display: none;
  }
`;
const ShortBackLabel = styled.span`
  display: none;
  @media (max-width: 600px) {
    display: inline;
  }
`;
