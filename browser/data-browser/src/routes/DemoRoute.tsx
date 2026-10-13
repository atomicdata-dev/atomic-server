import { createLazyRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { useSettings } from '../helpers/AppSettings';
import { SIDEBAR_TOGGLE_WIDTH } from '../components/SideBar';
import { STORAGE_BLOCKED_ERROR_NAME, useStore, type Store } from '@tomic/react';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { isClientDbEnabled, setClientDbEnabled } from '../helpers/clientDbMode';
import { isRunningInTauri } from '../helpers/tauri';
import {
  afterNextPaint,
  hideBootSplash,
  isBootSplashVisible,
  setBootSplashCaption,
  showBootSplash,
} from '../helpers/bootSplash';
import { Button } from '../components/Button';
import * as Sentry from '@sentry/react';
import type { DemoSetupStep } from '../chunks/Demo/startDemo';
import {
  lateFinishContext,
  stallContext,
  stallWaitMs,
  type StepStarts,
} from '../chunks/Demo/demoSetupReport';
import { localAgentIsDisposable } from '../helpers/managed/reconcile';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';
import { withDeadline } from '../helpers/withDeadline';
import {
  demoForDrive,
  readInteractiveDemo,
} from '../chunks/Templates/demoSession';
import { demoRunningInAnotherTab } from '../helpers/demoTabLock';
import { paths } from './paths';

// Setup takes seconds on a laptop and several times that on a phone. Past
// this, say so and offer a way out rather than spin forever: a phone in an
// in-app browser once sat on the spinner with nothing reported (Sentry
// ATOMIC-BROWSER-1G). The step it was on is sent along, so the next such
// report says where it stopped. A stall fires at a fixed deadline, so setup
// that is merely slow reports the same as setup that is stuck: the report
// carries how long each step took, and a run that does finish afterwards
// says so in a second report.
const STALLED_AFTER_MS = 45_000;

const STEP_LABELS: Record<DemoSetupStep, string> = {
  storage: 'opening local storage',
  identity: 'creating a guest identity',
  cleanup: 'clearing a previous demo',
  workspace: 'building the demo workspace',
};

type DemoRun = {
  startedAt: number;
  step?: DemoSetupStep;
  /** When each step began, in ms since `startedAt`. */
  stepStarts: StepStarts;
  error?: Error;
  done: boolean;
  reported: boolean;
};

// One setup at a time, kept outside the component. React 19 StrictMode
// mounts effects twice and navigation can remount the route; without this
// each mount would build a whole demo workspace (see DevDriveRoute for the
// same pattern). It used to be a bare in-flight promise, and a remount then
// lost the run's outcome: the first instance heard the error, the visible one
// kept spinning. Every mount now reads the same run.
let run: DemoRun | undefined;
const listeners = new Set<() => void>();

function updateRun(patch: Partial<DemoRun>): void {
  if (!run) return;
  run = { ...run, ...patch };
  for (const listener of listeners) listener();
}

/**
 * The drive a signed-in visitor lands on instead of the demo: the one open
 * now unless that is a demo drive, else their home. Undefined when neither
 * resolves, which sends them to the drive gallery.
 */
async function signedInDrive(
  store: Store,
  currentDrive: string | undefined,
): Promise<string | undefined> {
  const agent = store.getAgent();
  if (!agent?.subject) return undefined;
  // Guests and identities without a workspace keep getting the demo.
  if (await localAgentIsDisposable(store, agent.subject)) return undefined;

  if (currentDrive && !demoForDrive(currentDrive)) return currentDrive;

  return (
    (await withDeadline(
      fetchPrivateDriveSubject(store, agent).catch(() => undefined),
      2_500,
      undefined,
    )) ?? paths.newDrive
  );
}

/** Setup went on past the stall notice and finished: say how long it took. */
function reportLateFinish(): void {
  if (!run?.reported) return;

  const { tags, extra } = lateFinishContext(
    run.stepStarts,
    Date.now() - run.startedAt,
  );

  Sentry.captureMessage('Demo setup finished after stall', {
    level: 'info',
    tags,
    extra,
  });
}

function startRun(
  store: Store,
  currentDrive: string | undefined,
  onReady: (manifest: { welcomeDoc: string; meeting?: string }) => void,
  onSignedIn: (target: string) => void,
): void {
  run = { startedAt: Date.now(), stepStarts: {}, done: false, reported: false };
  // Someone with an account who follows "Try the app" wants their own
  // workspace, not a scripted one built next to it.
  signedInDrive(store, currentDrive)
    .then(async target => {
      if (target) return target;

      // Another tab is running the demo: join it. Starting a new one here
      // would delete that tab's workspace.
      const running = readInteractiveDemo();

      if (running && (await demoRunningInAnotherTab())) {
        store.setDrive(running.drive);

        return running;
      }

      const { startDemoWorkspace } = await import('../chunks/Demo/startDemo');

      return startDemoWorkspace(store, step => {
        // Visible in a performance trace, to see which step a slow start spent
        // its time in.
        performance.mark(`demo.${step}`);
        updateRun({
          step,
          stepStarts: {
            ...run?.stepStarts,
            [step]: Date.now() - (run?.startedAt ?? Date.now()),
          },
        });
      });
    })
    .then(result => {
      updateRun({ done: true });
      reportLateFinish();
      if (typeof result === 'string') onSignedIn(result);
      else onReady(result);
    })
    .catch(e => {
      updateRun({
        error: e instanceof Error ? e : new Error('Could not start the demo'),
      });
    });
}

/**
 * Starts the demo workspace immediately: mints a guest agent when
 * nobody is signed in, builds a FRESH drive (cleaning up a previous
 * demo run), starts the scripted scenario, and navigates to the
 * onboarding meeting. No interstitial — "Try the live demo" means the demo
 * starts.
 */
const DemoRoute: React.FC = () => {
  const store = useStore();
  const { setSideBarLocked, drive, setDrive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [current, setCurrent] = useState<DemoRun | undefined>(run);
  const [stalled, setStalled] = useState(false);

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

    // One loading screen for the whole setup: the boot splash that is already
    // up on a first visit, brought back when the demo is started from inside
    // the app.
    showBootSplash();
    setBootSplashCaption('Setting up your demo…');

    // Re-running the demo must always start fresh, so only a run still in
    // progress is joined.
    if (!run || run.done || run.error) {
      startRun(
        store,
        drive,
        manifest => {
          if (window.innerWidth < SIDEBAR_TOGGLE_WIDTH) setSideBarLocked(true);
          // A fresh demo opens in its onboarding meeting; joining another
          // tab's demo (no `meeting` in what that tab stored) opens the doc.
          const landing = manifest.meeting ?? manifest.welcomeDoc;

          void revealWhenReady(store, landing);
          // Replace, don't push: /app/demo builds a fresh demo every time it
          // loads, so leaving it in history made Back rebuild the demo (and
          // tear down the one just left) instead of returning to the page the
          // visitor came from.
          navigate({
            to: constructOpenURL(landing),
            replace: true,
          });
        },
        target => {
          void afterNextPaint().then(() => hideBootSplash());

          if (target === paths.newDrive) {
            navigate({ to: target, replace: true });

            return;
          }

          setDrive(target);
          navigate({ to: constructOpenURL(target), replace: true });
        },
      );
    }

    const sync = () => setCurrent(run);
    listeners.add(sync);
    sync();

    // The deadline is checked against the wall clock when the timer fires. A
    // timer that fires early (a bot with virtual time, a throttled or
    // suspended tab) is not a stall: reschedule for what is left instead.
    let timer: ReturnType<typeof setTimeout>;

    const arm = (delay: number) => {
      timer = setTimeout(() => {
        if (!run || run.done || run.error) return;

        const elapsed = Date.now() - run.startedAt;
        const wait = stallWaitMs(elapsed, STALLED_AFTER_MS);

        if (wait > 0) {
          arm(wait);

          return;
        }

        setStalled(true);
        if (run.reported) return;
        run.reported = true;
        const { tags, extra } = stallContext(
          run.stepStarts,
          elapsed,
          document.visibilityState,
        );

        Sentry.captureMessage('Demo setup stalled', {
          level: 'warning',
          tags: { demo_step: run.step ?? 'loading', ...tags },
          extra,
        });
      }, delay);
    };

    arm(Math.max(0, STALLED_AFTER_MS - (Date.now() - run!.startedAt)));

    return () => {
      listeners.delete(sync);
      clearTimeout(timer);
    };
  }, []);

  const error = current?.error;
  const step = current?.step;
  const needsAttention = !!error || stalled || !supported;

  // Something to read or a button to press has to be on the page, not behind
  // the splash.
  useEffect(() => {
    if (needsAttention) hideBootSplash();
  }, [needsAttention]);

  // Otherwise the splash is the loading screen, and this renders nothing.
  if (!needsAttention && isBootSplashVisible()) return null;

  return (
    <Surface>
      <DemoStatus>
        <DemoTitle>
          {error ? 'The demo could not start' : 'Setting up your demo…'}
        </DemoTitle>
        {!supported && !isRunningInTauri() && (
          <p>
            The demo needs the local database, which is disabled in this
            browser. Enable it on the Sync page and try again.
          </p>
        )}
        {error && (
          <p role='alert'>
            {error.name === STORAGE_BLOCKED_ERROR_NAME
              ? 'The demo keeps its workspace in this browser, and this window does not allow that. Private windows in Firefox and Safari block it, and so do settings that block site data. Open this page in a normal window to try the demo.'
              : error.message}
          </p>
        )}
        {!error && stalled && (
          <p>
            This is taking longer than usual.
            {step && ` Still busy with: ${STEP_LABELS[step]}.`}
          </p>
        )}
        {(error || stalled) && (
          <Button onClick={() => window.location.reload()}>Try again</Button>
        )}
      </DemoStatus>
    </Surface>
  );
};

/**
 * Take the splash away once the landing resource can be shown with its
 * content, not as soon as the route changes: a reveal onto "Loading…" is the
 * very jump the splash is there to hide. Capped, so a slow document still
 * gets revealed.
 */
async function revealWhenReady(store: Store, landing: string) {
  await withDeadline(
    store.getResource(landing).then(() => undefined),
    2_000,
    undefined,
  ).catch(() => undefined);
  await afterNextPaint();
  // The editor mounts a beat after the route; let it lay out first.
  await new Promise(resolve => setTimeout(resolve, 150));
  hideBootSplash({ reveal: true });
}

const Surface = styled.main`
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100dvh;
  padding: ${p => p.theme.size(6)};
  box-sizing: border-box;
`;

const DemoStatus = styled.div`
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: ${p => p.theme.size(5)};
  max-width: 30rem;

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
