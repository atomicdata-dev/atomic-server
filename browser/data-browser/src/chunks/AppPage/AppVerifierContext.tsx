// @wc-ignore-file
import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type PropsWithChildren,
} from 'react';
import { styled } from 'styled-components';
import { AppFrame, type AppOutcome } from './AppFrame';

/**
 * How long to wait before calling it inconclusive.
 *
 * An app that has not rendered in this long is not necessarily broken — it may
 * be waiting on a slow query — so the verdict says "could not tell", never
 * "failed". Reporting a slow app as broken would send a model off rewriting
 * code that works.
 */
const VERDICT_TIMEOUT_MS = 8000;

export type AppVerdict =
  | { verdict: 'renders'; children: number }
  | { verdict: 'broken'; message: string; stack?: string }
  | { verdict: 'unknown'; message: string };

interface AppVerifierValue {
  /** Opens an app out of sight and reports how it went. */
  verifyApp: (app: string, drive: string) => Promise<AppVerdict>;
}

const AppVerifierContext = createContext<AppVerifierValue>({
  verifyApp: async () => ({
    verdict: 'unknown',
    message: 'No verifier is mounted.',
  }),
});

export const useAppVerifier = () => useContext(AppVerifierContext);

/**
 * Runs an app once, off-screen, and says whether it worked.
 *
 * This exists because a model that has just written an app has no way to look
 * at it. It can read back what it saved, but not whether the code runs — and
 * the failures that matter most (a typo, a property that does not exist, a
 * view that renders nothing) are all invisible until something executes it.
 *
 * The run is real: the app's own code, in its own sandbox, with its own agent.
 * Which means an app that writes to its table on load will do so here too. That
 * is accepted rather than blocked — the app's rights already confine it to its
 * own subtree, opening it does the same thing a moment later, and a fake
 * read-only run would report false failures for every write it refused.
 */
export function AppVerifierProvider({
  children,
}: PropsWithChildren): React.JSX.Element {
  const [running, setRunning] = useState<{ app: string; drive: string }>();
  const settle = useRef<(verdict: AppVerdict) => void>(undefined);

  const finish = useCallback((verdict: AppVerdict) => {
    const resolve = settle.current;
    settle.current = undefined;
    setRunning(undefined);
    resolve?.(verdict);
  }, []);

  const verifyApp = useCallback(
    (app: string, drive: string): Promise<AppVerdict> => {
      // One at a time. The alternative is a frame per call, and a model that
      // creates three apps would run three at once for no benefit.
      if (settle.current) {
        return Promise.resolve({
          verdict: 'unknown' as const,
          message: 'Another app is being checked.',
        });
      }

      return new Promise<AppVerdict>(resolve => {
        const timer = setTimeout(() => {
          finish({
            verdict: 'unknown',
            message:
              'The app had not finished rendering after 8 seconds. It may be slow rather than broken.',
          });
        }, VERDICT_TIMEOUT_MS);

        settle.current = verdict => {
          clearTimeout(timer);
          resolve(verdict);
        };

        setRunning({ app, drive });
      });
    },
    [finish],
  );

  const onOutcome = useCallback(
    (outcome: AppOutcome) => {
      if (outcome.ok) {
        finish({ verdict: 'renders', children: outcome.children });

        return;
      }

      finish({
        verdict: 'broken',
        message: outcome.message,
        stack: outcome.stack,
      });
    },
    [finish],
  );

  return (
    <AppVerifierContext.Provider value={{ verifyApp }}>
      {children}
      {running && (
        // Off-screen rather than `display: none`: a hidden frame is allowed to
        // skip layout entirely, and an app that measures anything would see
        // zeroes and take a path nobody will ever take in real use.
        <OffScreen aria-hidden>
          <AppFrame
            key={`${running.app}-${running.drive}`}
            app={running.app}
            drive={running.drive}
            onOutcome={onOutcome}
            silent
          />
        </OffScreen>
      )}
    </AppVerifierContext.Provider>
  );
}

const OffScreen = styled.div`
  position: fixed;
  left: -10000px;
  top: 0;
  width: 800px;
  height: 600px;
  pointer-events: none;
`;
