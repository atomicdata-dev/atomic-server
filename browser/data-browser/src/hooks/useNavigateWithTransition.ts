import { useCallback } from 'react';
import { flushSync } from 'react-dom';
import { useNavigate } from 'react-router';
import { useSettings } from '../helpers/AppSettings';
const wait = (ms: number) => new Promise(r => setTimeout(r, ms));

/**
 * A wrapper around react-router's navigate function that will trigger css view transitions if enabled.
 */
export function useNavigateWithTransition() {
  const navigate = useNavigate();
  const { viewTransitionsDisabled } = useSettings();

  const navigateWithTransition = useCallback(
    (to: string | number) => {
      // @ts-ignore
      if (viewTransitionsDisabled || !document.startViewTransition) {
        //@ts-ignore
        navigate(to);

        return;
      }

      // @ts-ignore
      document.startViewTransition(
        async () =>
          new Promise<void>(resolve => {
            flushSync(() => {
              // @ts-ignore
              navigate(to);
              wait(1).then(() => {
                resolve();
              });
            });
          }),
      );
    },
    [navigate],
  );

  return navigateWithTransition;
}
