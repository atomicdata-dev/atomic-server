// The shared visual chrome of the full-screen onboarding surfaces: the
// welcome/sign-in flow, the invite page, the demo intro, and the post-sign-in
// "connect a device" screen. Lives apart from GettingStartedFlow so a step it
// renders can use the chrome without importing its parent.

import { useEffect, useState, type ComponentProps } from 'react';
import { useStore } from '@tomic/react';
import { checkOnboardingStorage } from '../../helpers/onboardingStorage';
import { styled, css } from 'styled-components';
import { Button } from '../../components/Button';
import '@tomic/service-ui/background.css';

export function Shell({ children, ...props }: ComponentProps<'div'>) {
  const store = useStore();
  const [state, setState] = useState<'checking' | 'ready' | 'failed'>(
    'checking',
  );
  useEffect(() => {
    let active = true;
    void checkOnboardingStorage(store).then(
      () => {
        if (active) setState('ready');
      },
      () => {
        if (active) setState('failed');
      },
    );

    return () => {
      active = false;
    };
  }, [store]);

  return (
    <ShellSurface {...props}>
      {state === 'ready' ? (
        children
      ) : (
        <Card>
          {state === 'checking' ? (
            <p role='status'>Checking local storage…</p>
          ) : (
            <>
              <CardTitle>This browser could not open local storage</CardTitle>
              <p>
                Open this link in a non-private browser window and allow this
                site to store data. If you are already in a regular window,
                close other tabs for this site and try again.
              </p>
              <Button onClick={() => window.location.reload()}>
                Reload and try again
              </Button>
            </>
          )}
        </Card>
      )}
    </ShellSurface>
  );
}

const ShellSurface = styled.div.attrs(({ theme }) => ({
  className: 'atomic-product-background',
  'data-product-theme': theme.darkMode ? 'dark' : 'light',
}))`
  /* A concrete viewport height (not 100%): nothing in the html/body/#root
     chain sets a height, so 100% would collapse to content height and,
     because body is overflow:hidden, tall content (the welcome pitch on a
     phone) gets clipped with no way to scroll to the buttons. 100dvh tracks
     the visible viewport (excludes mobile browser UI), giving overflow-y a
     real height to scroll within.

     Minus the on-screen keyboard (see useKeyboardInset), which Android lets
     cover the webview rather than resizing it for. Shrinking the box means the
     content re-flows into what's still visible — and overflow-y takes over
     once it no longer fits — instead of sitting behind the keys. */
  height: calc(100dvh - var(--keyboard-inset, 0px));
  transition: height 150ms ease-out;

  @media (prefers-reduced-motion: reduce) {
    transition: none;
  }
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  /* Every onboarding step begins at the top; short forms must not float
     halfway down the viewport. Leave room to scroll the last action above
     the shared fixed Feedback control. */
  & > * {
    margin-block: 0;
  }
  /* The Android (Tauri) webview draws edge-to-edge under the system status
     and navigation bars — 100dvh includes those strips, so centered content
     ends up half-hidden behind the nav bar (the welcome buttons were
     unreachable on a phone). The safe-area insets (needs viewport-fit=cover,
     set in index.html) pad the content back into the visible region. */
  padding: calc(1.5rem + env(safe-area-inset-top, 0px)) ${p => p.theme.size(5)}
    calc(5.5rem + env(safe-area-inset-bottom, 0px));
  box-sizing: border-box;
`;

const cardSurface = css`
  box-sizing: border-box;
  width: 100%;
  margin-inline: auto;
  padding: ${p => p.theme.size(7)};
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  background: ${p => p.theme.colors.bg1};
  box-shadow: ${p => p.theme.boxShadowSoft};
  backdrop-filter: blur(10px);
`;

export const Card = styled.div`
  ${cardSurface}
  max-width: 26.5rem;
`;

export const CardTitle = styled.h2`
  margin: 0 0 ${p => p.theme.size(6)} 0;
  font-size: 1.4rem;
  font-weight: 700;
  line-height: 1.25;
  text-align: center;
`;

export const CardSubtitle = styled.p`
  margin: 0 0 ${p => p.theme.size(2)} 0;
  font-size: 0.95rem;
  color: ${p => p.theme.colors.textLight};
  text-align: center;
`;

export const CardError = styled.p`
  margin: ${p => p.theme.size(4)} 0 0 0;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.alert};
`;

export const CtaButton = styled(Button)`
  width: fit-content;
  min-width: 12.5rem;
  align-self: center;
  justify-content: center;
`;

export const OnboardingWrap = styled.div`
  width: 100%;
  max-width: 40rem;
  margin-inline: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
`;

export const OnboardingCard = styled.div`
  ${cardSurface}
  max-width: 36rem;
`;

export const FooterBar = styled.div`
  width: 100%;
  max-width: 36rem;
  margin-inline: auto;
  margin-top: ${p => p.theme.size(5)};
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: ${p => p.theme.size(4)};
`;

export const BackLabel = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.4em;
`;
