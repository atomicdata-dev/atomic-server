import * as React from 'react';
import { type JSX, useMemo } from 'react';
import { styled } from 'styled-components';

import { SideBar } from './SideBar';
import { OverlayContainer } from './OverlayContainer';
import { CalculatedPageHeight } from '../globalCssVars';
import { AISidebarContextProvider } from './AI/AISidebarContext';
import { AppVerifierProvider } from '@chunks/AppPage/AppVerifierContext';
import { AISidebarContainer } from './AI/AISidebarContainer';
import { RightPanelProvider } from './RightPanel/RightPanelContext';
import { CommentsPanelContainer } from './CommentsPanel/CommentsPanelContainer';
import { FollowSessionPanelContainer } from './Presence/FollowSessionPanelContainer';
import { MeetingMessageToaster } from './Presence/MeetingMessageToaster';
import { ResourceContextMenuHost } from './ResourceContextMenu';
import { HideInPrint } from './HideInPrint';
import { MAIN_CONTAINER } from '@helpers/containers';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { useResource } from '@tomic/react';
import NavBarContent from './NavBar';
import { useLocation } from '@tanstack/react-router';
import { useSettings } from '../helpers/AppSettings';
import { ChromeTheme } from '../styling';
import { paths } from '../routes/paths';
import { useRootWelcomeLayout } from '../context/RootWelcomeLayoutContext';
import { isHostedDistribution } from '../helpers/managedServer';

interface NavWrapperProps {
  children: React.ReactNode;
}

const AISidebarMemo = React.memo(AISidebarContainer);
const CommentsPanelMemo = React.memo(CommentsPanelContainer);
const FollowSessionPanelMemo = React.memo(FollowSessionPanelContainer);

/** Wraps the entire app and adds a navbar at the top or bottom */
export function NavWrapper({ children }: NavWrapperProps): JSX.Element {
  const { navbarTop, agent } = useSettings();
  const { rootWelcomeChromeHidden } = useRootWelcomeLayout();
  const [subject] = useCurrentSubject();
  const { pathname, searchStr } = useLocation();

  const onboardingOrChild =
    pathname === paths.onboarding ||
    pathname.startsWith(`${paths.onboarding}/`);
  const welcomeOrChild =
    pathname === paths.welcome || pathname.startsWith(`${paths.welcome}/`);
  // The demo splash ("Setting up your demo team…") is a transient
  // full-screen moment; rendering it between the sidebars reads as a
  // broken page.
  const demoSplash = pathname === paths.demo;
  // The hosted product has no signed-out mode: the sidebar's "new user /
  // sign in" affordances next to a spinner or an error read as a broken
  // account rather than as a page for a visitor. Until an identity is
  // loaded, whatever is on screen (a loading state, a sign-in guard, a
  // public share) stands on its own. A self-hosted node keeps its chrome
  // for anonymous browsing.
  const signedOutHosted = isHostedDistribution() && !agent;
  const hideGlobalChrome =
    rootWelcomeChromeHidden ||
    onboardingOrChild ||
    welcomeOrChild ||
    demoSplash ||
    signedOutHosted;

  const search = useMemo(() => new URLSearchParams(searchStr), [searchStr]);

  const contextualSubject = useMemo(
    () =>
      subject ||
      search.get('parentSubject') ||
      search.get('parent') ||
      search.get('newSubject') ||
      undefined,
    [subject, search],
  );

  return (
    <RightPanelProvider>
      <AISidebarContextProvider>
        {/* Owns the off-screen frame an app is checked in. Inside the AI
         * providers, because the tools that ask for a check live there. */}
        <AppVerifierProvider>
          {/* The single app-wide resource context menu (right-click). Mounted here
           * so its actions have the AI-sidebar, dialog, and router contexts. */}
          <ResourceContextMenuHost />
          {/* Toasts new meeting messages when the meeting panel isn't open. */}
          {!hideGlobalChrome && <MeetingMessageToaster />}
          {!hideGlobalChrome && (
            <TopBar subject={contextualSubject} top={navbarTop} />
          )}
          <SideBarWrapper
            top={navbarTop}
            fullViewportContent={hideGlobalChrome}
          >
            {!hideGlobalChrome && <SideBar />}
            <Content>{children}</Content>
            {!hideGlobalChrome && (
              <HideInPrint>
                <CommentsPanelMemo />
                <FollowSessionPanelMemo />
                <AISidebarMemo />
              </HideInPrint>
            )}
          </SideBarWrapper>
          <OverlayContainer />
        </AppVerifierProvider>
      </AISidebarContextProvider>
    </RightPanelProvider>
  );
}

interface ContentProps {}

const Content = styled.div<ContentProps>`
  display: block;
  flex: 1;
  container: ${MAIN_CONTAINER} / inline-size;
`;

/** Persistently shown navigation bar */
const TopBar = React.memo(function TopBar({
  subject,
  top,
}: {
  subject: string | undefined;
  top: boolean;
}): JSX.Element {
  const resource = useResource(subject);

  return (
    <ChromeTheme>
      <NavBarStyled aria-label='navigation' top={top}>
        <NavBarContent resource={resource} />
      </NavBarStyled>
    </ChromeTheme>
  );
});

const NavBarStyled = styled.div<{ top: boolean }>`
  position: fixed;
  ${p => (p.top ? 'top: 0;' : 'bottom: 0;')}
  left: 0;
  right: 0;
  z-index: ${p => p.theme.zIndex.sidebar};
  height: ${p => p.theme.heights.breadCrumbBar};
  display: flex;
  background-color: ${props => props.theme.colors.bg};
  border-${p => (p.top ? 'bottom' : 'top')}: solid 1px ${props => props.theme.colors.bg2};
  container-name: nav-bar;
  container-type: inline-size;

  @media print {
    display: none;
  }
`;

const SideBarWrapper = styled.div<{
  top: boolean;
  fullViewportContent?: boolean;
}>`
  /* Subtract the on-screen keyboard (see useKeyboardInset). On Android the
     webview is covered by the keyboard rather than resized for it, so 100dvh
     stays full-screen; the browser then reveals a focused field by scrolling
     the visual viewport, which drags this fixed element — and the top bar
     above it — off the top of the screen. Shrinking instead means the field is
     already visible and nothing scrolls. */
  ${p =>
    p.fullViewportContent
      ? CalculatedPageHeight.define(`calc(100dvh - var(--keyboard-inset, 0px))`)
      : CalculatedPageHeight.define(
          `calc(100dvh - ${p.theme.heights.breadCrumbBar} - var(--keyboard-inset, 0px))`,
        )}
  display: flex;
  height: ${CalculatedPageHeight.var()};
  position: fixed;
  ${p => {
    if (p.fullViewportContent) {
      return 'top: 0;';
    }

    return p.top ? `top: ${p.theme.heights.breadCrumbBar};` : 'top: 0;';
  }}
  left: 0;
  right: 0;

  opacity: 1;
  transition: opacity 0.3s ease-out;
  @starting-style {
    opacity: 0;
  }

  @media print {
    height: auto;
    ${CalculatedPageHeight.define('auto')}
    position: static;
    display: block;
  }
`;
