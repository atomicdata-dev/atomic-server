import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import { StoreContext, Store } from '@tomic/react';

import { GlobalStyle, ThemeWrapper } from './styling';
import { AppRoutes } from './routes/Routes';
import { NavWrapper } from './components/Navigation';
import { MetaSetter } from './components/MetaSetter';
import { Toaster } from './components/Toaster';
import { isDev } from './config';
import { initBugsnag } from './helpers/loggingHandlers';
import HotKeysWrapper from './components/HotKeyWrapper';
import { AppSettingsContextProvider } from './helpers/AppSettings';
import CrashPage from './views/CrashPage';
import { DialogContainer } from './components/Dialog/DialogContainer';
import { registerHandlers } from './handlers';
import { ErrorBoundary } from './views/ErrorPage';
import { NetworkIndicator } from './components/NetworkIndicator';
import { getAgentFromLocalStorage } from './helpers/agentStorage';
import { DropdownContainer } from './components/Dropdown/DropdownContainer';
import { PopoverContainer } from './components/Popover';
import { SkipNav } from './components/SkipNav';
import { ControlLockProvider } from './hooks/useControlLock';

function fixDevUrl(url: string) {
  if (isDev()) {
    return url.replace('5173', '9883');
  }

  return url;
}

/**
 * Defaulting to the current URL's origin will make sense in most non-dev environments.
 * In dev envs, we want to default to port 9883
 */
const serverUrl = fixDevUrl(window.location.origin);
const initalAgent = getAgentFromLocalStorage();

// Initialize the store
const store = new Store({
  agent: initalAgent,
  serverUrl,
});

store.parseMetaTags();

declare global {
  interface Window {
    bugsnagApiKey: string;
  }
}
// Setup bugsnag for error handling, but only if there's an API key
const ErrBoundary = window.bugsnagApiKey
  ? initBugsnag(window.bugsnagApiKey)
  : ErrorBoundary;

// Fetch all the Properties and Classes - this helps speed up the app.
store.preloadPropsAndClasses();

// Register global event handlers.
registerHandlers(store);

if (isDev()) {
  // You can access the Store from your console in dev mode!
  window.store = store;
}

/** Entrypoint of the application. This is where providers go. */
function App(): JSX.Element {
  return (
    <StoreContext.Provider value={store}>
      <AppSettingsContextProvider>
        <HelmetProvider>
          {/* Basename is for hosting on GitHub pages */}
          <BrowserRouter basename='/'>
            <ControlLockProvider>
              <HotKeysWrapper>
                <ThemeWrapper>
                  {/* @ts-ignore TODO: Check if types are fixed or upgrade styled-components to 6.0.0 */}
                  <GlobalStyle />
                  {/* @ts-ignore fallback component type too strict */}
                  <ErrBoundary FallbackComponent={CrashPage}>
                    <Toaster />
                    <MetaSetter />
                    <DropdownContainer>
                      <DialogContainer>
                        <PopoverContainer>
                          <DropdownContainer>
                            <SkipNav />
                            <NavWrapper>
                              <AppRoutes />
                            </NavWrapper>
                          </DropdownContainer>
                        </PopoverContainer>
                        <NetworkIndicator />
                      </DialogContainer>
                    </DropdownContainer>
                  </ErrBoundary>
                </ThemeWrapper>
              </HotKeysWrapper>
            </ControlLockProvider>
          </BrowserRouter>
        </HelmetProvider>
      </AppSettingsContextProvider>
    </StoreContext.Provider>
  );
}

export default App;

declare global {
  interface Window {
    store: Store;
  }
}
