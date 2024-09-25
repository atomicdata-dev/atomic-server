import { BrowserRouter } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import { StoreContext, Store } from '@tomic/react';
import { StyleSheetManager } from 'styled-components';

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
import { DialogGlobalContextProvider } from './components/Dialog/DialogGlobalContextProvider';
import { registerHandlers } from './handlers';
import { ErrorBoundary } from './views/ErrorPage';
import { NetworkIndicator } from './components/NetworkIndicator';
import { getAgentFromLocalStorage } from './helpers/agentStorage';
import { DropdownContainer } from './components/Dropdown/DropdownContainer';
import { PopoverContainer } from './components/Popover';
import { SkipNav } from './components/SkipNav';
import { ControlLockProvider } from './hooks/useControlLock';
import { FormValidationContextProvider } from './components/forms/formValidation/FormValidationContextProvider';
import { registerCustomCreateActions } from './components/forms/NewForm/CustomCreateActions';
import isPropValid from '@emotion/is-prop-valid';
import { NewResourceUIProvider } from './components/forms/NewForm/useNewResourceUI';
import { serverURLStorage } from './helpers/serverURLStorage';

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

const serverUrl = fixDevUrl(serverURLStorage.get() ?? window.location.origin);
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

registerCustomCreateActions();
// Register global event handlers.
registerHandlers(store);

if (isDev()) {
  // You can access the Store from your console in dev mode!
  window.store = store;
}

// This implements the default behavior from styled-components v5
function shouldForwardProp(propName, target) {
  if (typeof target === 'string') {
    // For HTML elements, forward the prop if it is a valid HTML attribute
    return isPropValid(propName);
  }

  // For other elements, forward all props
  return true;
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
                <StyleSheetManager shouldForwardProp={shouldForwardProp}>
                  <ThemeWrapper>
                    {/* @ts-ignore TODO: Check if types are fixed or upgrade styled-components to 6.0.0 */}
                    <GlobalStyle />
                    {/* @ts-ignore fallback component type too strict */}
                    <ErrBoundary FallbackComponent={CrashPage}>
                      {/* Default form validation provider. Does not do anyting on its own but will make sure useValidation works without context*/}
                      <FormValidationContextProvider
                        onValidationChange={() => undefined}
                      >
                        <Toaster />
                        <MetaSetter />
                        <DropdownContainer>
                          <DialogGlobalContextProvider>
                            <PopoverContainer>
                              <DropdownContainer>
                                <NewResourceUIProvider>
                                  <SkipNav />
                                  <NavWrapper>
                                    <AppRoutes />
                                  </NavWrapper>
                                </NewResourceUIProvider>
                              </DropdownContainer>
                            </PopoverContainer>
                            <NetworkIndicator />
                          </DialogGlobalContextProvider>
                        </DropdownContainer>
                      </FormValidationContextProvider>
                    </ErrBoundary>
                  </ThemeWrapper>
                </StyleSheetManager>
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
