import { StyleSheetManager, type ShouldForwardProp } from 'styled-components';
import { DatabaseUpgradeNotice } from './components/DatabaseUpgradeNotice';
import { DialogGlobalContextProvider } from './components/Dialog/DialogGlobalContextProvider';
import { DropdownContainer } from './components/Dropdown/DropdownContainer';
import { FormValidationContextProvider } from './components/forms/formValidation/FormValidationContextProvider';
import { NewResourceUIProvider } from './components/forms/NewForm/useNewResourceUI';
import HotKeysWrapper from './components/HotKeyWrapper';
import { MetaSetter } from './components/MetaSetter';
import { NavWrapper } from './components/Navigation';
import { SearchOverlayContextProvider } from './components/Searchbar/SearchOverlayContext';
import { NetworkIndicator } from './components/NetworkIndicator';
import { PopoverContainer } from './components/Popover';
import { SkipNav } from './components/SkipNav';
import { ControlLockProvider } from './hooks/useControlLock';
import { useKeyboardInset } from './hooks/useKeyboardInset';
import { ThemeWrapper, GlobalStyle } from './styling';
import isPropValid from '@emotion/is-prop-valid';
import { initBugsnag } from './helpers/loggingHandlers';
import { ErrorBoundary } from './views/ErrorPage';
import CrashPage from './views/CrashPage';
import { AppSettingsContextProvider } from './helpers/AppSettings';
import { RootWelcomeLayoutProvider } from './context/RootWelcomeLayoutContext';
import { NavStateProvider } from './components/NavState';
import { Toaster } from './components/Toaster';
import { AISettingsContextProvider } from '@components/AI/AISettingsContext';
import { LocaleProvider } from '@components/LocaleContext';
import {
  CustomContextItemsProvider,
  ResourceContextMenuProvider,
} from './components/ResourceContextMenu';
import { LazyMCPProvider } from '@components/AI/MCP/LazyMCPProvider';
import { CustomViewProvider } from '@components/CustomViewProvider';
import { LazyAIChangesProvider } from '@components/AI/AIChanges/LazyAIChangesProvider';
import { FollowProvider } from '@components/Presence/FollowContext';
import { isRunningInTauri } from './helpers/tauri';

// Setup bugsnag for error handling, but only if there's an API key
const bugsnagApiKey =
  typeof window === 'undefined' ? undefined : window.bugsnagApiKey;
const ErrBoundary = bugsnagApiKey ? initBugsnag(bugsnagApiKey) : ErrorBoundary;

const VALID_PROPS = ['popover', 'closedby'];

// This implements the default behavior from styled-components v5
const shouldForwardProp: ShouldForwardProp<'web'> = (propName, target) => {
  if (typeof target === 'string') {
    // @emotion/is-prop-valid does not support popover, so we need to forward it manually.
    if (VALID_PROPS.includes(propName)) {
      return true;
    }

    // For HTML elements, forward the prop if it is a valid HTML attribute
    return isPropValid(propName);
  }

  // For other elements, forward all props
  return true;
};

export const Providers: React.FC<React.PropsWithChildren> = ({ children }) => {
  // Every screen with a text field needs the layout to shrink for the on-screen
  // keyboard, not just the onboarding ones — see useKeyboardInset.
  useKeyboardInset();

  return (
    <NavStateProvider>
      <LocaleProvider>
        <AppSettingsContextProvider>
          <RootWelcomeLayoutProvider>
            <AISettingsContextProvider>
              <LazyMCPProvider>
                <ControlLockProvider>
                  <HotKeysWrapper>
                    <StyleSheetManager
                      shouldForwardProp={shouldForwardProp}
                      disableCSSOMInjection={isRunningInTauri()}
                    >
                      <ThemeWrapper>
                        <GlobalStyle />
                        <ErrBoundary FallbackComponent={CrashPage}>
                          {/* Default form validation provider. Does not do anything on its own but will make sure useValidation works without context*/}
                          <FormValidationContextProvider
                            onValidationChange={() => undefined}
                          >
                            <Toaster />
                            <DatabaseUpgradeNotice />
                            <CustomViewProvider>
                              <MetaSetter />
                              <DropdownContainer>
                                <DialogGlobalContextProvider>
                                  <LazyAIChangesProvider>
                                    <PopoverContainer>
                                      <DropdownContainer>
                                        <CustomContextItemsProvider>
                                          <ResourceContextMenuProvider>
                                            <NewResourceUIProvider>
                                              <SkipNav />
                                              <SearchOverlayContextProvider>
                                                <FollowProvider>
                                                  <NavWrapper>
                                                    {children}
                                                  </NavWrapper>
                                                </FollowProvider>
                                              </SearchOverlayContextProvider>
                                            </NewResourceUIProvider>
                                          </ResourceContextMenuProvider>
                                        </CustomContextItemsProvider>
                                      </DropdownContainer>
                                    </PopoverContainer>
                                    <NetworkIndicator />
                                  </LazyAIChangesProvider>
                                </DialogGlobalContextProvider>
                              </DropdownContainer>
                            </CustomViewProvider>
                          </FormValidationContextProvider>
                        </ErrBoundary>
                      </ThemeWrapper>
                    </StyleSheetManager>
                  </HotKeysWrapper>
                </ControlLockProvider>
              </LazyMCPProvider>
            </AISettingsContextProvider>
          </RootWelcomeLayoutProvider>
        </AppSettingsContextProvider>
      </LocaleProvider>
    </NavStateProvider>
  );
};
