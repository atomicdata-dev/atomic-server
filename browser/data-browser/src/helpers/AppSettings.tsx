import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useMemo,
} from 'react';
import { DarkModeOption, useDarkMode } from './useDarkMode';
import {
  useLocalStorage,
  useCurrentAgent,
  useServerURL,
  Agent,
} from '@tomic/react';
import toast from 'react-hot-toast';
import { SIDEBAR_TOGGLE_WIDTH } from '../components/SideBar';
import { handleError } from './loggingHandlers';
import { serverURLStorage } from './serverURLStorage';

interface ProviderProps {
  children: ReactNode;
}

/** Create a provider for components to consume and subscribe to changes */
export const AppSettingsContextProvider = (
  props: ProviderProps,
): JSX.Element => {
  const [darkMode, setDarkMode, darkModeSetting] = useDarkMode();
  const [mainColor, setMainColor] = useLocalStorage('mainColor', '#1b50d8');
  const [navbarTop, setNavbarTop] = useLocalStorage('navbarTop', false);
  const [viewTransitionsDisabled, setViewTransitionsDisabled] = useLocalStorage(
    'viewTransitionsDisabled',
    false,
  );
  const [navbarFloating, setNavbarFloating] = useLocalStorage(
    'navbarFloating',
    true,
  );
  const [sideBarLocked, setSideBarLocked] = useLocalStorage(
    'sideBarOpen',
    window.innerWidth > SIDEBAR_TOGGLE_WIDTH,
  );

  const [sidebarKeyboardDndEnabled, setSidebarKeyboardDndEnabled] =
    useLocalStorage('sidebarKeyboardDndEnabled', false);

  const [agent, setAgent] = useCurrentAgent();
  const [baseURL, setBaseURL] = useServerURL();
  const [drive, innerSetDrive] = useLocalStorage('drive', baseURL);

  const setDrive = useCallback(
    (newDrive: string) => {
      const url = new URL(newDrive);
      innerSetDrive(newDrive);
      setBaseURL(url.origin);
      serverURLStorage.set(url.origin);
    },
    [innerSetDrive, setBaseURL],
  );

  const setAgentAndShowToast = useCallback(
    (newAgent: Agent | undefined) => {
      try {
        setAgent(newAgent);
        newAgent?.subject && toast.success('Signed in!');
        newAgent === undefined && toast.success('Signed out.');
      } catch (e) {
        handleError(new Error('Agent setting failed: ' + e.message));
      }
    },
    [setAgent],
  );

  const context = useMemo(
    () => ({
      drive,
      setDrive,
      darkMode,
      darkModeSetting,
      setDarkMode,
      mainColor,
      setMainColor,
      navbarTop,
      setNavbarTop,
      navbarFloating,
      setNavbarFloating,
      sideBarLocked,
      setSideBarLocked,
      agent,
      setAgent: setAgentAndShowToast,
      viewTransitionsDisabled,
      setViewTransitionsDisabled,
      sidebarKeyboardDndEnabled,
      setSidebarKeyboardDndEnabled,
    }),
    [
      drive,
      setDrive,
      darkMode,
      darkModeSetting,
      setDarkMode,
      mainColor,
      setMainColor,
      navbarTop,
      setNavbarTop,
      navbarFloating,
      setNavbarFloating,
      sideBarLocked,
      setSideBarLocked,
      agent,
      setAgentAndShowToast,
      viewTransitionsDisabled,
      setViewTransitionsDisabled,
      sidebarKeyboardDndEnabled,
      setSidebarKeyboardDndEnabled,
    ],
  );

  return (
    <SettingsContext.Provider value={context}>
      {props.children}
    </SettingsContext.Provider>
  );
};

/** A bunch of getters and setters for client-side app settings */
export interface AppSettings {
  /** Whether the App should render in dark mode. Checks user preferences. */
  darkMode: boolean;
  /** 'always', 'never' or 'auto' */
  darkModeSetting: DarkModeOption;
  /** When calling this with undefined (no arguments), it uses the browser's preference */
  setDarkMode: (b?: boolean) => void;
  /** CSS value for the primary color */
  mainColor: string;
  setMainColor: (s: string) => void;
  /** The URL that points to the Drive shown in the SideBar */
  drive: string;
  /** Sets the current Drive (and therefore, server!) */
  setDrive: (s: string) => void;
  /** If the navbar should be at the top of the page */
  navbarTop: boolean;
  setNavbarTop: (s: boolean) => void;
  /** If the navbar should be floating instead of being fixed at the top or bottom */
  navbarFloating: boolean;
  setNavbarFloating: (s: boolean) => void;
  /** If the Sidebar should be locked to the side */
  sideBarLocked: boolean;
  setSideBarLocked: (s: boolean) => void;
  /** The currently signed in Agent */
  agent: Agent | undefined;
  setAgent: (a: Agent | undefined) => void;
  /** If the app should use view transitions */
  viewTransitionsDisabled: boolean;
  setViewTransitionsDisabled: (b: boolean) => void;
  sidebarKeyboardDndEnabled: boolean;
  setSidebarKeyboardDndEnabled: (b: boolean) => void;
}

const initialState: AppSettings = {
  darkMode: false,
  darkModeSetting: DarkModeOption.auto,
  setDarkMode: () => undefined,
  mainColor: '',
  setMainColor: () => undefined,
  drive: '',
  setDrive: () => undefined,
  navbarTop: false,
  setNavbarTop: () => undefined,
  navbarFloating: false,
  setNavbarFloating: () => undefined,
  sideBarLocked: false,
  setSideBarLocked: () => undefined,
  agent: undefined,
  setAgent: () => undefined,
  viewTransitionsDisabled: true,
  setViewTransitionsDisabled: () => undefined,
  sidebarKeyboardDndEnabled: false,
  setSidebarKeyboardDndEnabled: () => undefined,
};

/** Hook for using App Settings, such as theme and darkmode */
export const useSettings = (): AppSettings => {
  return useContext(SettingsContext);
};

/**
 * The context must be provided by wrapping a high level React element in
 * <SettingsContext.Provider value={new AppSettings}>
 */
export const SettingsContext = createContext<AppSettings>(initialState);
