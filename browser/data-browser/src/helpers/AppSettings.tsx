import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useMemo,
  useEffect,
  type JSX,
} from 'react';
import { DarkModeOption, useDarkMode } from './useDarkMode';
import {
  useCurrentAgent,
  useServerURL,
  Agent,
  useStore,
  StoreEvents,
  Client,
} from '@tomic/react';
import toast from 'react-hot-toast';
import { SIDEBAR_TOGGLE_WIDTH } from '../components/SideBar';
import { serverURLStorage } from './serverURLStorage';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { errorHandler } from '../handlers/errorHandler';
import { isDev } from '../config';
import { getLocalServerOrigin, isRunningInTauri } from './tauri';
import { fetchManagedInfo, isAtomicServer } from './managedServer';

interface ProviderProps {
  children: ReactNode;
}

/** Create a provider for components to consume and subscribe to changes */
export const AppSettingsContextProvider = (
  props: ProviderProps,
): JSX.Element => {
  // == SYSTEM ==
  const [agent, setAgent] = useCurrentAgent();
  const [baseURL, setBaseURL] = useServerURL();
  const [drive, innerSetDrive] = useLocalStorage('drive', '');

  // == APPEARANCE ==
  const [darkMode, setDarkMode, darkModeSetting] = useDarkMode();
  const [mainColor, setMainColor] = useLocalStorage('mainColor', '#1b50d8');
  const [colorfulMode, setColorfulMode] = useLocalStorage(
    'colorfulMode',
    false,
  );
  const [hideTemplates, setHideTemplates] = useLocalStorage(
    'hideTemplates',
    false,
  );
  const [sideBarLocked, setSideBarLocked] = useLocalStorage(
    'sideBarOpen',
    window.innerWidth > SIDEBAR_TOGGLE_WIDTH,
  );
  const [navbarTop, setNavbarTop] = useLocalStorage('navbarTop', true);

  // == CONTENT LANGUAGE ==
  // The language localized *content* (LocalizedText values, translated
  // resources) is shown in — independent of the UI chrome language.
  const [contentLanguage, setContentLanguage] = useLocalStorage(
    'contentLanguage',
    navigator.language.split('-')[0],
  );

  const store = useStore();

  useEffect(() => {
    return store.on(StoreEvents.DriveChanged, newDrive => {
      if (newDrive !== drive) {
        innerSetDrive(newDrive);
      }
    });
  }, [drive, store, innerSetDrive]);

  useEffect(() => {
    store.setDrive(drive);
  }, [drive, store]);

  // == ACCESSIBILITY ==
  const [viewTransitionsDisabled, setViewTransitionsDisabled] = useLocalStorage(
    'viewTransitionsDisabled',
    false,
  );
  const [sidebarKeyboardDndEnabled, setSidebarKeyboardDndEnabled] =
    useLocalStorage('sidebarKeyboardDndEnabled', false);

  // The origin serving this app is usually a node worth listing on /sync — a
  // self-hosted atomic-server serves its own data-browser. But not always: the
  // managed deployment serves the SPA from a shared app origin (the portal's
  // process, not an atomic-server), and listing that as a device would be a
  // lie — "Switch" would point the store at something that can't answer. So
  // ask `/server` first and register only a real node. A non-answer also
  // *removes* the origin, cleaning up entries older builds added blindly; a
  // wrongly-removed node (transient fetch failure) re-adds itself on the next
  // load that reaches it.
  useEffect(() => {
    // In dev the server runs on its own port, which is configured — not a
    // constant. Hardcoding one meant this probe re-added that origin to the
    // known-servers list on *every* mount, so removing it from the sync page
    // never stuck, and pointing `VITE_ATOMIC_SERVER_URL` somewhere else left
    // a permanent ghost entry for a server the app doesn't use.
    const currentOrigin = isDev()
      ? (import.meta.env.VITE_ATOMIC_SERVER_URL ?? getLocalServerOrigin())
      : getLocalServerOrigin();

    fetchManagedInfo(currentOrigin).then(info => {
      if (isAtomicServer(info)) {
        serverURLStorage.addKnownServer(currentOrigin);
      } else {
        serverURLStorage.removeKnownServer(currentOrigin);
      }
    });
  }, []);

  const setServer = useCallback(
    (newServer: string) => {
      if (newServer.startsWith('http://') || newServer.startsWith('https://')) {
        const url = new URL(newServer);
        setBaseURL(url.origin);
        // Explicit: someone typed this, picked it from the list, or followed a
        // `?server=` link. This is the only kind of choice allowed to outrank
        // a device's own embedded node on the next launch.
        serverURLStorage.set(url.origin, true);
      }
    },
    [setBaseURL],
  );

  const setDrive = useCallback(
    (newDrive: string) => {
      innerSetDrive(newDrive);

      // A bare origin is a server switch (`https://host`). An HTTP drive
      // with a path is a workspace — including one on another origin.
      // Following that origin would move the whole session (websocket,
      // DID auth, every later fetch) onto a replica that may not speak
      // this client's protocol. Fetch it cross-origin; keep the home
      // server. `Store.setDrive` is the other half of this split.
      if (Client.isBareHttpOrigin(newDrive)) {
        const url = new URL(newDrive);
        // Opening a drive that lives elsewhere does mean reading from its
        // server for now.
        setBaseURL(url.origin);

        // But it is not a decision about where this app belongs. On a device
        // with its own node, persisting it is how a single visit to one
        // `https://…/drive/…` entry in the switcher left the app booting
        // against that server forever, ignoring the node running beside it.
        // Session-only here; `setServer` is the deliberate route.
        if (!isRunningInTauri()) {
          serverURLStorage.set(url.origin);
        }

        return;
      }

      // An HTTP drive with a path is a workspace, not a server: it is fetched
      // cross-origin and the home server stays where it is. That means it must
      // not reach the come-home branch below either. Before the origin/drive
      // split above, every `http(s)://` subject left through the early return;
      // now only a bare origin does, so without this a `https://host/drive/abc`
      // would fall through and repoint the session that was meant to stay.
      if (newDrive.startsWith('http://') || newDrive.startsWith('https://')) {
        return;
      }

      // A `did:` drive names no server, so this branch did nothing at all —
      // and that is how switching away and back stranded the app. Opening an
      // `https://…` drive repoints the store at that origin; coming back to a
      // drive that lives on THIS device left it pointed at the previous one.
      // Every collection then answers from a server that does not hold this
      // drive — or, if it is unreachable, answers nothing — and the sidebar
      // renders empty with no indication that the app is asking the wrong
      // machine. Restarting fixed it, which is what made it look
      // intermittent: `embeddedNodeWins` re-applies the device's own node at
      // boot, and nothing re-applied it here.
      //
      // Same rule as boot: a server the person actually chose outranks the
      // node running beside them — but it does NOT mean "stay wherever the
      // last drive put you". Gating the whole restore on `wasExplicitlyChosen`
      // left anyone who had ever picked a server stranded on the origin of the
      // https drive they just came from, which is the bug this branch is
      // supposed to fix, merely harder to reach.
      //
      // So come home either way; only the destination differs.
      if (isRunningInTauri()) {
        const chosen = serverURLStorage.wasExplicitlyChosen()
          ? serverURLStorage.get()
          : undefined;

        setBaseURL(chosen ?? getLocalServerOrigin());
      }
    },
    [innerSetDrive, setBaseURL],
  );

  const setAgentAndShowToast = useCallback(
    (newAgent: Agent | undefined) => {
      try {
        setAgent(newAgent);

        if (newAgent?.subject) {
          toast.success('Signed in!');
        }

        if (newAgent === undefined) {
          toast.success('Signed out.');
        }
      } catch (e) {
        errorHandler(new Error('Agent setting failed: ' + e.message));
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
      colorfulMode,
      setColorfulMode,
      sideBarLocked,
      setSideBarLocked,
      agent,
      setAgent: setAgentAndShowToast,
      viewTransitionsDisabled,
      setViewTransitionsDisabled,
      sidebarKeyboardDndEnabled,
      setSidebarKeyboardDndEnabled,
      hideTemplates,
      setHideTemplates,
      baseURL,
      setBaseURL,
      setServer,
      navbarTop,
      setNavbarTop,
      contentLanguage,
      setContentLanguage,
    }),
    [
      drive,
      setDrive,
      darkMode,
      darkModeSetting,
      setDarkMode,
      mainColor,
      setMainColor,
      colorfulMode,
      setColorfulMode,
      sideBarLocked,
      setSideBarLocked,
      agent,
      setAgentAndShowToast,
      viewTransitionsDisabled,
      setViewTransitionsDisabled,
      sidebarKeyboardDndEnabled,
      setSidebarKeyboardDndEnabled,
      hideTemplates,
      setHideTemplates,
      baseURL,
      setBaseURL,
      setServer,
      navbarTop,
      setNavbarTop,
      contentLanguage,
      setContentLanguage,
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
  /** If true, UI neutrals (backgrounds, text) are tinted with the main color */
  colorfulMode: boolean;
  setColorfulMode: (b: boolean) => void;
  /** The URL that points to the Drive shown in the SideBar */
  drive: string;
  /** Sets the current Drive (and therefore, server!) */
  setDrive: (s: string) => void;
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
  hideTemplates: boolean;
  setHideTemplates: (b: boolean) => void;
  /** The URL of the currently active server / peer used for resolution. */
  baseURL: string;
  /** Sets the active server / peer. */
  setBaseURL: (s: string) => void;
  /** Robustly sets the server and adds it to the known list. */
  setServer: (s: string) => void;
  /** Whether the navbar should be at the top or bottom */
  navbarTop: boolean;
  setNavbarTop: (b: boolean) => void;
  /** BCP 47 tag localized content is shown in (not the UI chrome language) */
  contentLanguage: string;
  setContentLanguage: (s: string) => void;
}

const initialState: AppSettings = {
  darkMode: false,
  darkModeSetting: DarkModeOption.auto,
  setDarkMode: () => undefined,
  mainColor: '',
  setMainColor: () => undefined,
  colorfulMode: false,
  setColorfulMode: () => undefined,
  drive: '',
  setDrive: () => undefined,
  sideBarLocked: false,
  setSideBarLocked: () => undefined,
  agent: undefined,
  setAgent: () => undefined,
  viewTransitionsDisabled: true,
  setViewTransitionsDisabled: () => undefined,
  sidebarKeyboardDndEnabled: false,
  setSidebarKeyboardDndEnabled: () => undefined,
  hideTemplates: false,
  setHideTemplates: () => undefined,
  baseURL: '',
  setBaseURL: () => undefined,
  setServer: () => undefined,
  navbarTop: true,
  setNavbarTop: () => undefined,
  contentLanguage: 'en',
  setContentLanguage: () => undefined,
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
