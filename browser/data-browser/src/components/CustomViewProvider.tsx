import {
  createContext,
  useContext,
  useEffect,
  useState,
  type PropsWithChildren,
} from 'react';
import { signRequest, type Store, useStore } from '@tomic/react';
import { useSettings } from '@helpers/AppSettings';
import { useRegisterAppCreation } from '@chunks/AppPage/useRegisterAppCreation';

interface UIPluginManifest {
  css: boolean;
}

interface UIPluginListItem {
  plugin: string;
  classes: string[];
  uiManifest: UIPluginManifest;
  resource: string;
}

export type UIPluginData = Omit<UIPluginListItem, 'classes'>;

interface CustomViewContext {
  getPluginForClass: (classSubject: string) => string | undefined;
  getUIPluginData: (plugin: string) => UIPluginData;
  loading: boolean;
  refresh: () => Promise<void>;
}

const CustomViewContext = createContext<CustomViewContext>({
  getPluginForClass: () => undefined,
  getUIPluginData: () => ({
    plugin: '',
    uiManifest: { css: false },
    resource: '',
  }),
  loading: true,
  refresh: () => Promise.resolve(),
});

type PluginListResult = [
  views: Map<string, string>,
  pluginData: Map<string, UIPluginData>,
];

function parsePluginList(data: UIPluginListItem[]): PluginListResult {
  const viewMap = new Map<string, string>();
  const dataMap = new Map<string, UIPluginData>();

  for (const item of data) {
    for (const classSubject of item.classes) {
      viewMap.set(classSubject, item.plugin);
    }

    dataMap.set(item.plugin, {
      plugin: item.plugin,
      uiManifest: item.uiManifest,
      resource: item.resource,
    });
  }

  return [viewMap, dataMap];
}

const fetchPluginList = async (
  store: Store,
  drive: string,
): Promise<PluginListResult> => {
  // Drive subjects (DIDs) often contain `+`. Without explicit encoding the
  // server's form-urlencoded query parser would decode `+` as space, so the
  // ClassExtenderScope::Drive comparison fails and plugin-list returns [].
  const url = `${store.getServerUrl()}/plugin-list?drive=${encodeURIComponent(drive)}`;
  // The server lists only the plugins this agent may read, so the request
  // is signed like any other resource fetch; the cookie covers the
  // same-origin case. Only same-origin: a node answers a foreign origin (the
  // hosted app on app.atomic.place talking to node1) without
  // `Access-Control-Allow-Credentials`, and a request made with credentials
  // then fails CORS even though the signature alone would have been enough.
  const agent = store.getAgent();
  const headers = agent ? await signRequest(url, agent, {}) : {};
  const response = await fetch(url, { headers, credentials: 'same-origin' });
  const data = await response.json();

  return parsePluginList(data);
};

export function CustomViewProvider({ children }: PropsWithChildren) {
  const store = useStore();
  const { drive } = useSettings();

  // Choosing "App" in the New menu has to build a whole app, not one empty
  // resource. Registered here because this provider is always mounted and
  // already knows the drive, and the App class is minted per drive.
  useRegisterAppCreation(drive);
  const [customViews, setCustomViews] = useState<Map<string, string>>(
    new Map(),
  );
  const [uiPluginDataMap, setUIPluginDataMap] = useState<
    Map<string, UIPluginData>
  >(new Map());

  const [loading, setLoading] = useState(true);
  const serverUrl = store.getServerUrl();

  const refresh = async () => {
    if (!drive) return;

    const [list, newManifests] = await fetchPluginList(store, drive);
    setCustomViews(list);
    setUIPluginDataMap(newManifests);
  };

  const getPluginForClass = (classSubject: string) => {
    const plugin = customViews.get(classSubject);
    const installation = plugin && uiPluginDataMap.get(plugin)?.resource;

    // Uninstall removes the Installation before the refreshed plugin list
    // arrives. Do not mount its deleted assets during that interval.
    return installation && !store.isDestroyed(installation)
      ? plugin
      : undefined;
  };

  const getUIPluginData = (plugin: string) => {
    return uiPluginDataMap.get(plugin)!;
  };

  useEffect(() => {
    // Before a drive is chosen — a share link, the first seconds of
    // onboarding — there is nothing to scope the list to. Asking anyway sent
    // `?drive=`, which the server answers with an error carrying no CORS
    // headers, so the browser logged a blocked fetch on every such page.
    const request: Promise<PluginListResult> = drive
      ? fetchPluginList(store, drive)
      : Promise.resolve([new Map(), new Map()]);

    request
      .then(([views, manifests]) => {
        setCustomViews(views);
        setUIPluginDataMap(manifests);
      })
      .catch(() => {
        // Server unreachable — continue without plugins
      })
      .finally(() => {
        setLoading(false);
      });
  }, [serverUrl, drive]);

  return (
    <CustomViewContext
      value={{
        getPluginForClass,
        getUIPluginData,
        loading,
        refresh,
      }}
    >
      {children}
    </CustomViewContext>
  );
}

export function useCustomViews() {
  return useContext(CustomViewContext);
}
