import {
  createContext,
  useContext,
  useEffect,
  useState,
  type PropsWithChildren,
} from 'react';
import { useStore } from '@tomic/react';
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
  serverUrl: string,
  drive: string,
): Promise<PluginListResult> => {
  // Drive subjects (DIDs) often contain `+`. Without explicit encoding the
  // server's form-urlencoded query parser would decode `+` as space, so the
  // ClassExtenderScope::Drive comparison fails and plugin-list returns [].
  const response = await fetch(
    `${serverUrl}/plugin-list?drive=${encodeURIComponent(drive)}`,
  );
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
    const [list, newManifests] = await fetchPluginList(serverUrl, drive);
    setCustomViews(list);
    setUIPluginDataMap(newManifests);
  };

  const getPluginForClass = (classSubject: string) => {
    return customViews.get(classSubject);
  };

  const getUIPluginData = (plugin: string) => {
    return uiPluginDataMap.get(plugin)!;
  };

  useEffect(() => {
    fetchPluginList(serverUrl, drive)
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
