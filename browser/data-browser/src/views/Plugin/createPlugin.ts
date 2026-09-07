import type { PluginMetadata } from '@chunks/Plugins/plugins';
import {
  core,
  server,
  useStore,
  type JSONValue,
  type Resource,
  type Server,
} from '@tomic/react';
import toast from 'react-hot-toast';
import { useCustomViews } from '@components/CustomViewProvider';

interface CreatePluginProps {
  metadata: PluginMetadata;
  config: JSONValue;
  file: File;
  drive: Resource<Server.Drive>;
}

export function useCreatePlugin() {
  const store = useStore();
  const { refresh: refreshCustomViews } = useCustomViews();

  const createPluginResource = async ({
    metadata,
    file,
    drive,
    config,
  }: CreatePluginProps): Promise<Resource<Server.Plugin>> => {
    const plugin = await store.newResource({
      isA: server.classes.plugin,
      parent: drive.subject,
      propVals: {
        [core.properties.name]: metadata.name,
        [server.properties.namespace]: metadata.namespace,
        [server.properties.version]: metadata.version,
        [server.properties.config]: config,
      },
    });

    await plugin.save();

    const [fileSubject] = await store.uploadFiles([file], plugin.subject);

    // Setting the file triggers the installation on the server.
    await plugin.set(server.properties.pluginFile, fileSubject);

    await plugin.save();
    await plugin.refresh();

    // We refresh the resource so we can see the dynamic plugin-agent property that was added by the server.

    return plugin;
  };

  const addPluginToDrive = async (
    plugin: Resource<Server.Plugin>,
    drive: Resource<Server.Drive>,
  ): Promise<void> => {
    drive.push(server.properties.plugins, [plugin.subject], true);
    await drive.save();
  };

  const uninstallPlugin = async (
    plugin: Resource<Server.Plugin>,
  ): Promise<void> => {
    const driveSubject = plugin.props.parent;
    await plugin.destroy();

    const drive = await store.getResource<Server.Drive>(driveSubject);
    await drive.set(
      server.properties.plugins,
      drive.props.plugins?.filter(p => p !== plugin.subject),
    );
    await drive.save();
    await refreshCustomViews();
  };

  const updatePlugin = async (
    plugin: Resource<Server.Plugin>,
    metadata: PluginMetadata,
    file: File,
    updatedConfig?: JSONValue,
  ): Promise<void> => {
    if (
      metadata.name !== plugin.props.name ||
      metadata.namespace !== plugin.props.namespace
    ) {
      throw new Error(
        "The update's identifier does not match the existing plugin.",
      );
    }

    const [fileSubject] = await store.uploadFiles([file], plugin.subject);

    await plugin.set(server.properties.pluginFile, fileSubject);

    if (updatedConfig) {
      await plugin.set(server.properties.config, updatedConfig);
    }

    try {
      await plugin.save();
    } catch (err) {
      toast.error(err.message);
    }

    // Refresh so we see any new dynamic properties if those were added.
    await plugin.refresh();
  };

  return {
    createPluginResource,
    addPluginToDrive,
    uninstallPlugin,
    updatePlugin,
  };
}
