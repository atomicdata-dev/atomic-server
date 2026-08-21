import { useStore, type Resource } from '@tomic/react';
import { PluginView } from './PluginView';
import { usePluginClass } from './runScript';

/**
 * Renders the plugin view, and only for a plugin.
 *
 * The default resource page is the fallback for anything without a dedicated
 * page, and a plugin lands there because its class is drive-local — a subject
 * that cannot be in `ResourcePage`'s static switch. So the check happens here.
 */
export function PluginSection({
  resource,
}: {
  resource: Resource;
}): React.JSX.Element | null {
  const store = useStore();
  const drive = store.getDrive();
  const pluginClass = usePluginClass(drive);

  if (pluginClass === undefined || !resource.hasClasses(pluginClass)) {
    return null;
  }

  return <PluginView resource={resource} drive={drive!} />;
}
