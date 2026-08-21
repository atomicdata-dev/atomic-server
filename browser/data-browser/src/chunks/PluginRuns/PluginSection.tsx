import { useStore, type Resource } from '@tomic/react';
import { usePluginClass } from './runScript';

/**
 * Whether this resource is a plugin.
 *
 * A plugin's class is created per drive, so it has no fixed subject and cannot
 * appear in `ResourcePage`'s static switch. The check has to be a hook.
 */
export function useIsPlugin(resource: Resource): boolean {
  const store = useStore();
  const pluginClass = usePluginClass(store.getDrive());

  return pluginClass !== undefined && resource.hasClasses(pluginClass);
}
