import { useCurrentAgent, useStore } from '@tomic/react';
import { useSettings } from '@helpers/AppSettings';
import { grantIdentity } from './grantIdentity';
import { useLocalStorage } from '@hooks/useLocalStorage';

export interface PermissionScope {
  allowAll: boolean;
  allowed: string[];
}

export interface PluginPermissions {
  read: PermissionScope;
  write: PermissionScope;
}

const defaultValue = {
  read: {
    allowAll: false,
    allowed: [],
  },
  write: {
    allowAll: false,
    allowed: [],
  },
};

export function useStoredPluginGrants(plugin: string, type: 'read' | 'write') {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const { drive } = useSettings();
  const [grants, setGrantsStorage] = useLocalStorage<PluginPermissions>(
    grantIdentity(store.getServerUrl(), drive, agent?.subject ?? '', plugin),
    defaultValue,
  );

  const setGrants = (value: PermissionScope) => {
    setGrantsStorage({
      ...grants,
      [type]: value,
    });
  };

  const addGrant = (subject: string) => {
    if (grants[type].allowAll) return;

    if (grants[type].allowed.includes(subject)) return;

    setGrants({
      ...grants[type],
      allowed: [...grants[type].allowed, subject],
    });
  };

  return {
    grants: grants[type],
    setGrants,
    addGrant,
  };
}
