import { urls, useArray, useResource } from '@tomic/react';
import { useCallback, useMemo } from 'react';
import { isDev } from '../config';
import { useSettings } from '../helpers/AppSettings';

const rootDrives = [
  window.location.origin + '/',
  'https://atomicdata.dev/',
  ...(isDev() ? ['http://localhost:9883/'] : []),
];

const arrayOpts = {
  commit: true,
};

export function useSavedDrives(): [
  savedDrives: string[],
  add: (drive: string) => void,
  remove: (drive: string) => void,
] {
  const { agent } = useSettings();
  const agentResource = useResource(agent?.subject);
  const [drives, setDrives] = useArray(
    agentResource,
    urls.properties.drives,
    arrayOpts,
  );

  const extraDrives = useMemo(() => [...rootDrives, ...drives], [drives]);

  const add = useCallback(
    (drive: string) => {
      // Don't do anything if the drive is hardcoded into the list.
      if (rootDrives.includes(drive)) {
        return;
      }

      if (!drives.includes(drive)) {
        setDrives([...drives, drive]).then(() => {
          agentResource.save();
        });
      }
    },
    [drives, setDrives],
  );

  const remove = useCallback(
    (drive: string) => {
      // Don't do anything if the drive is hardcoded into the list.
      if (rootDrives.includes(drive)) {
        return;
      }

      if (drives.includes(drive)) {
        setDrives(drives.filter(d => d !== drive)).then(() => {
          agentResource.save();
        });
      }
    },
    [drives, setDrives],
  );

  return [extraDrives, add, remove];
}
