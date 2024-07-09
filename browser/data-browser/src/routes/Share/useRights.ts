import { type Resource, useArray, core, urls } from '@tomic/react';
import { useMemo } from 'react';

export interface RightBools {
  read: boolean;
  write: boolean;
}

export interface MergedRight extends RightBools {
  agentSubject: string;
  setIn: string;
}

type UpdateRights = (agent: string, write: boolean, state: boolean) => void;

export function useRights(
  resource: Resource,
  onError: (e: Error | undefined) => void,
): [rights: MergedRight[], updateRights: UpdateRights] {
  const valueOpts = {
    commit: false,
    handleValidationError: onError,
  };

  const [writers, setWriters] = useArray(
    resource,
    core.properties.write,
    valueOpts,
  );
  const [readers, setReaders] = useArray(
    resource,
    core.properties.read,
    valueOpts,
  );

  const rights: MergedRight[] = useMemo(() => {
    const rightsMap = new Map<string, RightBools>();

    // Always show the public agent
    rightsMap.set(urls.instances.publicAgent, { read: false, write: false });

    readers.map(agent => {
      rightsMap.set(agent, {
        read: true,
        write: false,
      });
    });

    writers.map(agent => {
      const old = rightsMap.get(agent) ?? { read: false, write: false };
      rightsMap.set(agent, {
        ...old,
        write: true,
      });
    });

    return Array.from(rightsMap.entries())
      .map(([agent, right]) => ({
        agentSubject: agent,
        setIn: resource.subject,
        read: right.read,
        write: right.write,
      }))
      .sort(a => {
        return a.agentSubject === urls.instances.publicAgent ? -1 : 1;
      });
  }, [readers, writers]);

  function updateRights(agent: string, write: boolean, state: boolean) {
    let agents = write ? writers : readers;

    if (state) {
      agents = Array.from(new Set([...agents, agent]));
    } else {
      agents = agents.filter(s => s !== agent);
    }

    if (write) {
      setWriters(agents);
    } else {
      setReaders(agents);
    }
  }

  return [rights, updateRights];
}
