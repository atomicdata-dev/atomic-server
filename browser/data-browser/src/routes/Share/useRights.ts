import {
  type Resource,
  useArray,
  core,
  urls,
  agentKeyOf,
  includesAgentSubject,
  sameAgentSubject,
} from '@tomic/react';
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
    // Keyed by the agent's key, not the spelling of its subject: the same
    // agent listed as `atomic:agent:X` in one list and `did:ad:agent:X` in the
    // other is one row.
    const rightsMap = new Map<string, RightBools & { agent: string }>();

    // Always show the public agent
    rightsMap.set(urls.instances.publicAgent, {
      agent: urls.instances.publicAgent,
      read: false,
      write: false,
    });

    readers.map(agent => {
      const key = agentKeyOf(agent);

      rightsMap.set(key, {
        agent: rightsMap.get(key)?.agent ?? agent,
        read: true,
        write: false,
      });
    });

    writers.map(agent => {
      const key = agentKeyOf(agent);
      const old = rightsMap.get(key) ?? { agent, read: false, write: false };
      rightsMap.set(key, {
        ...old,
        write: true,
      });
    });

    return Array.from(rightsMap.values())
      .map(right => ({
        agentSubject: right.agent,
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
      agents = includesAgentSubject(agents, agent)
        ? agents
        : [...agents, agent];
    } else {
      agents = agents.filter(s => !sameAgentSubject(s, agent));
    }

    if (write) {
      setWriters(agents);
    } else {
      setReaders(agents);
    }
  }

  return [rights, updateRights];
}
