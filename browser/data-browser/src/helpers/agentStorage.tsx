import { Agent } from '@tomic/react';

const AGENT_LOCAL_STORAGE_KEY = 'agent';

export function getAgentFromLocalStorage(): Agent | undefined {
  const secret = localStorage.getItem(AGENT_LOCAL_STORAGE_KEY);

  if (!secret) {
    return undefined;
  }

  try {
    return Agent.fromSecret(secret);
  } catch (e) {
    console.error(e);

    return undefined;
  }
}

export function saveAgentToLocalStorage(agent: Agent | undefined): void {
  if (agent) {
    localStorage.setItem(AGENT_LOCAL_STORAGE_KEY, agent.buildSecret());
  } else {
    localStorage.removeItem(AGENT_LOCAL_STORAGE_KEY);
  }
}
