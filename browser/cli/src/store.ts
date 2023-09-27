import { Agent, Store } from '@tomic/lib';
import { atomicConfig } from './config.js';

const getCommandIndex = (): number | undefined => {
  const agentIndex = process.argv.indexOf('--agent');
  if (agentIndex !== -1) return agentIndex;

  const shortAgentIndex = process.argv.indexOf('-a');
  if (shortAgentIndex !== -1) return shortAgentIndex;

  return undefined;
};

const getAgent = (): Agent | undefined => {
  let secret;
  const agentCommandIndex = getCommandIndex();

  if (agentCommandIndex) {
    secret = process.argv[agentCommandIndex + 1];
  } else {
    secret = atomicConfig.agentSecret;
  }

  if (!secret) return undefined;

  return Agent.fromSecret(secret);
};

export const store = new Store();

const agent = getAgent();

if (agent) {
  store.setAgent(agent);
}
