import { Agent, Store, type OptionalClass, type Resource } from '@tomic/lib';
import { atomicConfig } from './config.js';

const stripTrailingSlash = (url: string): string => url.replace(/\/$/, '');

const originFromHttpSubject = (subject: string): string | undefined => {
  if (!subject.startsWith('http://') && !subject.startsWith('https://')) {
    return undefined;
  }

  try {
    return new URL(subject).origin;
  } catch {
    return undefined;
  }
};

/** Configured origin, or the host of the first HTTP ontology subject. */
const resolveServerUrl = (): string | undefined => {
  const configured = atomicConfig.serverUrl?.trim();

  if (configured) {
    return stripTrailingSlash(configured);
  }

  for (const subject of atomicConfig.ontologies) {
    const origin = originFromHttpSubject(subject);

    if (origin) {
      return origin;
    }
  }

  return undefined;
};

const getCommandIndex = (): number | undefined => {
  const agentIndex = process.argv.indexOf('--agent');
  if (agentIndex !== -1) return agentIndex;

  const shortAgentIndex = process.argv.indexOf('-a');
  if (shortAgentIndex !== -1) return shortAgentIndex;

  return undefined;
};

const getAgent = async (): Promise<Agent | undefined> => {
  let secret;
  const agentCommandIndex = getCommandIndex();

  if (agentCommandIndex !== undefined) {
    secret = process.argv[agentCommandIndex + 1];
  } else {
    secret = atomicConfig.agentSecret;
  }

  if (!secret) return undefined;

  return Agent.fromSecret(secret, 'js');
};

const serverUrl = resolveServerUrl();

export const store = new Store(serverUrl ? { serverUrl } : {});

// CLI reads are ordinary HTTP requests. Do not make them wait for the
// background WebSocket handshake or Store will classify the first ontology
// fetch as an offline-only read and fail before it reaches the server.
store.setServerConnected(true);

/**
 * Point the store at the origin of an HTTP ontology URL so nested DID
 * subjects (classes, properties) resolve against the server that served
 * it, even if `atomic.config.json` still has the init default of localhost.
 */
export const ensureServerUrlForSubject = (subject: string): void => {
  const origin = originFromHttpSubject(subject);

  if (origin && origin !== store.getServerUrl()) {
    store.setServerUrl(origin);
  }
};

/**
 * The CLI is a finite batch process, so always perform complete HTTP reads.
 * A previous fetch can open the Store WebSocket; letting later reads switch
 * transports can return a commit notification before the full resource has
 * been materialized.
 */
export const fetchResource = <C extends OptionalClass>(
  subject: string,
): Promise<Resource<C>> => {
  ensureServerUrlForSubject(subject);

  return store.fetchResourceFromServer<C>(subject, { noWebSocket: true });
};

/**
 * Resolves once the agent (from `--agent` / `-a` or the config file) has been
 * installed on the store. Commands await this before their first read, so a
 * request cannot go out unsigned because the secret was still being parsed.
 */
export const ready: Promise<void> = getAgent().then(agent => {
  if (agent) {
    store.setAgent(agent);
  }
});
