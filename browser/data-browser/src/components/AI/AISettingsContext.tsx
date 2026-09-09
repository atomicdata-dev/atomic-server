import { createContext, ReactNode, useContext, type JSX } from 'react';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { AIProvider } from './aiContstants';
import type { AIModelIdentifier, MCPServer } from '@chunks/AI/types';
import {
  defaultMCPServers,
  mergeDefaultMCPServers,
} from '@chunks/AI/defaultMCPServers';
import { useProviderAvailability } from './useProviderAvailability';

export const DEFAULT_CHAT_MODEL: AIModelIdentifier = {
  id: '~google/gemini-flash-latest',
  provider: AIProvider.OpenRouter,
};

interface AISettingsContextType {
  /** Enable all AI features in the app */
  enableAI: boolean;
  setEnableAI: (b: boolean) => void;
  /** List of MCP servers */
  mcpServers: MCPServer[];
  /** Update the list of MCP servers */
  setMcpServers: (servers: MCPServer[]) => void;
  /** Whether to show the token usage in AI chats */
  showTokenUsage: boolean;
  setShowTokenUsage: (b: boolean) => void;
  /** Whether to show the follow up prompts in AI chats */
  showFollowUpPrompts: boolean;
  setShowFollowUpPrompts: (b: boolean) => void;
  /** Default model for built-in agents and new custom agents */
  defaultChatModel: AIModelIdentifier;
  setDefaultChatModel: (model: AIModelIdentifier) => void;
  isProviderAvailable: (provider: AIProvider) => boolean;
  availableProviders: AIProvider[];
  openRouterAvailable: boolean;
  ollamaAvailable: boolean;
  /** The OpenRouter API key for making requests to OpenRouter */
  openRouterApiKey: string | undefined;
  setOpenRouterApiKey: (key: string | undefined) => void;
  /** The URL of the Ollama server */
  ollamaUrl: string | undefined;
  setOllamaUrl: (url: string | undefined) => void;
  shouldGenerateTitles: boolean;
  setShouldGenerateTitles: (b: boolean) => void;
  genFeaturesModel: AIModelIdentifier;
  setGenFeaturesModel: (model: AIModelIdentifier) => void;
}

interface ProviderProps {
  children: ReactNode;
}

const initialState: AISettingsContextType = {
  enableAI: true,
  setEnableAI: () => undefined,
  mcpServers: defaultMCPServers,
  setMcpServers: () => undefined,
  showTokenUsage: true,
  setShowTokenUsage: () => undefined,
  showFollowUpPrompts: true,
  setShowFollowUpPrompts: () => undefined,
  defaultChatModel: DEFAULT_CHAT_MODEL,
  setDefaultChatModel: () => undefined,
  isProviderAvailable: () => false,
  availableProviders: [],
  openRouterAvailable: false,
  ollamaAvailable: false,
  openRouterApiKey: undefined,
  setOpenRouterApiKey: () => undefined,
  // Unset until the user asks for local AI — see the note on the real default
  // in `AISettingsContextProvider` below.
  ollamaUrl: undefined,
  setOllamaUrl: () => undefined,
  shouldGenerateTitles: true,
  setShouldGenerateTitles: () => undefined,
  genFeaturesModel: {
    id: 'google/gemma-3-4b-it',
    provider: AIProvider.OpenRouter,
  },
  setGenFeaturesModel: () => undefined,
};

/**
 * The context must be provided by wrapping a high level React element in
 * <AISettingsContext.Provider value={new AISettingsContextType}>
 */
export const AISettingsContext =
  createContext<AISettingsContextType>(initialState);

/** Create a provider for AI settings */
export const AISettingsContextProvider = (
  props: ProviderProps,
): JSX.Element => {
  const [enableAI, setEnableAI] = useLocalStorage('atomic.ai.enabled', true);
  const [storedMcpServers, setStoredMcpServers] = useLocalStorage<MCPServer[]>(
    'atomic.ai.mcpServers',
    defaultMCPServers,
  );
  // Deliberately unset by default, even though `http://localhost:11434` is the
  // address almost every Ollama install uses — it stays as the input's
  // placeholder; LocalOllamaDiscovery probes only inside provider setup.
  //
  // A default here is not inert: this provider is mounted app-wide and runs a
  // reachability probe against the URL (`useProviderAvailability` below), so a
  // default meant every visitor's browser fetched `localhost:11434` on page
  // load. Browsers now gate requests from a public origin into the loopback
  // address space, so opening any page raised "<site> wants to access other
  // apps and services on this device" — before the visitor had asked for
  // anything AI-related. Beyond being alarming for someone who just opened a
  // document, a reflexive "Block" is remembered per-site and then silently
  // breaks Ollama for the people who actually want it.
  //
  // Unset means no probe (`useIsOllamaUrlValid` returns early on a falsy URL),
  // so the permission prompt only ever appears in response to someone
  // deliberately configuring local AI.
  const [ollamaUrl, setOllamaUrl] = useLocalStorage<string | undefined>(
    'atomic.ai.ollama-url',
    undefined,
  );
  const [showTokenUsage, setShowTokenUsage] = useLocalStorage(
    'atomic.ai.showTokenUsage',
    true,
  );
  const [openRouterApiKey, setOpenRouterApiKey] = useLocalStorage<
    string | undefined
  >('atomic.ai.openrouter-api-key', undefined);

  const [defaultChatModel, setDefaultChatModel] =
    useLocalStorage<AIModelIdentifier>(
      'atomic.ai.defaultChatModel',
      DEFAULT_CHAT_MODEL,
    );

  const [genFeaturesModel, setGenFeaturesModel] =
    useLocalStorage<AIModelIdentifier>('atomic.ai.genFeaturesModel', {
      id: 'google/gemma-3-4b-it',
      provider: AIProvider.OpenRouter,
    });

  const [showFollowUpPrompts, setShowFollowUpPrompts] = useLocalStorage(
    'atomic.ai.showFollowUpPrompts',
    true,
  );

  const [shouldGenerateTitles, setShouldGenerateTitles] = useLocalStorage(
    'atomic.ai.shouldGenerateTitles',
    true,
  );

  const {
    openRouterAvailable,
    ollamaAvailable,
    isProviderAvailable,
    availableProviders,
  } = useProviderAvailability(openRouterApiKey, ollamaUrl);

  const mcpServers = mergeDefaultMCPServers(storedMcpServers);
  const setMcpServers = (servers: MCPServer[]) =>
    setStoredMcpServers(mergeDefaultMCPServers(servers));

  const context = {
    openRouterApiKey,
    setOpenRouterApiKey,
    mcpServers,
    setMcpServers,
    enableAI,
    setEnableAI,
    showTokenUsage,
    setShowTokenUsage,
    ollamaUrl,
    setOllamaUrl,
    showFollowUpPrompts,
    setShowFollowUpPrompts,
    defaultChatModel,
    setDefaultChatModel,
    isProviderAvailable,
    availableProviders,
    openRouterAvailable,
    ollamaAvailable,
    shouldGenerateTitles,
    setShouldGenerateTitles,
    genFeaturesModel,
    setGenFeaturesModel,
  };

  return (
    <AISettingsContext.Provider value={context}>
      {props.children}
    </AISettingsContext.Provider>
  );
};

/** Hook for using AI Settings */
export const useAISettings = (): AISettingsContextType => {
  return useContext(AISettingsContext);
};
