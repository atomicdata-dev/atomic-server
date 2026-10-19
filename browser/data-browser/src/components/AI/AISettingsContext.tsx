import { createContext, ReactNode, useContext, useMemo, type JSX } from 'react';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { AIProvider } from './aiContstants';
import type { AIModelIdentifier, MCPServer } from '@chunks/AI/types';
import {
  defaultMCPServers,
  mergeDefaultMCPServers,
} from '@chunks/AI/defaultMCPServers';
import { useProviderAvailability } from './useProviderAvailability';
import { useHostedAI } from './useHostedAI';
import { enableHostedAI, type HostedAIStatus } from '@helpers/managed/ai';
import { showWebAI } from '../../embed/settings';

export const DEFAULT_CHAT_MODEL: AIModelIdentifier = {
  id: '~google/gemini-flash-latest',
  provider: AIProvider.OpenRouter,
};

interface AISettingsContextType {
  hostedAI?: HostedAIStatus;
  enableIncludedAI: () => Promise<void>;
  /** Enable all AI features in the app */
  enableAI: boolean;
  setEnableAI: (b: boolean) => void;
  openRouterZdr: boolean;
  setOpenRouterZdr: (enabled: boolean) => void;
  voiceEnabled: boolean;
  setVoiceEnabled: (enabled: boolean) => void;
  transcriptionModel: string;
  setTranscriptionModel: (model: string) => void;
  /** Device id of the microphone used for voice input, empty for the system default */
  microphoneId: string;
  setMicrophoneId: (id: string) => void;
  /** List of MCP servers */
  mcpServers: MCPServer[];
  /** Update the list of MCP servers */
  setMcpServers: (servers: MCPServer[]) => void;
  /** Whether to show the token usage in AI chats */
  showTokenUsage: boolean;
  setShowTokenUsage: (b: boolean) => void;
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
  enableIncludedAI: async () => {},
  openRouterZdr: false,
  setOpenRouterZdr: () => undefined,
  voiceEnabled: true,
  setVoiceEnabled: () => undefined,
  transcriptionModel: 'openai/whisper-1',
  setTranscriptionModel: () => undefined,
  microphoneId: '',
  setMicrophoneId: () => undefined,
  enableAI: true,
  setEnableAI: () => undefined,
  mcpServers: defaultMCPServers,
  setMcpServers: () => undefined,
  showTokenUsage: true,
  setShowTokenUsage: () => undefined,
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
  const [enableAISetting, setEnableAI] = useLocalStorage(
    'atomic.ai.enabled',
    true,
  );
  // The app's web view has no AI of its own; see `showWebAI`.
  const enableAI = enableAISetting && showWebAI();
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

  const [openRouterZdr, setOpenRouterZdr] = useLocalStorage(
    'atomic.ai.openRouterZdr',
    false,
  );
  const [voiceEnabled, setVoiceEnabled] = useLocalStorage(
    'atomic.ai.voiceEnabled',
    true,
  );
  const [transcriptionModel, setTranscriptionModel] = useLocalStorage(
    'atomic.ai.transcriptionModel',
    'openai/whisper-1',
  );
  const [microphoneId, setMicrophoneId] = useLocalStorage(
    'atomic.ai.microphoneId',
    '',
  );

  const [storedDefaultChatModel, setDefaultChatModel] =
    useLocalStorage<AIModelIdentifier>(
      'atomic.ai.defaultChatModel',
      DEFAULT_CHAT_MODEL,
    );

  const [storedGenFeaturesModel, setGenFeaturesModel] =
    useLocalStorage<AIModelIdentifier>('atomic.ai.genFeaturesModel', {
      id: 'google/gemma-3-4b-it',
      provider: AIProvider.OpenRouter,
    });

  const [shouldGenerateTitles, setShouldGenerateTitles] = useLocalStorage(
    'atomic.ai.shouldGenerateTitles',
    true,
  );

  const { hostedAI, setHostedAI } = useHostedAI();
  // SaaS is ready immediately; consent is recorded on the first explicit send,
  // after the inline disclosure, rather than through a setup wizard.
  const hostedAvailable = Boolean(hostedAI?.enabled);
  const hostedModelId = hostedAI?.model;
  const hostedModel = useMemo<AIModelIdentifier | undefined>(
    () =>
      hostedAvailable && hostedModelId
        ? { id: hostedModelId, provider: AIProvider.Hosted }
        : undefined,
    [hostedAvailable, hostedModelId],
  );
  const defaultChatModel =
    hostedAvailable && hostedModel && !openRouterApiKey && !ollamaUrl
      ? hostedModel
      : storedDefaultChatModel;
  const genFeaturesModel =
    hostedAvailable && hostedModel && !openRouterApiKey && !ollamaUrl
      ? hostedModel
      : storedGenFeaturesModel;

  const enableIncludedAI = async () => {
    const status = await enableHostedAI();
    setHostedAI(status);
    setDefaultChatModel({ id: status.model, provider: AIProvider.Hosted });
    setGenFeaturesModel({ id: status.model, provider: AIProvider.Hosted });
  };

  const {
    openRouterAvailable,
    ollamaAvailable,
    isProviderAvailable,
    availableProviders,
  } = useProviderAvailability(openRouterApiKey, ollamaUrl, hostedAvailable);

  const mcpServers = mergeDefaultMCPServers(storedMcpServers);
  const setMcpServers = (servers: MCPServer[]) =>
    setStoredMcpServers(mergeDefaultMCPServers(servers));

  const context = {
    hostedAI,
    enableIncludedAI,
    openRouterZdr,
    setOpenRouterZdr,
    voiceEnabled,
    setVoiceEnabled,
    transcriptionModel,
    setTranscriptionModel,
    microphoneId,
    setMicrophoneId,
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
