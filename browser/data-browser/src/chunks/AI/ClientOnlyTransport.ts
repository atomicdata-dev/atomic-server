// @wc-ignore-file
import {
  generateText,
  stepCountIs,
  streamText,
  type ChatTransport,
  type ToolSet,
  type UIMessageChunk,
} from 'ai';
import { modelMessagesWithToolRecovery } from './toolHistory';
import { usageMetadata } from './usageMetadata';
import { AIProvider } from '@components/AI/aiContstants';
import {
  type AIAgent,
  type AIModelIdentifier,
  type AtomicUIMessage,
} from './types';
import { createOpenRouter } from '@openrouter/ai-sdk-provider';
import { useRef } from 'react';
import { useStore } from '@tomic/react';
import { createOllama } from 'ollama-ai-provider-v2';
import { addFieldsIf } from '@helpers/addIf';
import { stringifyTree, useGetDriveStructure } from './useGetDriveStructure';
import { useSettings } from '@helpers/AppSettings';
import { shortenSubject } from '@tomic/react';
import { getClassesOnDrive } from '@tomic/react';
import { createHostedModel } from './hostedModel';
import { hostedVoiceModel } from './hostedVoiceModel';

export type Modalities = 'text' | 'image';

export interface ClientOnlyTransportOptions {
  openRouterAPIKey?: string;
  openRouterZdr?: boolean;
  ollamaURL?: string;
  selectedAgent: AIAgent;
  model: AIModelIdentifier;
  tools: ToolSet;
  addContextToMessages: (
    messages: AtomicUIMessage[],
  ) => Promise<AtomicUIMessage[]>;
  resolveOutputModalities: (modelId: string) => Modalities[];
  resolveParameterSupport: (modelId: string, parameter: string) => boolean;
  /** Appended after template substitution (e.g. skills instructions). */
  additionalSystemPrompt?: string;
}

/**
 * A transport layer for the useChat hook that handles text streaming internally instead of relying on a server.
 */
export class ClientOnlyTransport implements ChatTransport<AtomicUIMessage> {
  public constructor(
    private options: ClientOnlyTransportOptions,
    private idGenerator: () => string,
    private _prepareSystemPrompt: (systemPrompt: string) => Promise<string>,
  ) {}

  public set prepareSystemPrompt(
    func: (systemPrompt: string) => Promise<string>,
  ) {
    this._prepareSystemPrompt = func;
  }

  public setOptions(options: ClientOnlyTransportOptions) {
    this.options = options;
  }

  /** Use the configured personal provider when present, otherwise SaaS credits. */
  public async runLiveTask(
    messages: AtomicUIMessage[],
    abortSignal: AbortSignal,
  ) {
    const prepared = await this.options.addContextToMessages(
      trimToLastSummary(messages),
    );
    const result = await generateText({
      model: this.options.openRouterAPIKey
        ? this.getModel(this.options.model)
        : hostedVoiceModel(),
      messages: await modelMessagesWithToolRecovery(prepared),
      system: `${await this._prepareSystemPrompt(this.options.selectedAgent.systemPrompt)}\nYou are handling a delegated request from a live voice conversation. Use the latest user request and its corrections. Perform only requested actions. Return a brief factual result suitable for speech, including whether actions actually succeeded.`,
      tools: this.options.tools,
      abortSignal,
      maxRetries: 0,
      stopWhen: stepCountIs(8),
    });

    return (
      result.text ||
      'The task finished without a spoken result. Check the chat before repeating any action.'
    );
  }

  public async sendMessages({
    abortSignal,
    ...options
  }: Parameters<ChatTransport<AtomicUIMessage>['sendMessages']>[0]) {
    const messagesFromLastSummary = trimToLastSummary(options.messages);

    const transformedMessages = await this.options.addContextToMessages(
      messagesFromLastSummary,
    );

    const agent = this.options.selectedAgent;

    const result = streamText({
      messages: await modelMessagesWithToolRecovery(transformedMessages),
      model: this.getModel(this.options.model),
      system: await this._prepareSystemPrompt(agent.systemPrompt),
      tools: this.options.tools,
      abortSignal,
      stopWhen: stepCountIs(
        this.options.model.provider === AIProvider.Hosted ? 8 : 1000,
      ),
      maxRetries: this.options.model.provider === AIProvider.Hosted ? 0 : 2,
      ...this.getParameters(agent, this.options.model),
    });

    const originalStream = result.toUIMessageStream({
      originalMessages: transformedMessages,
      generateMessageId: this.idGenerator,
      messageMetadata: ({ part }) => usageMetadata(part),
      onError: error => {
        if (error instanceof Error) return error.message;
        if (error && typeof error === 'object' && 'message' in error)
          return String(error.message);

        return 'The model request failed.';
      },
      sendSources: true,
      sendReasoning: true,
    });

    return originalStream;
  }

  public async reconnectToStream(): Promise<ReadableStream<UIMessageChunk> | null> {
    return null;
  }

  private getModel(model: AIModelIdentifier) {
    if (model.provider === AIProvider.Hosted)
      return createHostedModel(model.id);

    if (
      model.provider === AIProvider.OpenRouter &&
      this.options.openRouterAPIKey
    ) {
      const modalities = this.options.resolveOutputModalities(model.id);

      const openRouter = createOpenRouter({
        apiKey: this.options.openRouterAPIKey,
        compatibility: 'strict',
        extraBody: {
          ...(this.options.openRouterZdr ? { provider: { zdr: true } } : {}),
          modalities,
          plugins: [{ id: 'context-compression' }],
        },
      });

      return openRouter(model.id);
    }

    if (model.provider === AIProvider.Ollama && this.options.ollamaURL) {
      const ollama = createOllama({
        baseURL: `${this.options.ollamaURL}/api`,
      });

      return ollama(model.id);
    }

    throw new Error('Invalid model provider');
  }

  private getParameters(agent: AIAgent, model: AIModelIdentifier) {
    if (model.provider === AIProvider.Hosted)
      return { temperature: agent.temperature };

    if (model.provider === AIProvider.Ollama) {
      // We can't check if Ollama supports specific parameters, so we just return all of them.
      return {
        temperature: agent.temperature,
      };
    }

    if (model.provider === AIProvider.OpenRouter) {
      return {
        ...addFieldsIf(
          this.options.resolveParameterSupport(model.id, 'temperature'),
          {
            temperature: agent.temperature,
          },
        ),
        ...addFieldsIf(
          this.options.resolveParameterSupport(model.id, 'reasoning'),
          {
            reasoning: {
              effort: 'low',
              summary: 'auto',
            },
          },
        ),
      };
    }

    throw new Error('Invalid model provider');
  }
}

/** Returns messages starting from the last summary message (inclusive), or all messages if none. */
function trimToLastSummary(messages: AtomicUIMessage[]): AtomicUIMessage[] {
  const lastSummaryIndex = messages.findLastIndex(
    m => m.metadata?.isSummary === true,
  );

  return lastSummaryIndex >= 0 ? messages.slice(lastSummaryIndex) : messages;
}

export const useClientOnlyTransport = (options: ClientOnlyTransportOptions) => {
  const store = useStore();
  const generateId = () => store.newLocalId();
  const { drive } = useSettings();
  const getDriveTree = useGetDriveStructure();

  /**
   * Prepares the system prompt by replacing the placeholders with the actual values.
   * If you add any new placeholder, be sure to update the helper text in the {@link AgentConfig} component.
   */
  const prepareSystemPrompt = async (systemPrompt: string) => {
    let modifiedSystemPrompt = systemPrompt;

    if (systemPrompt.includes('{{drive}}')) {
      modifiedSystemPrompt = modifiedSystemPrompt.replaceAll(
        '{{drive}}',
        drive,
      );
    }

    if (systemPrompt.includes('{{drive-structure}}')) {
      const driveTree = await getDriveTree();
      modifiedSystemPrompt = modifiedSystemPrompt.replaceAll(
        '{{drive-structure}}',
        stringifyTree(driveTree),
      );
    }

    if (systemPrompt.includes('{{custom-classes}}')) {
      const classSubjects = await getClassesOnDrive(drive, store);
      const customClasses = await Promise.all(
        classSubjects.map(async cls => {
          const resource = await store.getResource(cls);

          return `${resource.title}: ${shortenSubject(cls)}`;
        }),
      );

      modifiedSystemPrompt = modifiedSystemPrompt.replaceAll(
        '{{custom-classes}}',
        customClasses.length === 0
          ? 'No custom classes found on the current drive.'
          : customClasses.join('\n'),
      );
    }

    if (systemPrompt.includes('{{timestamp}}')) {
      modifiedSystemPrompt = modifiedSystemPrompt.replaceAll(
        '{{timestamp}}',
        new Date().toISOString(),
      );
    }

    if (options.additionalSystemPrompt) {
      modifiedSystemPrompt += `\n\n${options.additionalSystemPrompt}`;
    }

    return modifiedSystemPrompt;
  };

  // The useChat aggressively memoizes the transport so we need to make sure we always modify the same instance.
  const transportRef = useRef(
    new ClientOnlyTransport(options, generateId, prepareSystemPrompt),
  );
  const prevOptionsRef = useRef(options);

  // The ClientOnlyTransport instance needs to be stable between renders but we still need to update it's options when they change. I don't know how to do this without refs so we just have to accept these warnings.
  if (options !== prevOptionsRef.current) {
    transportRef.current.setOptions(options);
    prevOptionsRef.current = options;
  }

  transportRef.current.prepareSystemPrompt = prepareSystemPrompt;

  return transportRef.current;
};
