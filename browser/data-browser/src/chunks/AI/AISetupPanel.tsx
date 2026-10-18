import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '@components/Dialog';
import { LocalOllamaDiscovery } from '@components/AI/LocalOllamaDiscovery';
import React, { Suspense, useEffect, useState } from 'react';
import styled from 'styled-components';
import { Column } from '@components/Row';
import { useAISettings } from '@components/AI/AISettingsContext';
import { AIProvider } from '@components/AI/aiContstants';
import { OpenRouterLoginButton } from '@components/AI/OpenRouterLoginButton';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { OutlinedSection } from '@components/OutlinedSection';
import { useIsOllamaUrlValid } from '@components/AI/useIsOllamaUrlValid';
import { ProviderStatus } from '@components/AI/ProviderStatus';
import { Button } from '@components/Button';
import { LocalNetworkNotice } from '@components/AI/LocalNetworkNotice';
import { effectFetch } from '@helpers/effectFetch';
import { DEFAULT_CHAT_MODEL } from '@components/AI/AISettingsContext';
import type { AIModelIdentifier } from './types';
import { useLocalStorage } from '@hooks/useLocalStorage';
import { useAIAgentConfig } from './AgentConfig';
import { hasManagedApi } from '@helpers/managed/api';

const ModelSelect = React.lazy(
  () => import('@chunks/AI/ModelSelect/ModelSelect'),
);

type SetupStep = 'providers' | 'model';

type OllamaTag = { name: string; model: string };

const pickSuggestedOllamaModel = (models: OllamaTag[]): string | undefined => {
  if (models.length === 0) {
    return undefined;
  }

  const preferred = models.find(
    m =>
      /llama|qwen|mistral|gemma/i.test(m.model) &&
      !/embed|vision/i.test(m.model),
  );

  return (preferred ?? models[0]).model;
};

const getInitialPendingModel = (
  defaultChatModel: AIModelIdentifier,
  openRouterAvailable: boolean,
  isProviderAvailable: (provider: AIProvider) => boolean,
): AIModelIdentifier => {
  if (isProviderAvailable(defaultChatModel.provider)) {
    return defaultChatModel;
  }

  if (openRouterAvailable) {
    return DEFAULT_CHAT_MODEL;
  }

  return defaultChatModel;
};

const getInitialStep = (hasProvider: boolean): SetupStep => {
  if (sessionStorage.getItem('atomic.ai.openSetup') === 'true' && hasProvider) {
    return 'model';
  }

  return 'providers';
};

/** A new request resets dismissal and any half-finished setup step. */
export function AISetupPanel({
  requestId = 0,
  onDismiss,
}: {
  requestId?: number;
  onDismiss?: () => void;
}) {
  // Never interrupt a SaaS chat with onboarding, including while its account
  // status is loading. Advanced provider setup remains explicitly reachable.
  if (requestId === 0 && hasManagedApi()) return null;

  return <AISetupPanelSession key={requestId} onDismiss={onDismiss} />;
}

const AISetupPanelSession: React.FC<{ onDismiss?: () => void }> = ({
  onDismiss,
}) => {
  const [dismissed, setDismissed] = useState(false);
  const [hostedError, setHostedError] = useState<string>();
  const [enabling, setEnabling] = useState(false);
  const {
    hostedAI,
    enableIncludedAI,
    openRouterApiKey,
    setOpenRouterApiKey,
    ollamaUrl,
    ollamaEndpoint,
    ollamaBlocked,
    setOllamaUrl,
    defaultChatModel,
    setDefaultChatModel,
    isProviderAvailable,
    availableProviders,
    openRouterAvailable,
    ollamaAvailable,
    setGenFeaturesModel,
  } = useAISettings();
  const { agents, saveAgents } = useAIAgentConfig();

  const [setupComplete, setSetupComplete] = useLocalStorage(
    'atomic.ai.setupComplete',
    false,
  );

  const { checking: ollamaChecking } = useIsOllamaUrlValid(ollamaEndpoint);
  const hasProvider = availableProviders.length > 0;
  const [step, setStep] = useState<SetupStep>(() =>
    getInitialStep(hasProvider),
  );
  const [pendingModel, setPendingModel] = useState<AIModelIdentifier>(() =>
    getInitialPendingModel(
      defaultChatModel,
      openRouterAvailable,
      isProviderAvailable,
    ),
  );
  const [syncGenFeatures, setSyncGenFeatures] = useState(false);

  useEffect(() => {
    if (step !== 'model' || openRouterAvailable) {
      return;
    }

    if (!ollamaAvailable || !ollamaEndpoint) {
      return;
    }

    return effectFetch(`${ollamaEndpoint}/api/tags`)(data => {
      const models = (data.models ?? []) as OllamaTag[];
      const suggestedId = pickSuggestedOllamaModel(models);

      if (!suggestedId) {
        return;
      }

      setPendingModel(prev => {
        if (isProviderAvailable(prev.provider)) {
          return prev;
        }

        return { id: suggestedId, provider: AIProvider.Ollama };
      });
    });
  }, [
    step,
    ollamaAvailable,
    ollamaEndpoint,
    openRouterAvailable,
    isProviderAvailable,
  ]);

  if (setupComplete || dismissed) {
    return null;
  }

  const handleContinue = () => {
    setPendingModel(
      getInitialPendingModel(
        defaultChatModel,
        openRouterAvailable,
        isProviderAvailable,
      ),
    );
    setStep('model');
    sessionStorage.removeItem('atomic.ai.openSetup');
  };

  const handleBack = () => {
    setStep('providers');
  };

  const handleStartChatting = () => {
    setDefaultChatModel(pendingModel);
    saveAgents(agents);

    if (syncGenFeatures) {
      setGenFeaturesModel(pendingModel);
    }

    setSetupComplete(true);
    sessionStorage.removeItem('atomic.ai.openSetup');
  };

  if (step === 'model') {
    return (
      <SetupDialog
        title='Choose a default model'
        actions={
          <>
            <Button subtle onClick={handleBack}>
              Back
            </Button>
            <Button
              onClick={handleStartChatting}
              disabled={!isProviderAvailable(pendingModel.provider)}
            >
              Start chatting
            </Button>
          </>
        }
        onDismiss={() => {
          setDismissed(true);
          onDismiss?.();
        }}
      >
        <Panel>
          <Subtle>
            This pre-selects a model for built-in agents and new custom agents.
            You can change each agent&apos;s model individually later.
          </Subtle>
          <Suspense>
            <ModelSelect
              defaultModel={pendingModel}
              onSelect={setPendingModel}
              enforceToolSupport
            />
          </Suspense>
          <CheckboxRow>
            <input
              type='checkbox'
              id='sync-gen-features'
              checked={syncGenFeatures}
              onChange={e => setSyncGenFeatures(e.target.checked)}
            />
            <label htmlFor='sync-gen-features'>Also use for chat titles</label>
          </CheckboxRow>
        </Panel>
      </SetupDialog>
    );
  }

  return (
    <SetupDialog
      title='Connect a model to use AI chat'
      actions={
        <Button onClick={handleContinue} disabled={!hasProvider}>
          Continue
        </Button>
      }
      onDismiss={() => {
        setDismissed(true);
        onDismiss?.();
      }}
    >
      <Panel>
        {hostedAI?.enabled && (
          <Column>
            <strong>AI included with your account</strong>
            <span>{`${Math.floor(hostedAI.remaining_micros / 1000)} of ${Math.floor(hostedAI.allowance_micros / 1000)} credits remaining this month, shared across your drives.`}</span>
            <Subtle>
              Prompts and selected document content pass through Atomic and our
              AI provider. Atomic does not save prompt or response content in
              the AI service. Your own provider and local models remain
              available below.
            </Subtle>
            <Button
              disabled={enabling || hostedAI.remaining_micros === 0}
              onClick={async () => {
                setEnabling(true);
                setHostedError(undefined);

                try {
                  await enableIncludedAI();
                  setSetupComplete(true);
                } catch (error) {
                  setHostedError(
                    error instanceof Error
                      ? error.message
                      : 'Could not enable included AI.',
                  );
                }

                setEnabling(false);
              }}
            >
              Use included AI
            </Button>
            {hostedError && <span role='alert'>{hostedError}</span>}
          </Column>
        )}
        <Subtle>
          Use OpenRouter (cloud models) or Ollama (local models). At least one
          provider must be connected before you can continue.
        </Subtle>
        <ProvidersGrid>
          <OutlinedSection title='OpenRouter'>
            <ProviderSection>
              <ProviderStatus
                connected={openRouterAvailable}
                configured={Boolean(openRouterApiKey)}
              />
              <CredentialsRow>
                {!openRouterApiKey && (
                  <OpenRouterLoginGroup>
                    <OpenRouterLoginButton />
                    <OrText>or</OrText>
                  </OpenRouterLoginGroup>
                )}
                <ApiKeyField>
                  <InputStyled
                    type='password'
                    value={openRouterApiKey || ''}
                    onChange={e =>
                      setOpenRouterApiKey(e.target.value || undefined)
                    }
                    placeholder='Paste API key'
                    aria-label='OpenRouter API key'
                  />
                </ApiKeyField>
              </CredentialsRow>
            </ProviderSection>
          </OutlinedSection>
          <OutlinedSection title='Ollama'>
            <ProviderSection>
              {!ollamaUrl && <LocalOllamaDiscovery />}
              <ProviderStatus
                connected={ollamaAvailable}
                configured={Boolean(ollamaUrl)}
                checking={ollamaChecking}
                blocked={ollamaBlocked}
              />
              <LocalNetworkNotice url={ollamaUrl} />
              <FullWidthField>
                <InputStyled
                  type='url'
                  value={ollamaUrl || ''}
                  onChange={e => setOllamaUrl(e.target.value || undefined)}
                  placeholder='http://localhost:11434'
                  aria-label='Ollama URL'
                />
              </FullWidthField>
            </ProviderSection>
          </OutlinedSection>
        </ProvidersGrid>
      </Panel>
    </SetupDialog>
  );
};

/** Use the app-wide portal, backdrop, focus management and dismissal rules. */
function SetupDialog({
  children,
  title,
  actions,
  onDismiss,
}: React.PropsWithChildren<{
  title: string;
  actions: React.ReactNode;
  onDismiss: () => void;
}>) {
  const [dialogProps, showDialog] = useDialog({ onCancel: onDismiss });
  useEffect(() => {
    showDialog();
  }, [showDialog]);

  return (
    <Dialog {...dialogProps} width='36rem'>
      <DialogTitle>
        <h1>{title}</h1>
      </DialogTitle>
      <DialogContent>{children}</DialogContent>
      <DialogActions>{actions}</DialogActions>
    </Dialog>
  );
}

const Panel = styled(Column)`
  width: 100%;
  min-width: 0;
  gap: 1rem;
`;

const ProvidersGrid = styled(Column)`
  gap: 1rem;
`;

/** Full-width block inside OutlinedSection (its body is a horizontal flex row). */
const ProviderSection = styled(Column)`
  gap: 0.5rem;
  flex: 1 1 100%;
  width: 100%;
  min-width: 0;
`;

const CredentialsRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
`;

const OpenRouterLoginGroup = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  flex: 0 0 auto;
`;

const OrText = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const ApiKeyField = styled(InputWrapper)`
  flex: 1 1 12rem;
  min-width: min(100%, 12rem);

  input {
    width: 100%;
    min-width: 0;
  }
`;

const FullWidthField = styled(InputWrapper)`
  width: 100%;

  input {
    width: 100%;
    min-width: 0;
  }
`;

const Subtle = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
`;

const CheckboxRow = styled.label`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
`;
