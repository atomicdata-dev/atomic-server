import { LocalOllamaDiscovery } from '@components/AI/LocalOllamaDiscovery';
import React, { Suspense, useEffect, useState } from 'react';
import styled from 'styled-components';
import { Column, Row } from '@components/Row';
import { useAISettings } from '@components/AI/AISettingsContext';
import { AIProvider } from '@components/AI/aiContstants';
import { OpenRouterLoginButton } from '@components/AI/OpenRouterLoginButton';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { OutlinedSection } from '@components/OutlinedSection';
import { useIsOllamaUrlValid } from '@components/AI/useIsOllamaUrlValid';
import { ProviderStatus } from '@components/AI/ProviderStatus';
import { Button } from '@components/Button';
import { effectFetch } from '@helpers/effectFetch';
import { DEFAULT_CHAT_MODEL } from '@components/AI/AISettingsContext';
import type { AIModelIdentifier } from './types';
import { useLocalStorage } from '@hooks/useLocalStorage';
import { useAIAgentConfig } from './AgentConfig';

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

export const AISetupPanel: React.FC = () => {
  const {
    openRouterApiKey,
    setOpenRouterApiKey,
    ollamaUrl,
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

  const { checking: ollamaChecking } = useIsOllamaUrlValid(ollamaUrl);
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

    if (!ollamaAvailable || !ollamaUrl) {
      return;
    }

    return effectFetch(`${ollamaUrl}/api/tags`)(data => {
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
    ollamaUrl,
    openRouterAvailable,
    isProviderAvailable,
  ]);

  if (setupComplete) {
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
      <Overlay>
        <Panel>
          <Title>Choose a default model</Title>
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
            <label htmlFor='sync-gen-features'>
              Also use for chat titles and follow-up prompts
            </label>
          </CheckboxRow>
          <ActionsRow>
            <Button subtle onClick={handleBack}>
              Back
            </Button>
            <Button
              onClick={handleStartChatting}
              disabled={!isProviderAvailable(pendingModel.provider)}
            >
              Start chatting
            </Button>
          </ActionsRow>
        </Panel>
      </Overlay>
    );
  }

  return (
    <Overlay>
      <Panel>
        <Title>Connect a model to use Atomic Assistant</Title>
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
              />
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
        <Button onClick={handleContinue} disabled={!hasProvider}>
          Continue
        </Button>
      </Panel>
    </Overlay>
  );
};

const Overlay = styled.div`
  position: absolute;
  inset: 0;
  backdrop-filter: blur(4px);
  background-color: ${p =>
    p.theme.darkMode ? 'rgba(0, 0, 0, 0.8)' : 'rgba(255, 255, 255, 0.8)'};
  border-radius: ${p => p.theme.radius};
  z-index: 1000;
  display: grid;
  place-items: center;
  padding: 1rem;
  overflow-y: auto;
`;

const Panel = styled(Column)`
  max-width: 34rem;
  width: 100%;
  gap: 1rem;
  background-color: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 1.25rem;
  box-shadow: ${p => p.theme.boxShadowSoft};
`;

const ActionsRow = styled(Row)`
  justify-content: flex-end;
  gap: 0.5rem;
  flex-wrap: wrap;
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

const Title = styled.h3`
  margin: 0;
  font-size: 1rem;
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
