import { LocalOllamaDiscovery } from '@components/AI/LocalOllamaDiscovery';
import * as React from 'react';
import { Column, Row } from '@components/Row';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import styled, { useTheme } from 'styled-components';
import { Suspense, useEffect, useState } from 'react';
import { OpenRouterLoginButton } from './OpenRouterLoginButton';
import { effectFetch } from '@helpers/effectFetch';
import { CheckboxDescriptor } from '@components/forms/CheckboxDescriptor';
import { transition } from '@helpers/transition';
import { useAISettings } from './AISettingsContext';
import { useIsOllamaUrlValid } from './useIsOllamaUrlValid';
import { Details } from '@components/Details';
import {
  SettingsContent,
  SettingsSectionWrapper,
  SettingsLabel,
  useSettingsSearch,
  SettingsSearchProvider,
  queryMatches,
} from '@components/Settings';
import { WarningBlock } from '@components/WarningBlock';
import { FaCheck, FaTriangleExclamation } from 'react-icons/fa6';

const ModelSelect = React.lazy(
  () => import('@chunks/AI/ModelSelect/ModelSelect'),
);

const intl = new Intl.NumberFormat('default', {
  style: 'currency',
  currency: 'USD',
  currencyDisplay: 'narrowSymbol',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

interface CreditUsage {
  total: number;
  used: number;
}

const CREDITS_ENDPOINT = 'https://openrouter.ai/api/v1/credits';

// Keywords for the AI section's own content (enable toggle, token usage)
const AI_OWN_KEYWORDS = 'ai token usage';
// Keywords from child sections — makes this section visible, but children still filter
const AI_CHILD_KEYWORDS =
  'openrouter ollama mcp server generative model chat provider api key local';

const AISettings: React.FC = () => {
  const theme = useTheme();
  const { query: searchQuery } = useSettingsSearch();
  const {
    enableAI,
    setEnableAI,
    openRouterApiKey,
    setOpenRouterApiKey,
    showTokenUsage,
    setShowTokenUsage,
    ollamaUrl,
    setOllamaUrl,
    showFollowUpPrompts,
    setShowFollowUpPrompts,
    isProviderAvailable,
    shouldGenerateTitles,
    setShouldGenerateTitles,
    genFeaturesModel,
    setGenFeaturesModel,
  } = useAISettings();

  const [creditUsage, setCreditUsage] = useState<CreditUsage | undefined>();

  const handleSetOpenRouterKey = (key: string | undefined) => {
    if (!key) {
      setCreditUsage(undefined);
    }

    setOpenRouterApiKey(key);
  };

  const genFeaturesUnavailable = !isProviderAvailable(
    genFeaturesModel.provider,
  );

  const { valid: isOllamaUrlValid } = useIsOllamaUrlValid(ollamaUrl);

  useEffect(() => {
    if (!openRouterApiKey) {
      return;
    }

    return effectFetch(CREDITS_ENDPOINT, {
      headers: {
        Authorization: `Bearer ${openRouterApiKey}`,
      },
    })(data => {
      setCreditUsage({
        total: data.data.total_credits,
        used: data.data.total_usage,
      });
    });
  }, [openRouterApiKey]);

  const { parentMatched } = useSettingsSearch();
  const isSearching = searchQuery.length > 0;

  const ownMatch =
    isSearching && queryMatches(searchQuery, `ai ${AI_OWN_KEYWORDS}`);
  const childMatch =
    isSearching &&
    !ownMatch &&
    queryMatches(searchQuery, `ai ${AI_CHILD_KEYWORDS}`);

  // Only propagate parentMatched when this section's own content matched,
  // not when a child keyword matched (let children filter themselves).
  const childContext = React.useMemo(
    () => ({
      query: searchQuery,
      parentMatched: parentMatched || ownMatch,
    }),
    [searchQuery, parentMatched, ownMatch],
  );

  if (isSearching && !ownMatch && !childMatch && !parentMatched) {
    return null;
  }

  return (
    <SettingsSectionWrapper>
      <Details
        noIndent
        title={<SettingsLabel>AI</SettingsLabel>}
        open={isSearching}
        initialState={isSearching}
      >
        <SettingsContent>
          <SettingsSearchProvider value={childContext}>
            <Column gap='0.75rem'>
              <CheckboxLabel>
                <Checkbox checked={enableAI} onChange={setEnableAI} /> Enable AI
                Features
              </CheckboxLabel>
              <ConditionalSettings enabled={enableAI} inert={!enableAI}>
                <CheckboxLabel>
                  <Checkbox
                    checked={showTokenUsage}
                    onChange={setShowTokenUsage}
                  />
                  Show token usage in chats
                </CheckboxLabel>

                <SubGroup>
                  <SubSection>
                    <SubSectionTitle>OpenRouter</SubSectionTitle>
                    <Column gap='0.5rem'>
                      <ConditionalSettings
                        fullWidth
                        gap='0.5rem'
                        enabled={true}
                      >
                        <label htmlFor='openrouter-api-key'>
                          OpenRouter API Key
                        </label>
                        <Row center>
                          {!openRouterApiKey && (
                            <>
                              <OpenRouterLoginButton />
                              or
                            </>
                          )}
                          <InputWrapper>
                            <InputStyled
                              id='openrouter-api-key'
                              type='password'
                              value={openRouterApiKey || ''}
                              onChange={e =>
                                handleSetOpenRouterKey(
                                  e.target.value || undefined,
                                )
                              }
                              placeholder='Enter your OpenRouter API key'
                            />
                          </InputWrapper>
                        </Row>
                        {creditUsage && (
                          <Subtle>
                            Credits used: {intl.format(creditUsage.used)} /{' '}
                            {intl.format(creditUsage.total)}
                          </Subtle>
                        )}
                        {!openRouterApiKey && (
                          <Subtle>
                            OpenRouter provides a unified API that gives you
                            access to hundreds of AI models from all major
                            vendors, while automatically handling fallbacks and
                            selecting the most cost-effective options.
                          </Subtle>
                        )}
                      </ConditionalSettings>
                    </Column>
                  </SubSection>

                  <SubSection>
                    <SubSectionTitle>Ollama</SubSectionTitle>
                    <Column gap='0.5rem'>
                      {!ollamaUrl && <LocalOllamaDiscovery />}
                      <Subtle>
                        Host your own AI models locally using{' '}
                        <a
                          href='https://ollama.com/'
                          target='_blank'
                          rel='noreferrer'
                        >
                          Ollama
                        </a>
                      </Subtle>
                      <ConditionalSettings
                        fullWidth
                        gap='0.5rem'
                        enabled={true}
                      >
                        <Row center gap='1ch'>
                          {ollamaUrl &&
                            (isOllamaUrlValid ? (
                              <FaCheck
                                title='Server found'
                                color={theme.colors.main}
                              />
                            ) : (
                              <FaTriangleExclamation
                                title='Server not responding'
                                color={theme.colors.warning}
                              />
                            ))}
                          <label htmlFor='ollama-url'>Ollama API Url</label>
                        </Row>
                        <InputWrapper>
                          <InputStyled
                            id='ollama-url'
                            value={ollamaUrl || ''}
                            onChange={e =>
                              setOllamaUrl(e.target.value || undefined)
                            }
                            type='url'
                            placeholder='http://localhost:11434'
                          />
                        </InputWrapper>
                      </ConditionalSettings>
                    </Column>
                  </SubSection>

                  <SubSection>
                    <SubSectionTitle>Generative features</SubSectionTitle>
                    {genFeaturesUnavailable && (
                      <WarningBlock>
                        <WarningBlock.Title>
                          The generative features model uses a provider that is
                          not available.
                        </WarningBlock.Title>
                      </WarningBlock>
                    )}
                    <Column gap='0.5rem'>
                      <CheckboxLabel>
                        <Checkbox
                          checked={shouldGenerateTitles}
                          onChange={setShouldGenerateTitles}
                        />
                        Generate AI Chat titles
                      </CheckboxLabel>
                      <CheckboxDescriptor
                        label='Show follow up prompts in chats'
                        description='Uses a small model to generate a follow up prompt based on the last message in the chat.'
                      >
                        {id => (
                          <Checkbox
                            id={id}
                            checked={showFollowUpPrompts}
                            onChange={setShowFollowUpPrompts}
                          />
                        )}
                      </CheckboxDescriptor>
                      <Details title='Change what model is used for generative features'>
                        <Suspense>
                          <Subtle>(Tip) Choose a cheap and fast model</Subtle>
                          <ModelSelect
                            defaultModel={genFeaturesModel}
                            onSelect={setGenFeaturesModel}
                          />
                        </Suspense>
                      </Details>
                    </Column>
                  </SubSection>
                </SubGroup>
              </ConditionalSettings>
            </Column>
          </SettingsSearchProvider>
        </SettingsContent>
      </Details>
    </SettingsSectionWrapper>
  );
};

const ConditionalSettings = styled(Column)<{ enabled: boolean }>`
  opacity: ${p => (p.enabled ? 1 : 0.3)};
  pointer-events: ${p => (p.enabled ? 'auto' : 'none')};
  touch-action: ${p => (p.enabled ? 'auto' : 'none')};
  ${transition('opacity')}
`;

const SubGroup = styled.div`
  border-top: 1px solid ${p => p.theme.colors.bg2};
  margin-top: 0.25rem;
  padding-top: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;

  button[aria-label='collapse'],
  button[aria-label='expand'] {
    height: 1.5em;
    background: transparent !important;
    box-shadow: none !important;
  }
`;

const SubSection = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};

  &:last-child {
    border-bottom: 0;
    padding-bottom: 0;
  }
`;

const SubSectionTitle = styled.h3`
  margin: 0;
  font-size: 0.95rem;
  font-weight: 650;
  color: ${p => p.theme.colors.text};
`;

const Subtle = styled.p`
  font-size: 0.8rem;
  margin: 0;
  color: ${p => p.theme.colors.textLight};
`;

export default AISettings;
