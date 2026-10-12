import { styled } from 'styled-components';
import { useState } from 'react';
import { Checkbox, CheckboxLabel } from '@components/forms/Checkbox';
import { useIntegrationVisibility } from '@hooks/useIntegrationVisibility';
import { Column, Row } from '@components/Row';
import {
  InputStyled,
  InputWrapper,
  ErrMessage,
} from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { FaRotateLeft } from 'react-icons/fa6';
import { SettingsSection } from './SettingsSection';
import {
  defaultIntegrationProxy,
  setIntegrationProxy,
  useIntegrationProxy,
} from '@helpers/integrationProxy';
import {
  defaultPluginCatalogUrl,
  setPluginCatalogUrl,
  usePluginCatalogUrl,
} from '@helpers/pluginCatalogUrl';

export function IntegrationSettings() {
  const proxy = useIntegrationProxy();
  const catalogUrl = usePluginCatalogUrl();
  const {
    showExperimentalPlugins,
    experimentalToggleVisible,
    ready,
    pending,
    error,
    setVisibility,
  } = useIntegrationVisibility();

  return (
    <SettingsSection
      label='Integration'
      childSearchKeywords='proxy catalog server url experimental plugins'
    >
      <Column
        gap='1rem'
        data-testid='integration-visibility'
        data-ready={ready}
        aria-busy={pending}
      >
        {experimentalToggleVisible && (
          <>
            <CheckboxLabel>
              <Checkbox
                checked={showExperimentalPlugins}
                onChange={value =>
                  setVisibility('show-experimental-plugins', value)
                }
              />
              <span>Show experimental plugins</span>
            </CheckboxLabel>
            <Description>
              These preferences are saved in your private Atomic drive. Existing
              connections remain available.
            </Description>
          </>
        )}
        {error && <ErrMessage role='alert'>{error}</ErrMessage>}
        <ProxyForm key={proxy} proxy={proxy} />
        <CatalogUrlForm key={catalogUrl} catalogUrl={catalogUrl} />
      </Column>
    </SettingsSection>
  );
}

function ProxyForm({ proxy }: { proxy: string }) {
  const [value, setValue] = useState(proxy);
  const [error, setError] = useState('');

  return (
    <form
      onSubmit={event => {
        event.preventDefault();

        try {
          setIntegrationProxy(value);
          setError('');
        } catch {
          setError(
            'Enter an HTTPS server URL or a localhost HTTP URL, without a path.',
          );
        }
      }}
    >
      <Column gap='0.5rem'>
        <SectionTitle>Integration proxy</SectionTitle>
        <Description>
          The integration-proxy server that API plugins call through. This
          setting is saved in this browser.
        </Description>
        <Row center gap='1ch'>
          <label htmlFor='integration-proxy-url'>Integration proxy URL</label>
        </Row>
        <InputWrapper>
          <InputStyled
            id='integration-proxy-url'
            type='url'
            value={value}
            placeholder={defaultIntegrationProxy}
            onChange={event => setValue(event.target.value)}
            aria-invalid={!!error}
            aria-describedby={error ? 'integration-proxy-error' : undefined}
          />
          {value !== defaultIntegrationProxy && (
            <ResetButton
              onClick={() => {
                setIntegrationProxy('');
                setValue(defaultIntegrationProxy);
                setError('');
              }}
            />
          )}
        </InputWrapper>
        {error && (
          <ErrMessage id='integration-proxy-error' role='alert'>
            {error}
          </ErrMessage>
        )}
        <Row>
          <Button type='submit' disabled={value === proxy}>
            Save
          </Button>
        </Row>
      </Column>
    </form>
  );
}

function CatalogUrlForm({ catalogUrl }: { catalogUrl: string }) {
  const [value, setValue] = useState(catalogUrl);
  const [error, setError] = useState('');

  return (
    <form
      onSubmit={event => {
        event.preventDefault();

        try {
          setPluginCatalogUrl(value);
          setError('');
        } catch {
          setError(
            'Enter an HTTPS URL or a localhost HTTP URL pointing at a catalog.json file.',
          );
        }
      }}
    >
      <Column gap='0.5rem'>
        <SectionTitle>Plugin catalog URL</SectionTitle>
        <Description>
          Discover integrations from this catalog.json. This setting is saved in
          this browser.
        </Description>
        <Row center gap='1ch'>
          <label htmlFor='plugin-catalog-url'>Plugin catalog URL</label>
        </Row>
        <InputWrapper>
          <InputStyled
            id='plugin-catalog-url'
            type='url'
            value={value}
            placeholder={defaultPluginCatalogUrl}
            onChange={event => setValue(event.target.value)}
            aria-invalid={!!error}
            aria-describedby={error ? 'plugin-catalog-url-error' : undefined}
          />
          {value !== defaultPluginCatalogUrl && (
            <ResetButton
              onClick={() => {
                setPluginCatalogUrl('');
                setValue(defaultPluginCatalogUrl);
                setError('');
              }}
            />
          )}
        </InputWrapper>
        {error && (
          <ErrMessage id='plugin-catalog-url-error' role='alert'>
            {error}
          </ErrMessage>
        )}
        <Row>
          <Button type='submit' disabled={value === catalogUrl}>
            Save
          </Button>
        </Row>
      </Column>
    </form>
  );
}

/** Small end-aligned button inside a field that restores its default value. */
function ResetButton({ onClick }: { onClick: () => void }) {
  return (
    <InlineReset ghost type='button' title='Reset to default' onClick={onClick}>
      <FaRotateLeft aria-hidden />
      Reset
    </InlineReset>
  );
}

const InlineReset = styled(Button)`
  flex: none;
  margin-inline: 0.25rem;
  font-size: 0.8rem;
  padding: 0.2rem 0.4rem;
`;

const SectionTitle = styled.h3`
  margin: 0;
  font-size: 0.95rem;
  font-weight: 650;
  color: ${p => p.theme.colors.text};
`;

const Description = styled.p`
  font-size: 0.8rem;
  margin: 0;
  color: ${p => p.theme.colors.textLight};
`;
