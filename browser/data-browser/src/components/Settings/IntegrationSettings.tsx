import { styled } from 'styled-components';
import { useState } from 'react';
import { Column, Row } from '@components/Row';
import {
  InputStyled,
  InputWrapper,
  ErrMessage,
} from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { SettingsSection } from './SettingsSection';
import {
  defaultIntegrationProxy,
  setIntegrationProxy,
  useIntegrationProxy,
} from '@helpers/integrationProxy';

export function IntegrationSettings() {
  const proxy = useIntegrationProxy();

  return (
    <SettingsSection
      label='Integration'
      childSearchKeywords='proxy server url localthought'
    >
      <ProxyForm key={proxy} proxy={proxy} />
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
          Connect accounts and import records using a LocalThought
          integration-proxy server. This setting is saved in this browser.
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
        </InputWrapper>
        {error && (
          <ErrMessage id='integration-proxy-error' role='alert'>
            {error}
          </ErrMessage>
        )}
        <Row gap='0.5rem'>
          <Button type='submit' disabled={value === proxy}>
            Save
          </Button>
          <Button
            type='button'
            subtle
            onClick={() => {
              setIntegrationProxy('');
              setValue(defaultIntegrationProxy);
              setError('');
            }}
          >
            Reset to default
          </Button>
        </Row>
      </Column>
    </form>
  );
}

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
