import { useEffect, useState } from 'react';
import { Button } from '../Button';
import { Column } from '../Row';
import { useAISettings } from './AISettingsContext';

const LOCAL_OLLAMA_URL = 'http://localhost:11434';

/** Only mount inside an open provider setup, never in the app-wide provider. */
export function LocalOllamaDiscovery() {
  const { setOllamaUrl } = useAISettings();
  const [status, setStatus] = useState<'checking' | 'found' | 'unavailable'>(
    'checking',
  );

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 3000);

    void fetch(`${LOCAL_OLLAMA_URL}/api/tags`, { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Ollama discovery failed');
        const data = await response.json();

        if (active) {
          setStatus(Array.isArray(data?.models) ? 'found' : 'unavailable');
        }
      })
      .catch(() => {
        if (active) setStatus('unavailable');
      })
      .finally(() => clearTimeout(timeout));

    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, []);

  return (
    <Column gap='0.5rem'>
      <span role='status'>
        {status === 'found'
          ? 'Local Ollama detected'
          : status === 'checking'
            ? 'Looking for local Ollama…'
            : 'Local Ollama could not be reached. Start Ollama and connect.'}
      </span>
      <Button subtle onClick={() => setOllamaUrl(LOCAL_OLLAMA_URL)}>
        {status === 'found' ? 'Use local Ollama' : 'Connect local Ollama'}
      </Button>
    </Column>
  );
}
