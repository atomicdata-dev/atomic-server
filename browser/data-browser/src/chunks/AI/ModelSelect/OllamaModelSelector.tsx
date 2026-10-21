import styled from 'styled-components';
import { ComboBox } from '@components/ComboBox';
import { Column } from '@components/Row';
import { useEffect, useState } from 'react';
import { AIProvider } from '@components/AI/aiContstants';
import { type AIModelIdentifier } from '../types';
import { ModelInfoLayout } from './ModelInfoLayout';
import { ErrorLook } from '@components/ErrorLook';
import { TAB_PANEL_HAS_ERROR_CLASS } from '@components/Tabs';
import { LoaderBlock } from '@components/Loader';
import { effectFetch } from '@helpers/effectFetch';
import { useAISettings } from '@components/AI/AISettingsContext';

type OllamaModel = {
  name: string;
  model: string;
  size: number;
  details: {
    format: string;
    parent_model: string;
    family: string;
    parameter_size: string;
    quantization_level: string;
  };
};

interface OllamaModelSelectorProps {
  onSelect: (model: AIModelIdentifier) => void;
  selectedModel: AIModelIdentifier;
}

let modelCache: OllamaModel[] = [];

export const OllamaModelSelector: React.FC<OllamaModelSelectorProps> = ({
  onSelect,
  selectedModel,
}) => {
  const { ollamaEndpoint, isProviderAvailable } = useAISettings();

  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(modelCache.length === 0);
  const [models, setModels] = useState<OllamaModel[]>(modelCache);

  const currentModel = models.find(m => m.model === selectedModel.id);

  const options = models.map(model => ({
    label: model.name,
    searchLabel: model.model.toLowerCase(),
    value: model.model,
  }));

  useEffect(() => {
    if (!ollamaEndpoint) return;

    return effectFetch(`${ollamaEndpoint}/api/tags`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })(
      data => {
        setError(undefined);
        setModels(data.models);
        setLoading(false);
        modelCache = data.models;
      },
      e => {
        console.error(e);
        setError(
          'Unable to connect to Ollama server. Check if the server is running and you configured the correct url in the settings',
        );
      },
    );
  }, [ollamaEndpoint]);

  if (error) {
    return <ErrorLook className={TAB_PANEL_HAS_ERROR_CLASS}>{error}</ErrorLook>;
  }

  if (loading) {
    return <LoaderBlock>Loading...</LoaderBlock>;
  }

  if (!isProviderAvailable(AIProvider.Ollama)) {
    return (
      <ModelInfoLayout.Empty>
        Check your Ollama URL and that the server is running
      </ModelInfoLayout.Empty>
    );
  }

  return (
    <Column>
      <Column gap='0.2rem'>
        <ModelAmount>{models.length} Models</ModelAmount>
        <ComboBox
          selectedItem={selectedModel.id}
          options={options}
          onSelect={value => {
            const newVal = {
              id: value ?? selectedModel.id,
              provider: AIProvider.Ollama,
            };
            onSelect(newVal);
          }}
        />
      </Column>
      {currentModel ? (
        <ModelInfoLayout
          About={
            <ModelDetailsTable>
              <span>Format:</span>
              <span> {currentModel.details.format}</span>
              <span>Parent Model:</span>
              <span> {currentModel.details.parent_model || '-'}</span>
              <span>Family:</span>
              <span> {currentModel.details.family}</span>
              <span>Parameter Size:</span>
              <span> {currentModel.details.parameter_size}</span>
            </ModelDetailsTable>
          }
        />
      ) : (
        <ModelInfoLayout.Empty>Select a model</ModelInfoLayout.Empty>
      )}
    </Column>
  );
};

const ModelAmount = styled.div`
  font-size: 0.8em;
  color: ${p => p.theme.colors.textLight};
`;

const ModelDetailsTable = styled.div`
  display: grid;
  grid-template-columns: auto 1fr;
  gap: ${p => p.theme.size()};
  row-gap: 0.2rem;
`;
