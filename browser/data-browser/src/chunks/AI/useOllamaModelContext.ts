import { useEffect, useState } from 'react';
import { effectFetch } from '@helpers/effectFetch';
import { useLocalNetworkBlocked } from '@helpers/localNetworkAccess';
import { useAISettings } from '@components/AI/AISettingsContext';

type OllamaShowResponse = {
  parameters?: string;
  model_info?: Record<string, unknown>;
};

const contextLengthCache = new Map<string, number>();

function parseContextLengthFromShow(
  data: OllamaShowResponse,
): number | undefined {
  if (data.parameters) {
    const numCtxMatch = data.parameters.match(/num_ctx\s+(\d+)/);

    if (numCtxMatch) {
      return parseInt(numCtxMatch[1], 10);
    }
  }

  if (data.model_info) {
    for (const [key, value] of Object.entries(data.model_info)) {
      if (key.endsWith('.context_length') && typeof value === 'number') {
        return value;
      }
    }
  }

  return undefined;
}

export function useOllamaModelContextLength(
  modelId: string | undefined,
): number | undefined {
  const { ollamaUrl } = useAISettings();
  const blocked = useLocalNetworkBlocked(ollamaUrl);
  const cacheKey =
    ollamaUrl && modelId && !blocked ? `${ollamaUrl}:${modelId}` : undefined;
  const cachedLength = cacheKey ? contextLengthCache.get(cacheKey) : undefined;

  const [fetchedLength, setFetchedLength] = useState<
    { key: string; length: number | undefined } | undefined
  >();

  useEffect(() => {
    if (!cacheKey || contextLengthCache.has(cacheKey)) {
      return;
    }

    return effectFetch(`${ollamaUrl}/api/show`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model: modelId }),
    })(
      data => {
        const length = parseContextLengthFromShow(data as OllamaShowResponse);

        if (length !== undefined) {
          contextLengthCache.set(cacheKey, length);
        }

        setFetchedLength({ key: cacheKey, length });
      },
      () => {
        setFetchedLength({ key: cacheKey, length: undefined });
      },
    );
  }, [cacheKey, modelId, ollamaUrl]);

  if (!cacheKey) {
    return undefined;
  }

  if (cachedLength !== undefined) {
    return cachedLength;
  }

  if (fetchedLength?.key === cacheKey) {
    return fetchedLength.length;
  }

  return undefined;
}
