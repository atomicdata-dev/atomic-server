import { effectFetch } from '@helpers/effectFetch';
import { useLocalNetworkBlocked } from '@helpers/localNetworkAccess';
import { useDeferredValue, useEffect, useState } from 'react';

const MODEL_API_ROUTE = '/api/tags';

type OllamaCheckResult = {
  url: string;
  valid: boolean;
};

export type OllamaUrlStatus = {
  /** A reachability check completed for the current URL and it responded. */
  valid: boolean;
  /** A URL is configured but no completed check has landed for it yet. */
  checking: boolean;
  /** Not probed yet: the browser would ask for local network access first. */
  blocked: boolean;
};

export const useIsOllamaUrlValid = (
  url: string | undefined,
): OllamaUrlStatus => {
  const deferredUrl = useDeferredValue(url);
  const blocked = useLocalNetworkBlocked(deferredUrl);
  const [checkResult, setCheckResult] = useState<OllamaCheckResult | null>(
    null,
  );

  useEffect(() => {
    if (!deferredUrl || blocked) {
      return;
    }

    const modelAPIURL = `${deferredUrl}${MODEL_API_ROUTE}`;

    return effectFetch(modelAPIURL, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })(
      () => {
        setCheckResult({ url: deferredUrl, valid: true });
      },
      () => {
        setCheckResult({ url: deferredUrl, valid: false });
      },
    );
  }, [deferredUrl, blocked]);

  if (!url) {
    return { valid: false, checking: false, blocked: false };
  }

  if (blocked) {
    return { valid: false, checking: false, blocked: true };
  }

  // A settled result exists only when the completed check matches the URL we're
  // currently showing (`deferredUrl`). Until then we're genuinely checking —
  // NOT "not responding" (the bug: a failed check used to read as "checking
  // forever" because callers derived `checking` from `!valid`).
  const settled = checkResult !== null && checkResult.url === deferredUrl;

  return {
    valid: settled && checkResult.valid,
    checking: !settled,
    blocked: false,
  };
};
