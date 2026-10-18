import { effectFetch } from '@helpers/effectFetch';
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
};

export const useIsOllamaUrlValid = (
  url: string | undefined,
): OllamaUrlStatus => {
  const deferredUrl = useDeferredValue(url);
  const [checkResult, setCheckResult] = useState<OllamaCheckResult | null>(
    null,
  );

  useEffect(() => {
    if (!deferredUrl) {
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
  }, [deferredUrl]);

  if (!url) {
    return { valid: false, checking: false };
  }

  // A settled result exists only when the completed check matches the URL we're
  // currently showing (`deferredUrl`). Until then we're genuinely checking —
  // NOT "not responding" (the bug: a failed check used to read as "checking
  // forever" because callers derived `checking` from `!valid`).
  const settled = checkResult !== null && checkResult.url === deferredUrl;

  return {
    valid: settled && checkResult.valid,
    checking: !settled,
  };
};
