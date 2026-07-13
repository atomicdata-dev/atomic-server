import { forms, signRequest, useStore, type Store } from '@tomic/react';
import { useCallback, useEffect, useState, type JSX } from 'react';
import { FaArrowsRotate } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Button } from '@components/Button';
import { Row } from '@components/Row';
import { AnswerList } from './AnswerList';
import { ChoiceBars } from './ChoiceBars';
import { Histogram } from './Histogram';
import {
  isCheckboxSummary,
  isChoiceSummary,
  isNumberSummary,
  parseFormSummary,
  type FieldSummary,
  type FormSummary,
} from './types';

interface SummaryTabProps {
  formSubject: string;
}

/**
 * Fetches the form's JSON-AD straight from the server (the class extender
 * only runs on HTTP GETs) and reads `form-submission-summary` out of the raw
 * response, deliberately bypassing the store: the OPFS-first store rebuilds
 * propvals from the Loro doc on every hydration, so an ephemeral,
 * server-computed propval gets pinned to its first-fetched value there (and
 * "healed" into the local Loro doc, which it must never enter). Extenders
 * don't run on live commits either, hence the Refresh button instead of
 * realtime updates.
 */
async function fetchSummary(
  store: Store,
  formSubject: string,
): Promise<FormSummary | undefined> {
  // Same URL + signing scheme as `Client.fetchResourceHTTP`'s DID path.
  const url = `${store.getServerUrl()}/did?subject=${encodeURIComponent(formSubject)}`;
  let headers: Record<string, string> = { Accept: 'application/ad+json' };
  const agent = store.getAgent();

  if (agent) {
    headers = await signRequest(url, agent, headers);
  }

  const response = await fetch(url, { headers, cache: 'no-store' });

  if (!response.ok) {
    throw new Error(`summary fetch failed with status ${response.status}`);
  }

  const jsonAd = (await response.json()) as Record<string, unknown>;

  return parseFormSummary(jsonAd[forms.properties.formSubmissionSummary]);
}

export function SummaryTab({ formSubject }: SummaryTabProps): JSX.Element {
  const store = useStore();
  const [summary, setSummary] = useState<FormSummary | undefined>();
  const [fetching, setFetching] = useState(true);
  const [fetchError, setFetchError] = useState<Error | undefined>();

  const refresh = useCallback(async () => {
    setFetching(true);
    setFetchError(undefined);

    const result = await fetchSummary(store, formSubject).catch((e: Error) => {
      setFetchError(e);

      return undefined;
    });

    if (result) {
      setSummary(result);
    }

    setFetching(false);
  }, [store, formSubject]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <Wrapper>
      <Row justify='space-between' center>
        {summary ? (
          <ResponseCount>
            {summary.responses === 1
              ? '1 response'
              : `${summary.responses} responses`}
          </ResponseCount>
        ) : (
          <span />
        )}
        <Button subtle onClick={refresh} disabled={fetching}>
          <FaArrowsRotate />
          Refresh
        </Button>
      </Row>
      {renderBody(summary, fetching, fetchError)}
    </Wrapper>
  );
}

function renderBody(
  summary: FormSummary | undefined,
  fetching: boolean,
  fetchError: Error | undefined,
): JSX.Element {
  if (!summary) {
    if (fetching) {
      return <StatusMessage>Loading summary...</StatusMessage>;
    }

    if (fetchError) {
      return (
        <StatusMessage>
          Could not load the summary from the server. Check your connection and
          try refreshing.
        </StatusMessage>
      );
    }

    return (
      <StatusMessage>
        No summary available. The server may need to be updated.
      </StatusMessage>
    );
  }

  if (summary.responses === 0) {
    return <StatusMessage>No responses yet</StatusMessage>;
  }

  return (
    <Cards>
      {summary.fields.map(field => (
        <FieldCard key={field.mapsTo} field={field} />
      ))}
    </Cards>
  );
}

function FieldCard({ field }: { field: FieldSummary }): JSX.Element {
  return (
    <Card>
      <QuestionLabel>{field.label}</QuestionLabel>
      <AnsweredMeta>
        <span>{field.answered} answered</span>
        {field.skipped > 0 && <span> · {field.skipped} skipped</span>}
      </AnsweredMeta>
      <FieldBody field={field} />
    </Card>
  );
}

function FieldBody({ field }: { field: FieldSummary }): JSX.Element {
  if (isChoiceSummary(field)) {
    return <ChoiceBars counts={field.counts} answered={field.answered} />;
  }

  if (isCheckboxSummary(field)) {
    return (
      <ChoiceBars
        counts={[
          ['Yes', field.checked],
          ['No', field.unchecked],
        ]}
        answered={field.answered}
      />
    );
  }

  if (isNumberSummary(field)) {
    if (!field.bins || field.bins.length === 0) {
      return <StatusMessage>No numeric answers yet</StatusMessage>;
    }

    return (
      <Histogram
        bins={field.bins}
        min={field.min}
        max={field.max}
        mean={field.mean}
      />
    );
  }

  if ('answers' in field && field.answers.length > 0) {
    return (
      <AnswerList
        answers={field.answers}
        fieldType={field.type}
        answered={field.answered}
      />
    );
  }

  return <StatusMessage>No answers yet</StatusMessage>;
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(3)};
  max-width: 45rem;
  margin-inline: auto;
  width: 100%;
`;

const ResponseCount = styled.h2`
  font-size: 1.1rem;
  margin: 0;
  color: ${p => p.theme.colors.text};
`;

const Cards = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(3)};
`;

const Card = styled.section`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.size(3)};
  background: ${p => p.theme.colors.bg};
`;

const QuestionLabel = styled.h3`
  font-size: 1rem;
  margin: 0;
  color: ${p => p.theme.colors.text};
`;

const AnsweredMeta = styled.div`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  margin-bottom: ${p => p.theme.size(2)};
  font-variant-numeric: tabular-nums;
`;

const StatusMessage = styled.div`
  color: ${p => p.theme.colors.textLight};
  padding: ${p => p.theme.size(2)} 0;
`;
