import React, { useState } from 'react';
import {
  useResource,
  useStore,
  signRequest,
  HeadersObject,
} from '@tomic/react';

import AllProps from '../components/AllProps';
import { ContainerNarrow } from '../components/Containers';
import { AtomicLink } from '../components/AtomicLink';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { PropValRow, PropertyLabel } from '../components/PropVal';
import { Button } from '../components/Button';
import { ErrMessage } from '../components/forms/InputStyles';
import { useSettings } from '../helpers/AppSettings';
import { CodeBlock } from '../components/CodeBlock';
import { Title } from '../components/Title';
import { Row } from '../components/Row';
import { ErrorLook } from '../components/ErrorLook';
import { Childrenlist as ChildrenCard } from '../components/ChildrenList';

/** Renders the data of some Resource */
function Data(): JSX.Element {
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const [textResponse, setTextResponse] = useState<string | undefined>(
    undefined,
  );
  const [textResponseLoading, setTextResponseLoading] = useState(false);
  const [err, setErr] = useState<Error | undefined>(undefined);
  const { agent } = useSettings();
  const store = useStore();

  if (!subject) {
    <ContainerNarrow>No subject passed</ContainerNarrow>;
  }

  if (resource.loading) {
    return <ContainerNarrow>Loading {subject}...</ContainerNarrow>;
  }

  if (resource.error) {
    return (
      <ContainerNarrow>
        <ErrorLook>{resource.error.message}</ErrorLook>
      </ContainerNarrow>
    );
  }

  async function fetchAs(contentType: string) {
    let headers: HeadersObject = {};
    headers['Accept'] = contentType;

    if (agent) {
      headers = await signRequest(subject!, agent, headers);
    }

    setTextResponseLoading(true);

    try {
      const resp = await window.fetch(subject!, { headers: headers });
      const body = await resp.text();
      setTextResponseLoading(false);
      setTextResponse(body);
      setErr(undefined);
    } catch (e) {
      setTextResponseLoading(false);
      setErr(e);
    }
  }

  return (
    <ContainerNarrow about={subject}>
      <Title resource={resource} prefix='Data for' link />
      <PropValRow columns>
        <PropertyLabel title='The URL of the resource'>subject:</PropertyLabel>
        <AtomicLink subject={subject}>{subject}</AtomicLink>
      </PropValRow>
      <AllProps resource={resource} editable columns />
      <ChildrenCard resource={resource} />
      {resource.getCommitBuilder().hasUnsavedChanges() ? (
        <>
          <h2>⚠️ contains uncommitted changes</h2>
          <p>This means that (some) of your local changes are not yet saved.</p>
          {resource.commitError && (
            <ErrMessage>{resource.commitError.message}</ErrMessage>
          )}
          <Button onClick={() => resource.save(store)}>save</Button>
        </>
      ) : null}
      <Row wrapItems>
        <Button
          subtle
          onClick={() => fetchAs('application/ad+json')}
          data-test='fetch-json-ad'
        >
          JSON-AD
        </Button>
        <Button
          subtle
          onClick={() => fetchAs('application/json')}
          data-test='fetch-json'
        >
          JSON
        </Button>
        <Button
          subtle
          onClick={() => fetchAs('application/ld+json')}
          data-test='fetch-json-ld'
        >
          JSON-LD
        </Button>
        <Button
          subtle
          onClick={() => fetchAs('text/turtle')}
          data-test='fetch-turtle'
        >
          Turtle / N-triples / N3
        </Button>
      </Row>
      {err && <ErrMessage>{err.message}</ErrMessage>}
      {!err && textResponse && (
        <CodeBlock content={textResponse} loading={textResponseLoading} />
      )}
    </ContainerNarrow>
  );
}

export default Data;
