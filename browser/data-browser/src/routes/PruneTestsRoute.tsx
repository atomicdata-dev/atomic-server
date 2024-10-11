import { Resource, Server, useStore } from '@tomic/react';
import { useState } from 'react';
import { Button } from '../components/Button';
import { ContainerFull } from '../components/Containers';
import { Column } from '../components/Row';

export function PruneTestsRoute(): JSX.Element {
  const store = useStore();
  const [result, setResult] = useState<Resource<Server.EndpointResponse>>();
  const [isWaiting, setIsWaiting] = useState(false);

  const postPruneTest = async () => {
    setIsWaiting(true);
    const url = new URL('/prunetests', store.getServerUrl());
    const res = await store.postToServer(url.toString());
    setIsWaiting(false);
    setResult(res);
  };

  return (
    <main>
      <ContainerFull>
        <h1>Prune Test Data</h1>
        <p>
          Pruning test data will delete all drives on the server that have
          &rsquo;testdrive&rsquo; in their name.
        </p>
        <Column>
          <Button onClick={postPruneTest} disabled={isWaiting} alert>
            Prune
          </Button>
          {isWaiting && <p>Pruning, this might take a while...</p>}
          <p data-testid='prune-result'>
            {result && `✅ ${result.props.responseMessage}`}
          </p>
        </Column>
      </ContainerFull>
    </main>
  );
}
