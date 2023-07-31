import * as React from 'react';
import { ContainerNarrow } from '../components/Containers';
import { CodeBlock } from '../components/CodeBlock';
import { createAuthentication, useServerURL } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { Main } from '../components/Main';

/** Lets user create bearer tokens */
export const TokenRoute: React.FunctionComponent = () => {
  const [token, setToken] = React.useState('');
  const { agent } = useSettings();
  const [server] = useServerURL();
  React.useEffect(() => {
    async function getToken() {
      if (agent) {
        const json = await createAuthentication(server, agent);
        setToken(btoa(JSON.stringify(json)));
      }
    }

    getToken();
  }, [agent]);

  return (
    <Main>
      <ContainerNarrow>
        <CodeBlock content={token} />
      </ContainerNarrow>
    </Main>
  );
};
