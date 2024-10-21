'use client';

import { Store } from '@tomic/lib';
import { StoreContext } from '@tomic/react';
import { env } from '@/env';
import { initOntologies } from '@/ontologies';
import { CurrentSubjectProvider } from '@/app/context/CurrentSubjectContext';

const ProviderWrapper = ({
  children,
}: {
  children: Readonly<React.ReactNode>;
}) => {
  const store = new Store({
    serverUrl: env.NEXT_PUBLIC_ATOMIC_SERVER_URL,
  });

  initOntologies();

  return (
    <StoreContext.Provider value={store}>
      <CurrentSubjectProvider>{children}</CurrentSubjectProvider>
    </StoreContext.Provider>
  );
};

export default ProviderWrapper;
