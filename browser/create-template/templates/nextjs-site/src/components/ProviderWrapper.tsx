'use client';

import { StoreContext } from '@tomic/react';
import { CurrentSubjectProvider } from '@/app/context/CurrentSubjectContext';
import { store } from '@/app/store';

const ProviderWrapper = ({
  children,
}: {
  children: Readonly<React.ReactNode>;
}) => {
  return (
    <StoreContext.Provider value={store}>
      <CurrentSubjectProvider>{children}</CurrentSubjectProvider>
    </StoreContext.Provider>
  );
};

export default ProviderWrapper;
