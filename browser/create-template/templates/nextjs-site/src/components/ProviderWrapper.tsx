"use client";

import { Store } from "@tomic/lib";
import { StoreContext } from "@tomic/react";
import { env } from "@/env";
import { initOntologies } from "@/ontologies";

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
    <StoreContext.Provider value={store}>{children}</StoreContext.Provider>
  );
};

export default ProviderWrapper;
