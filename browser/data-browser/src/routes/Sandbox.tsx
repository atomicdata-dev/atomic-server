import React from 'react';
import { ContainerFull } from '../components/Containers';

export function Sandbox(): JSX.Element {
  return (
    <main>
      <ContainerFull>
        <h1>Sandbox</h1>
        <p>
          Welcome to the sandbox. This is a place to test components in
          isolation.
        </p>
      </ContainerFull>
    </main>
  );
}
