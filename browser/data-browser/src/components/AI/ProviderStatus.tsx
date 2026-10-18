import * as React from 'react';
import styled, { useTheme } from 'styled-components';
import { Row } from '@components/Row';
import { FaCheck, FaTriangleExclamation } from 'react-icons/fa6';

export interface ProviderStatusProps {
  connected: boolean;
  configured: boolean;
  checking?: boolean;
  /** Waiting for the user to allow local network access. */
  blocked?: boolean;
}

export const ProviderStatus: React.FC<ProviderStatusProps> = ({
  connected,
  configured,
  checking,
  blocked,
}) => {
  const theme = useTheme();

  if (!configured) {
    return <Subtle>Not configured</Subtle>;
  }

  if (connected) {
    return (
      <Row center gap='1ch'>
        <FaCheck title='Connected' color={theme.colors.main} />
        <Subtle>Connected</Subtle>
      </Row>
    );
  }

  if (blocked) {
    return (
      <Row center gap='1ch'>
        <FaTriangleExclamation
          title='Waiting for permission'
          color={theme.colors.warning}
        />
        <Subtle>Waiting for permission</Subtle>
      </Row>
    );
  }

  if (checking) {
    return (
      <Row center gap='1ch'>
        <FaTriangleExclamation
          title='Checking server…'
          color={theme.colors.warning}
        />
        <Subtle>Checking server…</Subtle>
      </Row>
    );
  }

  return (
    <Row center gap='1ch'>
      <FaTriangleExclamation
        title='Not responding'
        color={theme.colors.warning}
      />
      <Subtle>Not responding</Subtle>
    </Row>
  );
};

export const Subtle = styled.div`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  margin: 0;
`;
