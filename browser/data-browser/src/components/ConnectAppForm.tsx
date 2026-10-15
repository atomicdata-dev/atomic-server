import type { PropsWithChildren } from 'react';
import { styled } from 'styled-components';
import { Button } from './Button';
import { Margin } from './Card';
import { ConnectDrivePicker } from './ConnectDrivePicker';
import { ContainerNarrow } from './Containers';
import { ErrorLook } from './ErrorLook';
import { Main } from './Main';
import { Column, Row } from './Row';
import { RadioInput } from './forms/RadioInput';
import { useAccountDriveCatalog } from '../hooks/useAccountDriveCatalog';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { useSavedDrives } from '../hooks/useSavedDrives';

/** The drives a person can hand to an app, and the home drive its grant is remembered in. */
export function useConnectableDrives() {
  const { privateDrive, loading: homeLoading } = usePrivateDrive();
  const [savedDrives] = useSavedDrives();
  const catalog = useAccountDriveCatalog(
    privateDrive ? [privateDrive, ...savedDrives] : savedDrives,
  );

  return { privateDrive, homeLoading, catalog };
}

/** Narrow page shell shared by the connect-an-app routes. */
export function ConnectPage({ children }: PropsWithChildren) {
  return (
    <Main>
      <ContainerNarrow>{children}</ContainerNarrow>
    </Main>
  );
}

/** Adds or removes one subject from a selection. */
export const toggleSubject = (
  selected: string[],
  subject: string,
  on: boolean,
): string[] =>
  on
    ? [...selected, subject]
    : selected.filter(existing => existing !== subject);

interface ConnectAppFormProps {
  /** Subjects of the drives that can be picked. */
  subjects: string[];
  selected: string[];
  onToggle: (subject: string, on: boolean) => void;
  canEdit: boolean;
  onCanEditChange: (canEdit: boolean) => void;
  error?: string;
  busy: boolean;
  /** Also blocks Allow while the home drive loads. */
  disabled: boolean;
  onAllow: () => void;
  onCancel: () => void;
  /** Prefix of the `data-test` ids on the write option and the Allow button. */
  testId: string;
}

/**
 * The part of a connect-an-app page where the person decides: which drives,
 * read or edit, Allow or Cancel. What to do on Allow, and every check that
 * decides whether to show this at all, stays with the route.
 */
export function ConnectAppForm({
  subjects,
  selected,
  onToggle,
  canEdit,
  onCanEditChange,
  error,
  busy,
  disabled,
  onAllow,
  onCancel,
  testId,
}: ConnectAppFormProps) {
  return (
    <Column>
      <Heading>What it can reach</Heading>
      <ConnectDrivePicker
        subjects={subjects}
        selected={selected}
        onToggle={onToggle}
      />

      <Heading>What it can do</Heading>
      <Column gap='0.75rem'>
        <RadioInput
          name='access'
          checked={!canEdit}
          onChange={() => onCanEditChange(false)}
        >
          Read only
        </RadioInput>
        <RadioInput
          name='access'
          checked={canEdit}
          onChange={() => onCanEditChange(true)}
          data-test={`${testId}-write`}
        >
          Read and edit
        </RadioInput>
      </Column>

      <Margin />
      {error && <ErrorLook>{error}</ErrorLook>}
      <Row>
        <Button
          onClick={onAllow}
          disabled={busy || disabled || selected.length === 0}
          loading={busy ? 'Connecting' : undefined}
          data-test={`${testId}-allow`}
        >
          Allow
        </Button>
        <Button subtle onClick={onCancel}>
          Cancel
        </Button>
      </Row>
    </Column>
  );
}

const Heading = styled.h2`
  margin: 0;
  font-size: 1.1rem;
`;
