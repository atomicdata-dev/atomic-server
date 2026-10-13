import {
  core,
  isAgentSubject,
  unknownSubject,
  useCurrentAgent,
  useResource,
  useString,
} from '@tomic/react';
import { FaUser } from 'react-icons/fa6';
import { useSettings } from '../../helpers/AppSettings';
import { ResourceGlyph } from '../../components/ResourceGlyph';
import { useDriveMembers } from '../../chunks/TablePage/EditorCells/useResourceSearch';
import { useState } from 'react';
import { styled } from 'styled-components';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { ErrorLook } from '../../components/ErrorLook';
import {
  InputStyled,
  InputWrapper,
  LabelStyled,
} from '../../components/forms/InputStyles';
import { useOpenConversation } from '../../helpers/conversations/useConversations';

/**
 * Starts a conversation with someone by their Atomic ID. The other way in is
 * the "Message" item on any avatar.
 */
export function NewMessageDialogBody({ onDone }: { onDone: () => void }) {
  const [agent, setAgent] = useState('');
  const [error, setError] = useState<Error | undefined>();
  const { openConversation, busy } = useOpenConversation();
  const trimmed = agent.trim();
  const valid = isAgentSubject(trimmed);
  const { drive } = useSettings();
  const [me] = useCurrentAgent();
  // Typing a name or part of an ID narrows the people in this drive; a full
  // pasted ID needs no match.
  const people = useDriveMembers(drive, core.classes.agent, agent).filter(
    subject => subject !== me?.subject && subject !== trimmed,
  );

  const start = async (e?: React.FormEvent) => {
    e?.preventDefault();

    if (!valid) return;

    setError(undefined);

    try {
      await openConversation([trimmed]);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  };

  return (
    <>
      <Dialog.Title>
        <h1>New message</h1>
      </Dialog.Title>
      <Dialog.Content>
        <Form id='new-message-form' onSubmit={start}>
          <LabelStyled htmlFor='new-message-agent'>Who</LabelStyled>
          <InputWrapper $invalid={trimmed !== '' && !valid}>
            <InputStyled
              id='new-message-agent'
              autoFocus
              placeholder='Name or did:ad:agent:…'
              value={agent}
              onChange={e => setAgent(e.target.value)}
              disabled={busy}
            />
          </InputWrapper>
          {people.length > 0 && (
            <People aria-label='People in this drive'>
              {people.slice(0, 8).map(subject => (
                <li key={subject}>
                  <PersonRow
                    subject={subject}
                    onPick={() => setAgent(subject)}
                  />
                </li>
              ))}
            </People>
          )}
          <Hint>
            Search people in this drive by name, or paste their Atomic ID. They
            find it under their account. Only the two of you can read what you
            send.
          </Hint>
          {error && <ErrorLook>{error.message}</ErrorLook>}
        </Form>
      </Dialog.Content>
      <Dialog.Actions>
        <Button subtle onClick={onDone}>
          Cancel
        </Button>
        <Button type='submit' form='new-message-form' disabled={!valid || busy}>
          {busy ? 'Starting…' : 'Start conversation'}
        </Button>
      </Dialog.Actions>
    </>
  );
}

function PersonRow({
  subject,
  onPick,
}: {
  subject: string;
  onPick: () => void;
}) {
  const resource = useResource(subject ?? unknownSubject);
  const [name] = useString(resource, core.properties.name);

  return (
    <PersonButton
      type='button'
      onClick={onPick}
      data-testid='new-message-person'
    >
      <ResourceGlyph resource={resource} fallbackIcon={FaUser} />
      <span>{name ?? subject}</span>
    </PersonButton>
  );
}

const People = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 12rem;
  overflow-y: auto;
`;

const PersonButton = styled.button`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.4rem 0.5rem;
  border: 0;
  border-radius: ${p => p.theme.radius};
  background: none;
  color: ${p => p.theme.colors.text};
  font: inherit;
  text-align: start;
  cursor: pointer;

  &:hover,
  &:focus-visible {
    background: ${p => p.theme.colors.bg1};
  }
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
`;

const Hint = styled.p`
  margin: 0;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;
