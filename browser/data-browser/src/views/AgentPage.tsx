import {
  commits,
  properties,
  core,
  dataBrowser,
  Datatype,
  useCollection,
  useCollectionPage,
  useResource,
  useResources,
  useString,
  useStore,
  useTitle,
  type Resource,
} from '@tomic/react';
import { useState, type JSX } from 'react';
import { FaPaperPlane } from 'react-icons/fa6';
import { AgentAvatar } from '../components/Presence/AgentAvatar';
import { Button } from '../components/Button';
import { ContainerNarrow } from '../components/Containers';
import { Details } from '../components/Details';
import AllProps from '../components/AllProps';
import { ConversationLink } from '../components/SideBar/MessagesPanel';
import ValueComp from '../components/ValueComp';
import { ValueForm } from '../components/forms/ValueForm';
import { ValueFormAddButton } from '../components/forms/ValueForm/ValueFormAddButton';
import { Column, Row } from '../components/Row';
import { useSettings } from '../helpers/AppSettings';
import { createAgentNote, agentNoteQuery } from '../helpers/agentNotes';
import { hasMember } from '../helpers/conversations/conversations';
import {
  useConversations,
  useOpenConversation,
} from '../helpers/conversations/useConversations';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { ActivityFeed, SectionTitle } from './Drive/DriveHome';
import { defaultHiddenProps, EditResourceButton } from './ResourcePageDefault';
import type { ResourcePageProps } from './ResourcePage';

const MAX_CONVERSATIONS = 3;
const MAX_CREATED = 30;

/** Properties the profile shows in a nicer way than a table row. */
const profileHiddenProps = [
  ...defaultHiddenProps,
  dataBrowser.properties.icon,
  core.properties.personalDrive,
];

/**
 * Who an agent is, for yourself or someone else: profile, your private notes on
 * them, your recent messages with them and what they made in places you can
 * see.
 */
function AgentPage({ resource }: ResourcePageProps): JSX.Element {
  const { agent } = useSettings();
  const [title] = useTitle(resource);
  const [description] = useString(resource, core.properties.description);
  const isMe = agent?.subject === resource.subject;

  return (
    <ContainerNarrow>
      <Column gap='2rem'>
        <Column>
          <Row align='center' gap='1rem'>
            <AgentAvatar agentSubject={resource.subject} size='5rem' />
            <h1>{title}</h1>
            {isMe && <EditResourceButton resource={resource} />}
          </Row>
          {isMe ? (
            <ValueForm
              resource={resource}
              propertyURL={core.properties.description}
            />
          ) : (
            description && (
              <ValueComp value={description} datatype={Datatype.MARKDOWN} />
            )
          )}
          <Details title='Technical details'>
            <AllProps resource={resource} except={profileHiddenProps} />
          </Details>
        </Column>
        {agent && !isMe && <Conversations agent={resource.subject} />}
        {agent && !isMe && <Notes agent={resource} />}
        <Created agent={resource.subject} />
      </Column>
    </ContainerNarrow>
  );
}

/** Your latest conversations that this agent is part of, and a way to start one. */
function Conversations({ agent }: { agent: string }): JSX.Element {
  const store = useStore();
  const { openConversation, busy } = useOpenConversation();
  const listed = useConversations();
  const resources = useResources(listed);
  const shared = listed
    .filter(subject => {
      const conversation = resources.get(subject);

      return (
        conversation && !conversation.error && hasMember(conversation, agent)
      );
    })
    .reverse()
    .slice(0, MAX_CONVERSATIONS);

  const send = () =>
    openConversation([agent]).catch(error => store.notifyError(error));

  return (
    <section aria-label='Messages'>
      <SectionTitle>Messages</SectionTitle>
      <Column gap='0.5rem'>
        {shared.map(subject => (
          <ConversationLink key={subject} subject={subject} />
        ))}
        <Row>
          <Button onClick={send} loading={busy ? 'Opening...' : undefined}>
            <FaPaperPlane /> Send message
          </Button>
        </Row>
      </Column>
    </section>
  );
}

/** What you wrote about this agent, in your own private drive. */
function Notes({ agent }: { agent: Resource }): JSX.Element | null {
  const { privateDrive } = usePrivateDrive();

  if (!privateDrive) {
    return null;
  }

  return <NoteEditor agent={agent} privateDrive={privateDrive} />;
}

function NoteEditor({
  agent,
  privateDrive,
}: {
  agent: Resource;
  privateDrive: string;
}): JSX.Element {
  const store = useStore();
  const [name] = useTitle(agent);
  const { collection, invalidateCollection } = useCollection(
    agentNoteQuery(privateDrive, agent.subject),
    { pageSize: 1 },
  );
  const [existing] = useCollectionPage(collection, 0);
  const [created, setCreated] = useState<string>();
  const [adding, setAdding] = useState(false);
  const note = useResource(existing ?? created);

  const add = async () => {
    setAdding(true);

    try {
      setCreated(
        await createAgentNote(store, privateDrive, agent.subject, name),
      );
      await invalidateCollection();
    } catch (error) {
      store.notifyError(error as Error);
    }
  };

  return (
    <section aria-label='Your notes'>
      <SectionTitle>Your notes</SectionTitle>
      <Column gap='0.5rem'>
        <small>Only you can see these. {name} cannot.</small>
        {existing || created ? (
          !note.loading &&
          (adding ? (
            <ValueForm
              resource={note}
              propertyURL={core.properties.description}
              datatype={Datatype.MARKDOWN}
              defaultEditState
            />
          ) : (
            <ValueFormAddButton
              resource={note}
              propertyURL={core.properties.description}
              datatype={Datatype.MARKDOWN}
              buttonLabel='Add a note'
            />
          ))
        ) : (
          <Row>
            <Button subtle onClick={add}>
              Add a note
            </Button>
          </Row>
        )}
      </Column>
    </section>
  );
}

/** The newest resources this agent created, in drives you can read. */
function Created({ agent }: { agent: string }): JSX.Element {
  const { collection } = useCollection(
    {
      property: properties.createdBy,
      value: agent,
      sort_by: commits.properties.createdAt,
      sort_desc: true,
    },
    { pageSize: MAX_CREATED, preferServer: true },
  );
  const subjects = useCollectionPage(collection, 0);

  return <ActivityFeed subjects={subjects} title='Created' />;
}

export default AgentPage;
