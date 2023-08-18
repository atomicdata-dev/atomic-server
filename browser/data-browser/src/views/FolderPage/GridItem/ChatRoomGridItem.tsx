import {
  properties,
  useArray,
  useResource,
  useString,
  useSubject,
  useTitle,
} from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { GridItemDescription, InnerWrapper } from './components';
import { GridItemViewProps } from './GridItemViewProps';

export function ChatRoomGridItem({ resource }: GridItemViewProps): JSX.Element {
  const [messages] = useArray(resource, properties.chatRoom.messages);

  return (
    <ChatWrapper>
      {messages.length > 0 ? (
        <>
          <Message subject={messages[messages.length - 2]} />
          <Message subject={messages[messages.length - 1]} alignment='right' />
        </>
      ) : (
        <GridItemDescription>Empty Chat</GridItemDescription>
      )}
    </ChatWrapper>
  );
}

type Alignment = 'left' | 'right';

interface LastMessageProps {
  subject: string;
  alignment?: Alignment;
}

const Message = ({ subject, alignment }: LastMessageProps): JSX.Element => {
  const messageResource = useResource(subject);
  const [lastCommit] = useSubject(
    messageResource,
    properties.commit.lastCommit,
  );
  const lastCommitResource = useResource(lastCommit);
  const [signer] = useSubject(lastCommitResource, properties.commit.signer);
  const signerResource = useResource(signer);

  const [signerName] = useTitle(signerResource);
  const [text] = useString(messageResource, properties.description);

  return (
    <MessageWrapper alignment={alignment}>
      <CommitWrapper>{signerName}</CommitWrapper>
      <TextWrapper>{text}</TextWrapper>
    </MessageWrapper>
  );
};

interface MessageWrapperProps {
  alignment?: Alignment;
}

const TextWrapper = styled.div`
  background-color: ${p => p.theme.colors.bg};
  padding: 0.5rem;
  border-radius: 15px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: ${p => p.theme.colors.text};
`;

const MessageWrapper = styled.div<MessageWrapperProps>`
  padding-inline: ${p => p.theme.margin}rem;
  width: 100%;
  text-align: ${p => p.alignment ?? 'left'};

  ${TextWrapper} {
    border-bottom-left-radius: ${p => (p.alignment !== 'right' ? '0' : '15px')};
    border-bottom-right-radius: ${p =>
      p.alignment === 'right' ? '0' : '15px'};
  }
`;

const CommitWrapper = styled.div`
  color: ${p => p.theme.colors.textLight};
  padding-inline: 0.5rem;
  width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const ChatWrapper = styled(InnerWrapper)`
  display: flex;
  flex-direction: column;
  justify-content: space-evenly;
`;
