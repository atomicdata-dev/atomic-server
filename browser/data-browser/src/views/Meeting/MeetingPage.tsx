import { lazy, Suspense, useState } from 'react';
import { styled } from 'styled-components';
import {
  dataBrowser,
  useLoroDoc,
  useNumber,
  type DataBrowser,
} from '@tomic/react';
import type { ResourcePageProps } from '../ResourcePage';
import { EditableTitle } from '../../components/EditableTitle';
import { ResourceCoverImage } from '../../components/ResourceDecorations';
import { Button } from '../../components/Button';
import { Row, Column } from '../../components/Row';
import { useFollow } from '../../components/Presence/FollowContext';
import { useRightPanel } from '../../components/RightPanel/RightPanelContext';
import { getMeetingPhase } from './meetingLifecycle';

const CollaborativeEditor = lazy(
  () => import('../../chunks/RTE/CollaborativeEditor'),
);

export function MeetingPage({
  resource,
}: ResourcePageProps<DataBrowser.Meeting>): React.JSX.Element {
  const doc = useLoroDoc(resource);
  const [startedAt] = useNumber(
    resource,
    dataBrowser.properties.meetingStartedAt,
  );
  const [endedAt] = useNumber(resource, dataBrowser.properties.meetingEndedAt);
  const { activeMeeting, startMeeting, endMeeting } = useFollow();
  const { openMeetingPanel } = useRightPanel();
  const [changing, setChanging] = useState(false);
  const phase = getMeetingPhase(startedAt, endedAt);
  const leading = activeMeeting === resource.subject;

  async function handleStart() {
    setChanging(true);
    const subject = await startMeeting(undefined, resource.subject);
    openMeetingPanel(subject);
    setChanging(false);
  }

  async function handleEnd() {
    setChanging(true);
    await endMeeting();
    setChanging(false);
  }

  const focusEditor = () => {
    document.getElementById('meeting-editor')?.focus();
  };

  return (
    <>
      <ResourceCoverImage resource={resource} />
      <Page>
        <MeetingHeader>
          <Column gap='0.4rem'>
            <Phase>{phase}</Phase>
            <EditableTitle
              resource={resource}
              onCommit={focusEditor}
              withDecorations
            />
          </Column>
          <MeetingActions gap='0.5rem' center>
            <Button subtle onClick={() => openMeetingPanel(resource.subject)}>
              Open chat
            </Button>
            {phase === 'agenda' && (
              <Button onClick={handleStart} disabled={changing}>
                Start meeting
              </Button>
            )}
            {phase === 'notes' && leading && (
              <Button alert onClick={handleEnd} disabled={changing}>
                End meeting
              </Button>
            )}
          </MeetingActions>
        </MeetingHeader>

        {doc ? (
          <Suspense fallback={<div>Loading meeting notes…</div>}>
            <CollaborativeEditor
              id='meeting-editor'
              resource={resource}
              doc={doc}
              property={dataBrowser.properties.documentContent}
            />
          </Suspense>
        ) : (
          <div>Loading meeting notes…</div>
        )}
      </Page>
    </>
  );
}

const Page = styled(Column)`
  width: min(100%, ${p => p.theme.containerWidthWide});
  margin: auto;
  box-sizing: border-box;
  min-width: 0;
  padding: clamp(1rem, 4vw, ${p => p.theme.size(7)});
  container-type: inline-size;
  gap: ${p => p.theme.size(4)};
`;

const MeetingHeader = styled(Row)`
  align-items: flex-start;
  justify-content: space-between;
  > :first-child {
    min-width: 0;
  }
  @container (max-width: 36rem) {
    flex-direction: column;
    align-items: stretch;
  }
  gap: ${p => p.theme.size(3)};
  padding-bottom: ${p => p.theme.size(3)};
  border-bottom: 2px solid ${p => p.theme.colors.main};
`;

const MeetingActions = styled(Row)`
  flex-shrink: 0;
  flex-wrap: wrap;
  button {
    flex-shrink: 0;
    white-space: nowrap;
    min-height: 2.75rem;
  }
`;

const Phase = styled.span`
  color: ${p => p.theme.colors.main};
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
`;
