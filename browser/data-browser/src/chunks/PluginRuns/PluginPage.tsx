import { useCallback, useState } from 'react';
import { styled } from 'styled-components';
import { FaPencil, FaPlay } from 'react-icons/fa6';
import { useStore, type Resource } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { ContainerWide } from '@components/Containers';
import { EditableTitle } from '@components/EditableTitle';
import { HighlightedCodeBlock } from '@components/HighlightedCodeBlock';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { editURL } from '@helpers/navigation';
import { PluginSecrets } from './PluginSecrets';
import { PluginRunHistory } from './PluginRunHistory';
import { RunPluginDialog } from './RunPluginDialog';
import { usePluginManifest, usePluginSource } from './runScript';
import { originsMentionedIn, secretsMentionedIn } from '@tomic/react';

/**
 * A plugin's page.
 *
 * A page of its own rather than sections appended to the default resource view,
 * which rendered the source twice — once as prose in the property table beside
 * `created-at`, once properly — and left a generic header above it.
 *
 * Ordered by what someone came for: run it, see what it needs, see what it did,
 * and only then read how it works. The source is the longest thing here and the
 * least often read once the plugin works.
 */
export function PluginPage({
  resource,
  drive,
}: {
  resource: Resource;
  drive: string;
}): React.JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [running, setRunning] = useState<boolean>();
  const source = usePluginSource(store, resource.subject, drive);
  const manifest = usePluginManifest(source);

  const run = useCallback(() => setRunning(true), []);

  return (
    <ContainerWide>
      <Column gap='1.5rem'>
        <Row justify='space-between' align='flex-start'>
          <EditableTitle resource={resource} />
          {/* A long title was squeezing these until their labels wrapped one
              letter per line. */}
          <Actions gap='0.5rem' center>
            <Button subtle onClick={() => navigate(editURL(resource.subject))}>
              <FaPencil aria-hidden /> Edit
            </Button>
            <Button onClick={run}>
              <FaPlay aria-hidden /> Run
            </Button>
          </Actions>
        </Row>

        <PluginSecrets
          plugin={resource.subject}
          drive={drive}
          declared={manifest.secrets}
          mentioned={secretsMentionedIn(source ?? '')}
          candidateOrigins={originsMentionedIn(source ?? '')}
        />

        <PluginRunHistory resource={resource} />

        <Column gap='0.5rem'>
          <SectionTitle>Source</SectionTitle>
          {source === undefined ? (
            <Muted>Loading…</Muted>
          ) : source === '' ? (
            <Muted>This plugin has no source yet.</Muted>
          ) : (
            <HighlightedCodeBlock code={source} language='typescript' />
          )}
        </Column>

        {running !== undefined && (
          <RunPluginDialog
            resource={resource}
            drive={drive}
            show={running}
            onShowChange={setRunning}
          />
        )}
      </Column>
    </ContainerWide>
  );
}

/** Never squeezed by the title beside it. */
const Actions = styled(Row)`
  flex-shrink: 0;

  button {
    white-space: nowrap;
  }
`;

const SectionTitle = styled.h2`
  font-size: 1.1rem;
  margin: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;
