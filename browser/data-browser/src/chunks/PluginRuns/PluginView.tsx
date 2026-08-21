import { useCallback, useState } from 'react';
import { styled } from 'styled-components';
import { FaPlay } from 'react-icons/fa6';
import { useStore, type Resource } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { HighlightedCodeBlock } from '@components/HighlightedCodeBlock';
import { PluginSecrets } from '@views/Plugin/PluginSecrets';
import { RunPluginDialog } from './RunPluginDialog';
import { PluginRunHistory } from './PluginRunHistory';
import { usePluginSource } from './runScript';

/**
 * What a plugin's page is for: read what it does, run it, see what it did.
 *
 * The source is the plugin — showing it as one property among `created-at` and
 * `drive` buries the only thing worth reading. And since the trigger is manual,
 * running it should be a button rather than an item three levels into a menu.
 */
export function PluginView({
  resource,
  drive,
}: {
  resource: Resource;
  drive: string;
}): React.JSX.Element {
  const store = useStore();
  const [running, setRunning] = useState<boolean>();
  const source = usePluginSource(store, resource.subject, drive);

  const run = useCallback(() => setRunning(true), []);

  return (
    <Column gap='1.5rem'>
      <Row justify='space-between' center>
        <SectionTitle>Source</SectionTitle>
        <Button onClick={run}>
          <FaPlay aria-hidden /> Run
        </Button>
      </Row>

      {source === undefined ? (
        <Muted>Loading…</Muted>
      ) : source === '' ? (
        <Muted>This plugin has no source yet.</Muted>
      ) : (
        <HighlightedCodeBlock code={source} language='typescript' />
      )}

      <PluginSecrets plugin={resource} drive={drive} />
      <PluginRunHistory resource={resource} />

      {running !== undefined && (
        <RunPluginDialog
          resource={resource}
          drive={drive}
          show={running}
          onShowChange={setRunning}
        />
      )}
    </Column>
  );
}

const SectionTitle = styled.h2`
  font-size: 1.1rem;
  margin: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;
