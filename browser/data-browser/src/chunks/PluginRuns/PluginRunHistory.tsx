import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { core, useCollection, useStore, type Resource } from '@tomic/react';
import type { ChangeOutcome, Problem } from '@tomic/react';
import { Details } from '@components/Details';
import { Column, Row } from '@components/Row';
import { AtomicLink } from '@components/AtomicLink';
import { onRunsChanged, pluginClassesFor, usePluginClass } from './runScript';

/**
 * What a plugin has actually done, every time it ran.
 *
 * The point of the log is that someone who did not write the plugin — and
 * cannot read its source with any confidence that it does what it claims — can
 * still see what it did. So this shows outcomes and problems, not the code.
 */

interface RunSummary {
  subject: string;
  status: string;
  startedAt?: number;
  problems: Problem[];
  outcomes: ChangeOutcome[];
}

export function PluginRunHistory({
  resource,
}: {
  resource: Resource;
}): React.JSX.Element | null {
  const store = useStore();
  const drive = store.getDrive();
  const pluginClass = usePluginClass(drive);
  const [runs, setRuns] = useState<RunSummary[]>();

  const { subject } = resource;
  const isPlugin =
    pluginClass !== undefined && resource.hasClasses(pluginClass);

  // Children are not materialized on the parent, so ask the index for them.
  const { collection, ready, invalidateCollection } = useCollection({
    property: core.properties.parent,
    value: subject,
  });

  // A run creates a resource this query has never seen, so the query has to be
  // told. Otherwise the log only catches up on reload.
  useEffect(
    () => onRunsChanged(subject, () => void invalidateCollection()),
    [subject, invalidateCollection],
  );

  useEffect(() => {
    if (!isPlugin || !drive || !ready) return;

    let cancelled = false;

    (async () => {
      const schema = await pluginClassesFor(store, drive);
      const found: RunSummary[] = [];

      for (let i = 0; i < collection.totalMembers; i++) {
        const child = await collection.getMemberWithIndex(i);

        if (!child) continue;

        const record = await store.getResource(child);
        const status = record.get(schema.properties['run-status']) as
          | string
          | undefined;

        // Everything under a plugin that is not a run — anything it created
        // with itself as parent — is skipped by having no status.
        if (!status) continue;

        found.push({
          subject: child,
          status,
          startedAt: record.get(schema.properties['started-at']) as
            | number
            | undefined,
          problems: (record.get(schema.properties['run-problems']) ??
            []) as Problem[],
          outcomes: (record.get(schema.properties['run-outcomes']) ??
            []) as ChangeOutcome[],
        });
      }

      found.sort((a, b) => (b.startedAt ?? 0) - (a.startedAt ?? 0));

      if (!cancelled) setRuns(found);
    })().catch(() => {
      if (!cancelled) setRuns([]);
    });

    return () => {
      cancelled = true;
    };
  }, [isPlugin, drive, store, subject, ready, collection]);

  if (!isPlugin) return null;

  return (
    <Column gap='0.5rem'>
      <Heading>Runs</Heading>
      {runs === undefined && <Muted>Loading…</Muted>}
      {runs?.length === 0 && <Muted>This plugin has not run yet.</Muted>}
      {runs?.map(run => (
        <Details
          key={run.subject}
          title={
            <Row gap='0.5rem' align='baseline'>
              <Status $status={run.status}>{run.status}</Status>
              <Muted>{describe(run)}</Muted>
            </Row>
          }
        >
          <Column gap='0.25rem'>
            {run.problems.map((problem, i) => (
              <Message key={i} $tone={problem.severity}>
                {problem.message}
              </Message>
            ))}
            {run.outcomes.map((outcome, i) => (
              <Row key={i} gap='0.5rem' align='baseline'>
                <Muted>{outcome.op}</Muted>
                <AtomicLink subject={outcome.subject}>
                  {outcome.localId ?? outcome.subject}
                </AtomicLink>
                <Muted>{outcome.status}</Muted>
              </Row>
            ))}
          </Column>
        </Details>
      ))}
    </Column>
  );
}

function describe(run: RunSummary): string {
  const when = run.startedAt
    ? new Date(run.startedAt).toLocaleString()
    : 'unknown time';
  const applied = run.outcomes.filter(o => o.status === 'applied').length;
  const failed = run.outcomes.filter(o => o.status === 'failed').length;

  const counts = [
    `${applied} applied`,
    failed > 0 ? `${failed} failed` : undefined,
    run.problems.length > 0
      ? `${run.problems.length} ${run.problems.length === 1 ? 'problem' : 'problems'}`
      : undefined,
  ].filter(Boolean);

  return `${when} — ${counts.join(', ')}`;
}

const Heading = styled.h2`
  font-size: 1.1rem;
  margin: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const Status = styled.span<{ $status: string }>`
  text-transform: uppercase;
  font-size: 0.75rem;
  color: ${p =>
    p.$status === 'applied' ? p.theme.colors.textLight : p.theme.colors.alert};
`;

const Message = styled.p<{ $tone: string }>`
  margin: 0;
  font-size: 0.9rem;
  color: ${p =>
    p.$tone === 'error' ? p.theme.colors.alert : p.theme.colors.textLight};
`;
