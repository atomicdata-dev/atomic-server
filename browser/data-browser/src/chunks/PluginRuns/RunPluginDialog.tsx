import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { useStore, type Resource } from '@tomic/react';
import { Dialog, useDialog } from '@components/Dialog';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { LoaderBlock } from '@components/Loader';
import {
  applyRun,
  pluginClassesFor,
  prepareRun,
  recordBlockedRun,
  type PreparedRun,
} from './runScript';

/**
 * Applying, shaped as a result rather than an exception.
 *
 * The React Compiler cannot compile try/catch/finally inside a component, and
 * this is exactly the kind of async failure handling that needs one — so it
 * lives out here and the component only branches.
 */
async function attemptApply(
  store: ReturnType<typeof useStore>,
  prepared: PreparedRun,
  target: { plugin: string; drive: string },
): Promise<
  | { ok: true; report: Awaited<ReturnType<typeof applyRun>>['report'] }
  | {
      ok: false;
      message: string;
    }
> {
  try {
    const { report } = await applyRun(store, prepared, target);

    return { ok: true, report };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}

interface RunPluginDialogProps {
  resource: Resource;
  drive: string;
  show: boolean;
  onShowChange: (show: boolean) => void;
}

/**
 * Shows what a plugin proposes, before anything is written.
 *
 * The run has already happened by the time this renders — a run holds no
 * authority, so executing it needs no consent. What needs approving is the
 * writing, and this dialog is that boundary.
 */
export function RunPluginDialog({
  resource,
  drive,
  show,
  onShowChange,
}: RunPluginDialogProps): React.JSX.Element {
  const store = useStore();
  const [dialogProps, showDialog, closeDialog] = useDialog({
    bindShow: onShowChange,
  });
  const { subject } = resource;
  const [prepared, setPrepared] = useState<PreparedRun>();
  const [applying, setApplying] = useState(false);

  useEffect(() => {
    if (show) showDialog();
  }, [show, showDialog]);

  useEffect(() => {
    if (!show) {
      setPrepared(undefined);

      return;
    }

    let cancelled = false;

    (async () => {
      const schema = await pluginClassesFor(store, drive);
      // Read through the store rather than the passed resource, so the effect
      // depends on a subject string instead of a proxy whose identity churns.
      const plugin = await store.getResource(subject);
      const source = plugin.get(schema.properties['plugin-source']) as
        | string
        | undefined;

      const result = await prepareRun(
        store,
        source ?? '',
        { kind: 'manual', at: Date.now(), subject },
        { plugin: subject, drive },
      );

      if (!cancelled) setPrepared(result);
    })().catch((e: Error) => {
      toast.error(`Could not run this plugin: ${e.message}`);
      closeDialog();
    });

    return () => {
      cancelled = true;
    };
  }, [show, subject, drive, store, closeDialog]);

  const apply = useCallback(async () => {
    if (!prepared) return;

    setApplying(true);

    const result = await attemptApply(store, prepared, {
      plugin: subject,
      drive,
    });

    setApplying(false);

    if (!result.ok) {
      toast.error(`Could not apply: ${result.message}`);

      return;
    }

    const { report } = result;
    toast.success(
      report.failed > 0
        ? `Applied ${report.applied}, ${report.failed} failed`
        : `Applied ${report.applied} changes`,
    );
    closeDialog(true);
  }, [prepared, store, subject, drive, closeDialog]);

  const dismiss = useCallback(() => {
    // A refused run is still a run: record it so the refusal is findable.
    if (prepared?.plan.blocked) {
      void recordBlockedRun(store, prepared, {
        plugin: subject,
        drive,
      }).catch(() => undefined);
    }

    closeDialog();
  }, [prepared, store, subject, drive, closeDialog]);

  const plan = prepared?.plan;
  const nothingToApply = !plan || plan.blocked || plan.changes.length === 0;

  return (
    <Dialog {...dialogProps}>
      <Dialog.Title>
        <h1>{resource.title}</h1>
      </Dialog.Title>
      <Dialog.Content>
        {!prepared ? (
          <LoaderBlock />
        ) : (
          <Column>
            {prepared.timedOut && (
              <Message $tone='error'>
                This plugin ran too long and was stopped. Nothing was planned.
              </Message>
            )}
            {plan!.blocked && (
              <Message $tone='error'>
                Nothing can be written until these are fixed.
              </Message>
            )}
            {plan!.problems.map((problem, i) => (
              <Message key={i} $tone={problem.severity}>
                {problem.message}
              </Message>
            ))}
            {plan!.changes.length === 0 && !plan!.blocked && (
              <Message $tone='warning'>This run proposes no changes.</Message>
            )}
            {plan!.changes.map(change => (
              <Change key={`${change.op}-${change.subject}`}>
                <Row gap='0.5rem'>
                  <Op>{change.op}</Op>
                  <Subject>
                    {change.op === 'create'
                      ? (change.localId ?? 'new resource')
                      : change.subject}
                  </Subject>
                </Row>
                {change.properties.map(property => (
                  <PropertyRow key={property.property}>
                    <Name>{property.shortname ?? property.property}</Name>
                    {property.from !== undefined && (
                      <Was>{JSON.stringify(property.from)}</Was>
                    )}
                    <Now>
                      {property.to === undefined
                        ? 'removed'
                        : JSON.stringify(property.to)}
                    </Now>
                  </PropertyRow>
                ))}
                {change.problems.map((problem, i) => (
                  <Message key={i} $tone={problem.severity}>
                    {problem.message}
                  </Message>
                ))}
              </Change>
            ))}
          </Column>
        )}
      </Dialog.Content>
      <Dialog.Actions>
        <Button subtle onClick={dismiss} disabled={applying}>
          Cancel
        </Button>
        <Button onClick={apply} disabled={nothingToApply || applying}>
          {applying
            ? 'Applying…'
            : `Apply ${plan?.changes.length ?? 0} changes`}
        </Button>
      </Dialog.Actions>
    </Dialog>
  );
}

const Message = styled.p<{ $tone: 'error' | 'warning' }>`
  color: ${p =>
    p.$tone === 'error' ? p.theme.colors.alert : p.theme.colors.textLight};
  margin: 0;
  font-size: 0.9rem;
`;

const Change = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
`;

const Op = styled.span`
  text-transform: uppercase;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
`;

const Subject = styled.span`
  font-family: monospace;
  overflow-wrap: anywhere;
`;

const PropertyRow = styled.div`
  display: flex;
  gap: 0.5rem;
  align-items: baseline;
  font-size: 0.9rem;
`;

const Name = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Was = styled.span`
  text-decoration: line-through;
  opacity: 0.6;
`;

const Now = styled.span`
  font-family: monospace;
`;
