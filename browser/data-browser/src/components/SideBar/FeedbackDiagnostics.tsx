import {
  useEffect,
  useId,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { useStore } from '@tomic/react';
import { styled } from 'styled-components';
import { getPersistentDiagnostics } from '../../helpers/persistent-diagnostics';
import { Details } from '../Details';
import { Button } from '../Button';
import { Checkbox } from '../forms/Checkbox';
import { Column, Row } from '../Row';
import { CodeBlock } from '../CodeBlock';
import {
  previewDiagnostics,
  currentDiagnosticText,
  downloadDiagnostics,
  type DiagnosticPreview,
} from '../../helpers/diagnostic-report';

export function FeedbackDiagnostics({
  onSelect,
  disabled,
  children,
}: {
  onSelect: (preview: DiagnosticPreview | undefined) => void;
  disabled: boolean;
  children?: ReactNode;
}) {
  const includeId = useId();
  const store = useStore();
  const recorder = store.diagnostics;
  const persistence = getPersistentDiagnostics(recorder);
  const persistenceStatus = useSyncExternalStore(
    persistence?.subscribe ?? recorder.subscribe,
    () => persistence?.status ?? 'memory-only',
  );
  const session = useSyncExternalStore(
    recorder.subscribe,
    () => recorder.session,
  );
  const active = useSyncExternalStore(
    recorder.subscribe,
    () => recorder.active,
  );
  const [preview, setPreview] = useState<DiagnosticPreview | undefined>();
  // Attached by default; the person can opt out, and that holds across the
  // recorder's updates for as long as this dialog stays open.
  const [included, setIncluded] = useState(true);
  const declined = useRef(false);
  const current = preview?.session === session ? preview : undefined;

  useEffect(() => {
    const refresh = () => {
      const selected = recorder.active
        ? previewDiagnostics(recorder)
        : undefined;
      const attach = !!selected && !declined.current;

      setPreview(selected);
      setIncluded(attach);
      onSelect(attach ? selected : undefined);
    };

    refresh();

    return recorder.subscribe(refresh);
  }, [recorder, onSelect]);

  return (
    <DiagnosticsLayout>
      <Checkbox.Label htmlFor={includeId}>
        <Checkbox
          id={includeId}
          checked={included && active}
          disabled={disabled || !active}
          onChange={value => {
            declined.current = !value;
            setIncluded(value);

            if (!value) {
              onSelect(undefined);

              return;
            }

            const selected = previewDiagnostics(recorder);

            setPreview(selected);
            onSelect(selected);
          }}
        />
        <span>Include diagnostic data</span>
      </Checkbox.Label>
      {children}
      <Details
        title={
          <DiagnosticsTitle>
            <span>Diagnostic data</span>
          </DiagnosticsTitle>
        }
        noIndent
        onStateToggle={open => {
          if (open && active && !included) {
            setPreview(previewDiagnostics(recorder));
          }
        }}
      >
        <DiagnosticsCard>
          <RecordingState $active={active}>
            {active ? 'Recording locally' : 'Not recording'}
          </RecordingState>
          <p>
            Recent save and connection activity only. No document content,
            names, URLs, or error messages. Nothing is shared unless you attach
            it below.
          </p>
          {persistenceStatus === 'memory-only' && (
            <StatusMessage role='status'>
              Kept in this tab only; it will be lost on reload.
            </StatusMessage>
          )}
          {persistenceStatus === 'clear-failed' && (
            <StatusMessage role='alert'>
              Couldn’t clear local diagnostics. Recording is stopped; retry
              before leaving this browser.
            </StatusMessage>
          )}
          {persistenceStatus === 'paused' && (
            <StatusMessage role='status'>
              Reset in another tab. Reload to record again.
            </StatusMessage>
          )}
          <Row gap='0.5rem' wrapItems>
            <Button
              subtle
              disabled={
                disabled ||
                persistenceStatus === 'loading' ||
                persistenceStatus === 'paused'
              }
              onClick={() => {
                if (persistence) {
                  void persistence.setEnabled(
                    persistenceStatus === 'clear-failed'
                      ? false
                      : !recorder.active,
                  );
                } else if (recorder.active) recorder.clear();
                else {
                  recorder.start();
                  recorder.connection(store.serverConnected);
                  const status = store.getSyncStatus();
                  recorder.queue(
                    status.pendingDirtyCount,
                    status.blockedCount,
                    status.serverConnected,
                  );
                }
              }}
            >
              {persistenceStatus === 'clear-failed'
                ? 'Retry clearing diagnostics'
                : active
                  ? 'Stop and clear'
                  : 'Start recording'}
            </Button>
          </Row>
          {current && (
            <ReviewPanel>
              <p>Review the timing and activity counts before sharing.</p>
              <section aria-label='Diagnostic report preview'>
                <DiagnosticCodeBlock content={current.text} wordWrap />
              </section>
              <Button
                subtle
                disabled={disabled}
                onClick={() => {
                  const text = currentDiagnosticText(recorder, current);
                  if (text) downloadDiagnostics(text);
                }}
              >
                Download report
              </Button>
            </ReviewPanel>
          )}
        </DiagnosticsCard>
      </Details>
    </DiagnosticsLayout>
  );
}

const DiagnosticsLayout = styled(Column)`
  gap: 1rem;
`;

const DiagnosticsTitle = styled.span`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
`;

const RecordingState = styled.span<{ $active: boolean }>`
  color: ${({ theme, $active }) =>
    $active ? theme.colors.main : theme.colors.textLight};
  font-size: 0.8em;
  font-weight: normal;
`;

const DiagnosticsCard = styled(Column)`
  gap: 0.75rem;
  margin: 0.5rem 0 0;
  padding: 0.85rem;
  border: 1px solid ${({ theme }) => theme.colors.bg2};
  border-radius: ${({ theme }) => theme.radius};
  background: ${({ theme }) => theme.colors.bg1};
`;

const StatusMessage = styled.p`
  color: ${({ theme }) => theme.colors.textLight};
`;

const ReviewPanel = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
  padding-top: 0.25rem;
  border-top: 1px solid ${({ theme }) => theme.colors.bg2};
`;

const DiagnosticCodeBlock = styled(CodeBlock)`
  max-height: 16rem;
  overflow: auto;
  padding-right: 3rem;
  background: ${({ theme }) => theme.colors.bg};
`;
