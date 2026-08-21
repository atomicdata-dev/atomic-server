import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaClock } from 'react-icons/fa6';
import { errorMessageFromResponse, signRequest, useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';

/**
 * Running a plugin when nobody is watching.
 *
 * A background run fetches but does not write — there is no one to approve at
 * 3am — so what it produces waits here until someone reviews it. That is the
 * whole reason this section shows a verdict rather than a success message.
 */

interface ScheduleInfo {
  intervalSeconds: number;
  nextRunAt: number;
  lastRunAt: number | null;
  pendingVerdict: string | null;
  lastError: string | null;
}

/** Intervals worth offering. Below a minute the server refuses anyway. */
const INTERVALS: Array<{ label: string; seconds: number }> = [
  { label: 'Every 15 minutes', seconds: 15 * 60 },
  { label: 'Hourly', seconds: 60 * 60 },
  { label: 'Every 6 hours', seconds: 6 * 60 * 60 },
  { label: 'Daily', seconds: 24 * 60 * 60 },
];

export function PluginSchedule({
  plugin,
  drive,
  onReview,
  reviewedNonce,
}: {
  plugin: string;
  drive: string;
  /** Opens the review dialog with the verdict a background run produced. */
  onReview: (verdict: string) => void;
  /**
   * Bumped once a pending verdict has been applied. Clearing it here rather
   * than in the dialog keeps the dialog ignorant of schedules — and leaving it
   * would offer the same changes again, which is how something gets applied
   * twice.
   */
  reviewedNonce: number;
}): React.JSX.Element {
  const store = useStore();
  const [schedule, setSchedule] = useState<ScheduleInfo | null>();

  const endpoint = `${store.getServerUrl()}/plugin-schedule`;
  const params = `drive=${encodeURIComponent(drive)}&plugin=${encodeURIComponent(plugin)}`;

  const load = useCallback(async () => {
    const result = await request(store, `${endpoint}?${params}`, {
      method: 'GET',
    });

    setSchedule(result.ok ? (result.body as ScheduleInfo | null) : null);
  }, [store, endpoint, params]);

  useEffect(() => {
    void load();
  }, [load]);

  const set = useCallback(
    async (intervalSeconds: number | null) => {
      const result = await request(store, endpoint, {
        method: 'POST',
        body: JSON.stringify({ drive, plugin, intervalSeconds }),
      });

      if (!result.ok) {
        toast.error(result.error);

        return;
      }

      setSchedule(result.body as ScheduleInfo | null);
    },
    [store, endpoint, drive, plugin],
  );

  const clearPending = useCallback(async () => {
    const result = await request(store, `${endpoint}?${params}`, {
      method: 'DELETE',
    });

    if (result.ok) setSchedule(result.body as ScheduleInfo | null);
  }, [store, endpoint, params]);

  useEffect(() => {
    if (reviewedNonce === 0) return;

    void clearPending();
  }, [reviewedNonce, clearPending]);

  const pending = schedule?.pendingVerdict ?? undefined;

  // A schedule set elsewhere — by an earlier version, or through the endpoint —
  // may not be one of the offered intervals. Showing it as "off" would be a lie,
  // and the next change to any field would silently turn it off for real.
  const current = schedule?.intervalSeconds;
  const options =
    current !== undefined && !INTERVALS.some(i => i.seconds === current)
      ? [...INTERVALS, { label: describeInterval(current), seconds: current }]
      : INTERVALS;

  return (
    <Column gap='0.5rem'>
      <SectionTitle>
        <Row gap='0.5ch' center>
          <FaClock aria-hidden />
          Schedule
        </Row>
      </SectionTitle>

      <Row gap='0.5rem' center>
        <BasicSelect
          value={schedule ? String(schedule.intervalSeconds) : ''}
          onChange={e =>
            set(e.target.value === '' ? null : Number(e.target.value))
          }
        >
          <option value=''>Only when I press Run</option>
          {options.map(interval => (
            <option key={interval.seconds} value={interval.seconds}>
              {interval.label}
            </option>
          ))}
        </BasicSelect>
        {schedule && (
          <Muted>
            {schedule.lastRunAt
              ? `Last ran ${new Date(schedule.lastRunAt).toLocaleString()}`
              : 'Has not run yet'}
          </Muted>
        )}
      </Row>

      {schedule?.lastError && (
        <Failed>The last background run failed: {schedule.lastError}</Failed>
      )}

      {pending && (
        <Pending>
          <Row center justify='space-between' gap='0.5rem'>
            <Column gap='0.1rem'>
              <strong>A background run has changes waiting</strong>
              <Muted>
                It ran without writing anything, because nothing is applied
                without you seeing it first.
              </Muted>
            </Column>
            <Row gap='0.5rem' center>
              <Button subtle onClick={clearPending}>
                Discard
              </Button>
              <Button onClick={() => onReview(pending)}>Review</Button>
            </Row>
          </Row>
        </Pending>
      )}
    </Column>
  );
}

/** For an interval nobody offered, said in whatever unit reads plainly. */
function describeInterval(seconds: number): string {
  if (seconds % 86400 === 0) return `Every ${seconds / 86400} day(s)`;

  if (seconds % 3600 === 0) return `Every ${seconds / 3600} hour(s)`;

  if (seconds % 60 === 0) return `Every ${seconds / 60} minute(s)`;

  return `Every ${seconds} seconds`;
}

type RequestResult = { ok: true; body: unknown } | { ok: false; error: string };

async function request(
  store: ReturnType<typeof useStore>,
  url: string,
  init: RequestInit,
): Promise<RequestResult> {
  const agent = store.getAgent();

  if (!agent) return { ok: false, error: 'Not signed in' };

  try {
    const headers = await signRequest(url, agent, {});
    const response = await fetch(url, {
      ...init,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      return {
        ok: false,
        error: errorMessageFromResponse(await response.text(), response.status),
      };
    }

    return { ok: true, body: await response.json() };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

const SectionTitle = styled.h2`
  font-size: 1.1rem;
  margin: 0;
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;

const Failed = styled.p`
  margin: 0;
  font-size: 0.9rem;
  color: ${p => p.theme.colors.alert};
`;

const Pending = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.75rem;
`;
