import {
  calendarWeekdays,
  defaultRepeatRule,
  isLastWeekday,
  weekdayOf,
  weekdayOrdinal,
  type RepeatAnchor,
  type RepeatFrequency,
  type RepeatParse,
  type RepeatRule,
} from '@tomic/lib/calendar-recurrence.js';
import { useId, useState, type JSX, type ReactNode } from 'react';
import { styled } from 'styled-components';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { ButtonClean } from '@components/Button';
import { describeRepeat, weekdayName } from './repeatSummary';
import { untilDateToCommit } from './untilDraft';

interface RepeatFieldProps {
  parsed: RepeatParse;
  /** Where the series starts; the defaults and the summary follow it. */
  anchor: RepeatAnchor;
  disabled?: boolean;
  onChange: (next: RepeatParse) => void;
  /** The raw payload's editor, behind "Show JSON". */
  json?: ReactNode;
}

type Choice = 'none' | RepeatFrequency | 'custom';

/** The Repeat setting of a calendar row: none, daily, weekly on chosen days,
 * monthly by date or weekday, or yearly; ending never, on a date or after N
 * times. A rule it cannot show is "Custom", kept as is, with its JSON. */
export function RepeatField({
  parsed,
  anchor,
  disabled,
  onChange,
  json,
}: RepeatFieldProps): JSX.Element {
  const id = useId();
  const [showJson, setShowJson] = useState(false);
  const rule = parsed.kind === 'rule' ? parsed.rule : undefined;
  const choice: Choice =
    parsed.kind === 'rule' ? parsed.rule.frequency : parsed.kind;

  const update = (patch: Partial<RepeatRule>) => {
    if (rule) onChange({ kind: 'rule', rule: { ...rule, ...patch } });
  };

  const choose = (next: Choice) => {
    if (next === 'none') onChange({ kind: 'none' });
    else if (next !== 'custom')
      onChange({
        kind: 'rule',
        // Keep the end when switching between frequencies.
        rule: { ...defaultRepeatRule(next, anchor), end: rule?.end ?? NEVER },
      });
  };

  return (
    <Wrapper data-testid='repeat-field'>
      <FieldRow>
        <Label htmlFor={`${id}-repeat`}>Repeat</Label>
        <BasicSelect
          id={`${id}-repeat`}
          value={choice}
          disabled={disabled}
          onChange={e => choose(e.target.value as Choice)}
        >
          <option value='none'>Does not repeat</option>
          <option value='daily'>Daily</option>
          <option value='weekly'>Weekly</option>
          <option value='monthly'>Monthly</option>
          <option value='yearly'>Yearly</option>
          {parsed.kind === 'custom' && <option value='custom'>Custom</option>}
        </BasicSelect>
      </FieldRow>

      {rule && (
        <>
          <FieldRow>
            <Label htmlFor={`${id}-interval`}>Every</Label>
            <Inline>
              <NumberWrapper>
                <InputStyled
                  id={`${id}-interval`}
                  type='number'
                  min={1}
                  max={1000}
                  value={rule.interval}
                  disabled={disabled}
                  onChange={e => {
                    const interval = Number(e.target.value);

                    if (Number.isSafeInteger(interval) && interval >= 1) {
                      update({ interval: Math.min(interval, 1000) });
                    }
                  }}
                />
              </NumberWrapper>
              <IntervalUnit frequency={rule.frequency} />
            </Inline>
          </FieldRow>

          {rule.frequency === 'weekly' && (
            <FieldRow>
              <Label as='span' id={`${id}-days`}>
                On
              </Label>
              <Weekdays role='group' aria-labelledby={`${id}-days`}>
                {calendarWeekdays.map(day => {
                  const on = rule.weekdays.includes(day);

                  return (
                    <WeekdayToggle
                      key={day}
                      type='button'
                      aria-pressed={on}
                      aria-label={weekdayName(day)}
                      title={weekdayName(day)}
                      disabled={disabled}
                      $on={on}
                      onClick={() => {
                        const weekdays = on
                          ? rule.weekdays.filter(d => d !== day)
                          : [...rule.weekdays, day];
                        // A weekly series needs at least one day.
                        if (weekdays.length) update({ weekdays });
                      }}
                    >
                      {weekdayName(day, undefined, 'short')}
                    </WeekdayToggle>
                  );
                })}
              </Weekdays>
            </FieldRow>
          )}

          {rule.frequency === 'monthly' && (
            <FieldRow>
              <Label htmlFor={`${id}-monthly`}>On</Label>
              <BasicSelect
                id={`${id}-monthly`}
                value={
                  rule.monthlyBy === 'weekday'
                    ? `weekday:${rule.ordinal ?? weekdayOrdinal(anchor.date)}`
                    : 'date'
                }
                disabled={disabled}
                onChange={e => {
                  const [by, ordinal] = e.target.value.split(':');
                  update(
                    by === 'date'
                      ? { monthlyBy: 'date', ordinal: undefined }
                      : {
                          monthlyBy: 'weekday',
                          ordinal:
                            Number(ordinal) === weekdayOrdinal(anchor.date)
                              ? undefined
                              : Number(ordinal),
                        },
                  );
                }}
              >
                <option value='date'>
                  {monthDayLabel(Number(anchor.date.slice(8)))}
                </option>
                {monthlyWeekdayOptions(anchor).map(ordinal => (
                  <option key={ordinal} value={`weekday:${ordinal}`}>
                    {nthWeekdayLabel(
                      ordinal,
                      weekdayName(weekdayOf(anchor.date)),
                    )}
                  </option>
                ))}
              </BasicSelect>
            </FieldRow>
          )}

          <FieldRow>
            <Label htmlFor={`${id}-ends`}>Ends</Label>
            <Inline>
              <BasicSelect
                id={`${id}-ends`}
                value={rule.end.type}
                disabled={disabled}
                onChange={e =>
                  update({ end: defaultEnd(e.target.value, anchor) })
                }
              >
                <option value='never'>Never</option>
                <option value='until'>On a date</option>
                <option value='count'>After a number of times</option>
              </BasicSelect>
              {rule.end.type === 'until' && (
                <DateWrapper>
                  <UntilDateInput
                    min={anchor.date}
                    value={rule.end.date}
                    disabled={disabled}
                    onCommit={date => update({ end: { type: 'until', date } })}
                  />
                </DateWrapper>
              )}
              {rule.end.type === 'count' && (
                <>
                  <NumberWrapper>
                    <InputStyled
                      type='number'
                      aria-label='Number of times'
                      min={1}
                      value={rule.end.count}
                      disabled={disabled}
                      onChange={e => {
                        const count = Number(e.target.value);

                        if (Number.isSafeInteger(count) && count >= 1) {
                          update({ end: { type: 'count', count } });
                        }
                      }}
                    />
                  </NumberWrapper>
                  <span>times</span>
                </>
              )}
            </Inline>
          </FieldRow>
        </>
      )}

      <Footer>
        <Summary data-testid='repeat-summary' aria-live='polite'>
          {describeRepeat(parsed, anchor)}
        </Summary>
        {json && (
          <JsonToggle
            type='button'
            aria-expanded={showJson}
            onClick={() => setShowJson(show => !show)}
          >
            {showJson ? 'Hide JSON' : 'Show JSON'}
          </JsonToggle>
        )}
      </Footer>
      {parsed.kind === 'custom' && <CustomHint />}
      {json && showJson && <div>{json}</div>}
    </Wrapper>
  );
}

// Its own component, so the extractor sees the sentence: inside the guard
// above it fell out of the catalog.
function CustomHint(): JSX.Element {
  return (
    <Hint>
      This repeat rule has options the Repeat field cannot show. Edit its JSON,
      or pick a repeat above to replace it.
    </Hint>
  );
}

const NEVER = { type: 'never' } as const;

function defaultEnd(type: string, anchor: RepeatAnchor): RepeatRule['end'] {
  if (type === 'until') return { type: 'until', date: anchor.date };
  if (type === 'count') return { type: 'count', count: 10 };

  return NEVER;
}

/** The start's own nth weekday, and "last" too when it is also the last. */
function monthlyWeekdayOptions(anchor: RepeatAnchor): number[] {
  const own = weekdayOrdinal(anchor.date);

  return own !== -1 && isLastWeekday(anchor.date) ? [own, -1] : [own];
}

function IntervalUnit({
  frequency,
}: {
  frequency: RepeatFrequency;
}): JSX.Element {
  switch (frequency) {
    case 'daily':
      return <span>days</span>;
    case 'weekly':
      return <span>weeks</span>;
    case 'monthly':
      return <span>months</span>;
    case 'yearly':
      return <span>years</span>;
  }
}

// Plain strings: an <option> can only hold text.
function monthDayLabel(day: number): string {
  return `On day ${day}`;
}

function nthWeekdayLabel(ordinal: number, weekday: string): string {
  switch (ordinal) {
    case 1:
      return `On the first ${weekday}`;
    case 2:
      return `On the second ${weekday}`;
    case 3:
      return `On the third ${weekday}`;
    case 4:
      return `On the fourth ${weekday}`;
    default:
      return `On the last ${weekday}`;
  }
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
`;

const FieldRow = styled.div`
  display: grid;
  grid-template-columns: 6rem minmax(0, 1fr);
  align-items: center;
  gap: 0.5rem;
`;

const Label = styled.label`
  font-weight: bold;
`;

const Inline = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
`;

const NumberWrapper = styled(InputWrapper)`
  flex: 0 0 5rem;
`;

const DateWrapper = styled(InputWrapper)`
  flex: 0 1 11rem;
`;

const Weekdays = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
`;

const WeekdayToggle = styled.button<{ $on: boolean }>`
  min-width: 2.6rem;
  height: 2rem;
  padding-inline: 0.4rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => (p.$on ? p.theme.colors.main : p.theme.colors.bg2)};
  background-color: ${p => (p.$on ? p.theme.colors.main : p.theme.colors.bg)};
  color: ${p => (p.$on ? 'white' : p.theme.colors.text)};
  font-family: inherit;
  cursor: pointer;

  &:disabled {
    cursor: default;
    opacity: 0.6;
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 1px;
  }
`;

const Footer = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
`;

const Summary = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const Hint = styled.p`
  margin: 0;
  font-size: 0.9em;
  color: ${p => p.theme.colors.textLight};
`;

const JsonToggle = styled(ButtonClean)`
  color: ${p => p.theme.colors.main};
  text-decoration: underline;
  font-size: 0.9em;
`;

/** Keeps what is typed in a local draft and commits on blur or Enter, so the
 * input keeps focus while a date is typed (#2137). */
function UntilDateInput({
  min,
  value,
  disabled,
  onCommit,
}: {
  min: string;
  value: string;
  disabled?: boolean;
  onCommit: (date: string) => void;
}): JSX.Element {
  const [draft, setDraft] = useState<string | null>(null);

  const commit = () => {
    const date = untilDateToCommit(draft, value);

    setDraft(null);

    if (date) onCommit(date);
  };

  return (
    <InputStyled
      type='date'
      aria-label='Last day'
      min={min}
      value={draft ?? value}
      disabled={disabled}
      onChange={e => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={e => {
        if (e.key === 'Enter') commit();
      }}
    />
  );
}
