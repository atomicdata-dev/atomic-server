import { forms, useNumber, type Resource } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaXmark } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { IconButton } from '@components/IconButton/IconButton';
import { Column, Row } from '@components/Row';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useDateTimeInput } from '@components/forms/hooks/useDateTimeInput';
import { formatScheduleMoment, getFormAvailability } from './formSchedule';

/** How often the status line re-evaluates its "now". Only runs while the
 * form has a bound that can still flip on its own. */
const TICK_MS = 30_000;

interface FormScheduleSectionProps {
  resource: Resource;
}

/**
 * "Schedule" settings (Phase 7 "Scheduled publish/unpublish"): an optional
 * open/close window on top of the manual publish switch. Both bounds are
 * plain timestamps compared per request by the server
 * (`server/src/forms.rs::form_availability_at`) — there is no scheduler, so
 * a form opens and closes on time even if the server was down at that exact
 * moment.
 */
export function FormScheduleSection({
  resource,
}: FormScheduleSectionProps): JSX.Element {
  const [publishedAt] = useNumber(resource, forms.properties.formPublishedAt);
  const [openAt, setOpenAt] = useNumber(resource, forms.properties.formOpenAt, {
    commit: true,
  });
  const [closeAt, setCloseAt] = useNumber(
    resource,
    forms.properties.formCloseAt,
    { commit: true },
  );

  const now = useNow(openAt !== undefined || closeAt !== undefined);
  const availability = getFormAvailability(
    { publishedAt, openAt, closeAt },
    now,
  );
  const invertedWindow =
    openAt !== undefined && closeAt !== undefined && closeAt <= openAt;

  return (
    <Column gap="1rem">
      <StatusLine data-testid="schedule-status">
        <Status
          availability={availability}
          isPublished={publishedAt !== undefined}
        />
      </StatusLine>
      <MomentField
        label="Opens"
        testId="schedule-open-input"
        clearTitle="Clear open date"
        title='Before this moment visitors see a "not open yet" page'
        value={openAt}
        onChange={setOpenAt}
      />
      <MomentField
        label="Closes"
        testId="schedule-close-input"
        clearTitle="Clear close date"
        title='From this moment on visitors see a "closed" page'
        value={closeAt}
        onChange={setCloseAt}
      />
      {invertedWindow && (
        <Warning>
          This form closes before it opens, so it will never accept responses.
        </Warning>
      )}
    </Column>
  );
}

const Status: React.FC<{
  availability: ReturnType<typeof getFormAvailability>;
  isPublished: boolean;
}> = ({ availability, isPublished }) => {
  switch (availability.state) {
    case 'unpublished':
      return isPublished ? <></> : 'Publish the form to apply the schedule';
    case 'not-yet-open':
      return (
        <>
          Scheduled for{' '}
          <time dateTime={availability.opensAt.toString()}>
            {formatScheduleMoment(availability.opensAt)}
          </time>
        </>
      );
    case 'closed':
      return (
        <>
          Status: <ClosedLabel>Closed</ClosedLabel>
        </>
      );
    case 'open':
      return (
        <>
          Status: <OpenLabel>Open</OpenLabel>
        </>
      );
  }
};

interface MomentFieldProps {
  label: string;
  testId: string;
  /** Passed in rather than derived from `label`: a translated label does not
   * necessarily compose into a natural "Clear <label>" sentence. */
  clearTitle: string;
  title: string;
  value: number | undefined;
  onChange: (value: number | undefined) => void;
}

function MomentField({
  label,
  testId,
  clearTitle,
  title,
  value,
  onChange,
}: MomentFieldProps): JSX.Element {
  const [localDate, handleChange] = useDateTimeInput(value, onChange);

  return (
    <Field label={label}>
      <Row gap="0.5rem" center>
        <NarrowInputWrapper>
          <InputStyled
            type="datetime-local"
            data-testid={testId}
            title={title}
            value={localDate ?? ''}
            onChange={handleChange}
          />
        </NarrowInputWrapper>
        {value !== undefined && (
          <IconButton title={clearTitle} onClick={() => onChange(undefined)}>
            <FaXmark />
          </IconButton>
        )}
      </Row>
    </Field>
  );
}

/** A "now" that advances while the panel is open, so the status line flips
 * by itself the moment a form opens or closes. Frozen (one initial read)
 * when there is no schedule to wait on. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!active) {
      return;
    }

    const id = setInterval(() => setNow(Date.now()), TICK_MS);

    return () => clearInterval(id);
  }, [active]);

  return now;
}

const NarrowInputWrapper = styled(InputWrapper)`
  width: min-content;
`;

const StatusLine = styled.p`
  margin: 0;

  & time {
    font-weight: bold;
  }
`;

const Hint = styled.p`
  margin: 0;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const Warning = styled(Hint)`
  color: ${p => p.theme.colors.alert};
`;

const ClosedLabel = styled.span`
  color: ${p => p.theme.colors.alert};
  font-weight: bold;
`;

const OpenLabel = styled.span`
  color: ${p => p.theme.colors.main};
  font-weight: bold;
`;
