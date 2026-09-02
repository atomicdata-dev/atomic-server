import { forms, Resource, useNumber } from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { Row } from '@components/Row';
import { Button } from '@components/Button';
import { formatScheduleMoment, getFormAvailability } from './formSchedule';

interface PublishToggleProps {
  resource: Resource;
}

/**
 * The manual publish switch. `form-published-at` is the master switch the
 * server gates every `/form/:id` route on
 * (`server/src/forms.rs::form_availability_at`); the optional
 * `form-open-at` / `form-close-at` window from the Settings tab's Schedule
 * section narrows it further, which is what the badge next to the button
 * reports — otherwise "Unpublish" would be the only signal on a form no
 * visitor can currently open.
 */
export function PublishToggle({ resource }: PublishToggleProps): JSX.Element {
  const [publishedAt, setPublishedAt] = useNumber(
    resource,
    forms.properties.formPublishedAt,
    { commit: true },
  );
  const [openAt] = useNumber(resource, forms.properties.formOpenAt);
  const [closeAt] = useNumber(resource, forms.properties.formCloseAt);

  const isPublished = publishedAt !== undefined;
  const availability = getFormAvailability({ publishedAt, openAt, closeAt });

  return (
    <Row gap='0.5rem' center>
      {availability.state === 'not-yet-open' && (
        <Badge title={`Opens ${formatScheduleMoment(availability.opensAt)}`}>
          Scheduled
        </Badge>
      )}
      {availability.state === 'closed' && (
        <Badge title={`Closed ${formatScheduleMoment(availability.closedAt)}`}>
          Closed
        </Badge>
      )}
      <Button
        type='button'
        subtle={!isPublished}
        onClick={() => setPublishedAt(isPublished ? undefined : Date.now())}
      >
        {isPublished ? 'Unpublish' : 'Publish'}
      </Button>
    </Row>
  );
}

const Badge = styled.span`
  padding: 0.15rem 0.5rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
`;
