import { forms, Resource, useNumber } from '@tomic/react';
import type { JSX } from 'react';
import { Button } from '@components/Button';

interface PublishToggleProps {
  resource: Resource;
}

/**
 * UI-only in Phase 2: writes/clears `form-published-at` but nothing reads it
 * yet (no `/form/:id` route, no submit endpoint) — the runtime that enforces
 * this lands in Phase 3/4.
 */
export function PublishToggle({ resource }: PublishToggleProps): JSX.Element {
  const [publishedAt, setPublishedAt] = useNumber(
    resource,
    forms.properties.formPublishedAt,
    { commit: true },
  );

  const isPublished = publishedAt !== undefined;

  return (
    <Button
      type='button'
      subtle={!isPublished}
      onClick={() => setPublishedAt(isPublished ? undefined : Date.now())}
    >
      {isPublished ? 'Unpublish' : 'Publish'}
    </Button>
  );
}
