import { useEffect, useState } from 'react';
import {
  core,
  useStore,
  useString,
  useValue,
  type Resource,
} from '@tomic/react';
import { ImportReferences } from './ImportReferences';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

export function ImportResolutionNotice({ resource }: { resource: Resource }) {
  const store = useStore();
  const [localId] = useString(resource, core.properties.localId);
  const [parent] = useString(resource, core.properties.parent);
  const [primary, setPrimary] = useState('');
  const [review] = useValue(resource, core.properties.importResolution);
  const marker = review as
    | { canonical?: string; members?: Record<string, unknown> }
    | undefined;
  const drive = store.getDrive();
  useEffect(() => {
    let cancelled = false;
    setPrimary('');

    if (localId && parent && drive) {
      store
        .findByLocalId(drive, parent, localId)
        .then(found => {
          if (
            !cancelled &&
            found &&
            found.subject.split('?')[0] !== resource.subject.split('?')[0]
          )
            setPrimary(found.subject);
        })
        .catch(() => {
          /* An unresolved group has no redirect. */
        });
    }

    return () => {
      cancelled = true;
    };
  }, [store, drive, localId, parent, resource.subject]);

  if (marker?.canonical === resource.subject.split('?')[0] && marker.members) {
    return (
      <details>
        <summary>Review links to original copies</summary>
        <ImportReferences
          primary={resource.subject}
          copies={Object.keys(marker.members)}
        />
      </details>
    );
  }

  if (!primary) return null;

  return (
    <p role='note'>
      This original copy is kept for its history and existing links. Future
      imports update <ResourceInline subject={primary} />.
    </p>
  );
}
