import { useEffect, useState } from 'react';
import {
  findSchema,
  pluginSchema,
  pluginWorkspace,
  useStore,
} from '@tomic/react';
import { Card } from '@components/Card';
import { Column, Row } from '@components/Row';
import { AtomicLink } from '@components/AtomicLink';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

export function ConnectedIntegration({
  subject,
  drive,
}: {
  subject: string;
  drive: string;
}) {
  const store = useStore();
  const [workspace, setWorkspace] = useState<string>();
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;

    const load = async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const resource = await store.getResource(subject);
      if (resource.error) throw resource.error;
      const value = pluginWorkspace(resource, schema.properties ?? {});

      if (active) {
        setWorkspace(value);
        setError('');
      }
    };

    const refresh = () => {
      void load().catch(e => {
        if (active) setError(String(e));
      });
    };

    refresh();
    const unsubscribe = store.subscribe(subject, refresh);

    return () => {
      active = false;
      unsubscribe();
    };
  }, [store, drive, subject]);

  return (
    <Card data-connection={subject}>
      <Column gap='0.75rem'>
        <ResourceInline subject={subject} />
        <Row gap='1rem'>
          {workspace && (
            <AtomicLink subject={workspace}>Open workspace</AtomicLink>
          )}
          <AtomicLink subject={subject}>Connection settings</AtomicLink>
        </Row>
        {error && <p role='alert'>{error}</p>}
      </Column>
    </Card>
  );
}
