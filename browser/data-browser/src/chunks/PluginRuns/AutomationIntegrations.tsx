import { useEffect, useState } from 'react';
import {
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  useStore,
} from '@tomic/react';
import { Column } from '@components/Row';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

/** Explicit references, independent of either resource's containment parent. */
export function AutomationIntegrations({
  drive,
  subject,
  inverse = false,
}: {
  drive: string;
  subject: string;
  inverse?: boolean;
}) {
  const store = useStore();
  const [subjects, setSubjects] = useState<string[]>([]);
  useEffect(() => {
    let active = true;

    const load = async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const property = schema.properties?.['automation-integrations'];
      if (!property) return;
      const linked = inverse
        ? await readConnectionSubjects(store, drive, property, subject)
        : (await store.getResource(subject)).get(property);
      if (active)
        setSubjects(Array.isArray(linked) ? (linked as string[]) : []);
    };

    void load().catch(() => {
      if (active) setSubjects([]);
    });

    return () => {
      active = false;
    };
  }, [store, drive, subject, inverse]);
  if (!subjects.length) return null;

  return (
    <Column gap='0.5rem'>
      <h3>
        {inverse ? 'Automations using this integration' : 'Uses integrations'}
      </h3>
      {subjects.map(link => (
        <ResourceInline key={link} subject={link} />
      ))}
    </Column>
  );
}
