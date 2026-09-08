import {
  dataBrowser,
  useResource,
  useCanWrite,
  useArray,
  useString,
  useTitle,
} from '@tomic/react';
import { TableResource } from '@chunks/TablePage/TableResource';
import { Column } from '@components/Row';
import { BasicSelect as Select } from '@components/forms/BasicSelect';
import { useState } from 'react';

export function IntegrationDataView({ subject }: { subject: string }) {
  const resource = useResource(subject);
  if (resource.error) return <p role='alert'>{resource.error.message}</p>;
  if (resource.loading) return <p>Loading your data…</p>;

  return <TableResource resource={resource} />;
}

export function IntegrationDefaultView({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);
  const [views] = useArray(resource, dataBrowser.properties.tableViews);
  const [value] = useString(resource, dataBrowser.properties.tableDefaultView);
  const [error, setError] = useState('');

  return (
    <Column gap='0.5rem'>
      <label htmlFor='integration-default-view'>Opening view</label>
      <Select
        id='integration-default-view'
        value={value || views[0] || ''}
        disabled={!canWrite}
        onChange={async e => {
          try {
            await resource.set(
              dataBrowser.properties.tableDefaultView,
              e.target.value,
            );
            await resource.save();
            setError('');
          } catch (err) {
            setError(String(err));
          }
        }}
      >
        {views.map(view => (
          <ViewOption key={view} subject={view} />
        ))}
      </Select>
      <p>
        Choose which view opens when you visit this integration or its table.
      </p>
      {error && <p role='alert'>{error}</p>}
    </Column>
  );
}

function ViewOption({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return <option value={subject}>{title}</option>;
}
