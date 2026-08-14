import { useResource, type Resource } from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { Column } from '@components/Row';
import { ConditionsEditor } from './ConditionsEditor';

interface PageSettingsPanelProps {
  pageSubject: string;
  form: Resource;
}

/** Shown in the builder's right pane when a page is selected but no field is.
 * Page title is edited in-place on the tab; this pane is for visibility. */
export function PageSettingsPanel({
  pageSubject,
  form,
}: PageSettingsPanelProps): JSX.Element {
  const page = useResource(pageSubject);

  return (
    <Panel>
      <ConditionsEditor resource={page} form={form} beforePage={pageSubject} />
    </Panel>
  );
}

const Panel = styled(Column)`
  gap: 0.75rem;
`;
