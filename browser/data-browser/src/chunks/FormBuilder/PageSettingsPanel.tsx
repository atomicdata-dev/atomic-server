import { core, useProperty, useResource, type Resource } from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import Field from '@components/forms/Field';
import InputSwitcher from '@components/forms/InputSwitcher';
import { Column } from '@components/Row';
import { ConditionsEditor } from './ConditionsEditor';

interface PageSettingsPanelProps {
  pageSubject: string;
  form: Resource;
}

/** Shown in the builder's right pane when a page is selected but no field is. */
export function PageSettingsPanel({
  pageSubject,
  form,
}: PageSettingsPanelProps): JSX.Element {
  const page = useResource(pageSubject);
  const nameProp = useProperty(core.properties.name);

  return (
    <Panel>
      <Field label='Name' required>
        <InputSwitcher
          commit
          resource={page}
          property={nameProp}
          required
          data-testid='page-name-input'
        />
      </Field>
      <ConditionsEditor resource={page} form={form} beforePage={pageSubject} />
    </Panel>
  );
}

const Panel = styled(Column)`
  gap: 0.75rem;
`;
