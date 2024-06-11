import {
  core,
  dataBrowser,
  useResource,
  useStore,
  type Resource,
} from '@tomic/react';
import { useMemo, useState } from 'react';
import { Checkbox, CheckboxLabel } from '../../components/forms/Checkbox';
import { Column } from '../../components/Row';
import { CodeUsage } from './CodeUsage';
import { PropSelector } from './PropSelector';
import { BasicCodeGenerator } from './generators/BasicCodeGenerator';
import { TableCodeGenerator } from './generators/TableCodeGenerator';
import type { CodeGenerator } from './generators/CodeGenerator';

export interface CodeUsageSharedProps {
  resource: Resource;
}

interface ResourceCodeUsageProps {
  subject: string;
}

export function ResourceCodeUsage({
  subject,
}: ResourceCodeUsageProps): React.JSX.Element {
  const store = useStore();
  const resource = useResource(subject);
  const [selectedProp, setSelectedProp] = useState<string>();
  const [typescriptEnabled, setTypescriptEnabled] = useState(true);

  const generator = useMemo(
    () =>
      resource.matchClass<CodeGenerator>(
        {
          [dataBrowser.classes.table]: new TableCodeGenerator(store, resource),
        },
        new BasicCodeGenerator(store, resource),
      ),
    [store, resource],
  );

  const classSubject = resource.matchClass(
    {
      [dataBrowser.classes.table]: resource.get(core.properties.classtype),
    },
    resource.getClasses()[0],
  ) as string;

  return (
    <Column fullHeight>
      <Column wrapItems as='label'>
        Read a property:
        <PropSelector
          classSubject={classSubject}
          onPropSelect={setSelectedProp}
        />
      </Column>
      <CheckboxLabel>
        <Checkbox onChange={setTypescriptEnabled} checked={typescriptEnabled} />
        Typescript
      </CheckboxLabel>
      <CodeUsage
        generator={generator}
        property={selectedProp}
        ts={typescriptEnabled}
      />
    </Column>
  );
}
