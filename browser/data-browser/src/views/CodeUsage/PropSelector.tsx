import { useResource, type Core, useResources } from '@tomic/react';
import { useMemo } from 'react';
import { BasicSelect } from '../../components/forms/BasicSelect';

interface PropSelectorProps {
  classSubject: string;
  onPropSelect: (prop: string) => void;
}

export function PropSelector({
  classSubject,
  onPropSelect,
}: PropSelectorProps): React.JSX.Element {
  const classResource = useResource<Core.Class>(classSubject);
  const allProps = useMemo(
    () => [
      ...(classResource.props.requires ?? []),
      ...(classResource.props.recommends ?? []),
    ],
    [classResource.props.requires, classResource.props.recommends],
  );
  const props = useResources(allProps);

  return (
    <BasicSelect onChange={e => onPropSelect(e.target.value)} defaultValue={''}>
      <option value=''>None</option>
      <hr />
      {Array.from(props.entries()).map(([prop, propResource]) => (
        <option key={prop} value={prop}>
          {propResource.title}
        </option>
      ))}
    </BasicSelect>
  );
}
