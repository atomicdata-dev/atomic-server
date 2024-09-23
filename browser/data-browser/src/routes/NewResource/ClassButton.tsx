import { useResource, useTitle } from '@tomic/react';
import { getIconForClass } from '../../helpers/iconMap';
import { NewInstanceButton } from '../../components/NewInstanceButton';

interface ClassButtonProps {
  classType: string;
  parent: string;
}

export function ClassButton({
  classType,
  parent,
}: ClassButtonProps): JSX.Element {
  const classResource = useResource(classType);
  const [label] = useTitle(classResource);

  return (
    <NewInstanceButton
      icon
      IconComponent={getIconForClass(classType)}
      klass={classType}
      parent={parent}
      label={label}
      subtle
    />
  );
}
