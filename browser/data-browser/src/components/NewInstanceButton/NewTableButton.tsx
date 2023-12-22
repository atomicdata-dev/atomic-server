import { dataBrowser, useResource } from '@tomic/react';
import { Base } from './Base';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { useNewResourceUI } from '../forms/NewForm/useNewResourceUI';
import { useSettings } from '../../helpers/AppSettings';

export function NewTableButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
}: NewInstanceButtonProps): JSX.Element {
  const classResource = useResource(klass);
  const { drive } = useSettings();
  const showNewResourceUI = useNewResourceUI();

  const show = () => {
    showNewResourceUI(dataBrowser.classes.table, parent ?? drive);
  };

  return (
    <>
      <Base
        onClick={show}
        title={classResource.title}
        icon={icon}
        IconComponent={IconComponent}
        subtle={subtle}
        label={label}
      >
        {children}
      </Base>
    </>
  );
}
