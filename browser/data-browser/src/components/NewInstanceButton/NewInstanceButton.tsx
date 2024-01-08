import { useResource } from '@tomic/react';

import { useSettings } from '../../helpers/AppSettings';
import { useNewResourceUI } from '../forms/NewForm/useNewResourceUI';
import { Base } from './Base';
import { IconType } from 'react-icons';

interface NewInstanceButtonProps {
  /** URL of the Class to be instantiated */
  klass: string;
  subtle?: boolean;
  icon?: boolean;
  IconComponent?: IconType;
  /** subject of the parent Resource, which will be passed to the form */
  parent?: string;
  /** Give explicit label. If missing, uses the Shortname of the Class */
  label?: string;
  className?: string;
}

/** A button for creating a new instance of some thing */
export function NewInstanceButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
  className,
}: React.PropsWithChildren<NewInstanceButtonProps>): JSX.Element {
  const { drive } = useSettings();
  const classResource = useResource(klass);
  const showNewResourceUI = useNewResourceUI();

  const onClick = () => {
    showNewResourceUI(klass, parent ?? drive);
  };

  return (
    <Base
      className={className}
      onClick={onClick}
      IconComponent={IconComponent}
      title={classResource.title}
      icon={icon}
      subtle={subtle}
      label={label}
    >
      {children}
    </Base>
  );
}
