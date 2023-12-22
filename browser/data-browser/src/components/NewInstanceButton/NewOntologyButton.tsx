import { core, useResource } from '@tomic/react';
import { Base } from './Base';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { useNewResourceUI } from '../forms/NewForm/useNewResourceUI';
import { useSettings } from '../../helpers/AppSettings';

export function NewOntologyButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
}: NewInstanceButtonProps): JSX.Element {
  const ontology = useResource(klass);
  const { drive } = useSettings();

  const showNewResourceUI = useNewResourceUI();

  const show = () => {
    showNewResourceUI(core.classes.ontology, parent ?? drive);
  };

  return (
    <Base
      onClick={show}
      title={ontology.title}
      icon={icon}
      IconComponent={IconComponent}
      subtle={subtle}
      label={label}
    >
      {children}
    </Base>
  );
}
