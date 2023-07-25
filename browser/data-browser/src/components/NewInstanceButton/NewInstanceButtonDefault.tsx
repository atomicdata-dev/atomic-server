import React from 'react';
import { useResource, useTitle } from '@tomic/react';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { Base } from './Base';
import { useDefaultNewInstanceHandler } from './useDefaultNewInstanceHandler';

/** Default handler for the new Instance button. DO NOT USE DIRECTLY. */
export function NewInstanceButtonDefault({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
  className,
}: NewInstanceButtonProps): JSX.Element {
  const classResource = useResource(klass);
  const [title] = useTitle(classResource);

  const onClick = useDefaultNewInstanceHandler(klass, parent);

  return (
    <Base
      className={className}
      onClick={onClick}
      IconComponent={IconComponent}
      title={title}
      icon={icon}
      subtle={subtle}
      label={label}
    >
      {children}
    </Base>
  );
}
