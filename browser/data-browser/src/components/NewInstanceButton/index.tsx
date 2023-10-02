import { classes } from '@tomic/react';
import React from 'react';
import { NewBookmarkButton } from './NewBookmarkButton';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { NewInstanceButtonDefault } from './NewInstanceButtonDefault';
import { useSettings } from '../../helpers/AppSettings';
import { NewTableButton } from './NewTableButton';
import { NewOntologyButton } from './NewOntologyButton';

type InstanceButton = (props: NewInstanceButtonProps) => JSX.Element;

/** If your New Instance button requires custom logic, such as a custom dialog */
const classMap = new Map<string, InstanceButton>([
  [classes.bookmark, NewBookmarkButton],
  [classes.table, NewTableButton],
  [classes.ontology, NewOntologyButton],
]);

/** A button for creating a new instance of some thing */
export default function NewInstanceButton(
  props: NewInstanceButtonProps,
): JSX.Element {
  const { klass, parent } = props;
  const { drive } = useSettings();

  const Comp = classMap.get(klass) ?? NewInstanceButtonDefault;

  return <Comp {...props} parent={parent ?? drive} />;
}

export { useDefaultNewInstanceHandler } from './useDefaultNewInstanceHandler';
export { useCreateAndNavigate } from './useCreateAndNavigate';
