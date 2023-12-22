import { core, dataBrowser } from '@tomic/react';
import { ButtonSection } from './ButtonSection';
import { ClassButton } from './ClassButton';

interface BaseButtonsProps {
  parent: string;
}

const buttons = [
  dataBrowser.classes.table,
  dataBrowser.classes.folder,
  dataBrowser.classes.document,
  dataBrowser.classes.chatroom,
  dataBrowser.classes.bookmark,
  core.classes.ontology,
];

export function BaseButtons({ parent }: BaseButtonsProps): JSX.Element {
  return (
    <ButtonSection title='Base classes'>
      {buttons.map(classType => (
        <ClassButton key={classType} classType={classType} parent={parent} />
      ))}
    </ButtonSection>
  );
}
