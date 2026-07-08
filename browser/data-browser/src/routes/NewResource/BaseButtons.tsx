import { ai, canvas, core, dataBrowser, forms } from '@tomic/react';
import { OutlinedSection } from '../../components/OutlinedSection';
import { ClassButton } from './ClassButton';

import type { JSX } from 'react';
import { useAISettings } from '@components/AI/AISettingsContext';

interface BaseButtonsProps {
  parent: string;
}

const buttons = [
  dataBrowser.classes.table,
  dataBrowser.classes.dashboard,
  dataBrowser.classes.folder,
  dataBrowser.classes.documentV2,
  dataBrowser.classes.meeting,
  dataBrowser.classes.chatroom,
  dataBrowser.classes.bookmark,
  canvas.classes.canvas,
  core.classes.ontology,
  forms.classes.form,
];

export function BaseButtons({ parent }: BaseButtonsProps): JSX.Element {
  const { enableAI } = useAISettings();
  const filteredButtons = enableAI ? [...buttons, ai.classes.aiChat] : buttons;

  return (
    <OutlinedSection extraPadding title='Base classes'>
      {filteredButtons.map(classType => (
        <ClassButton key={classType} classType={classType} parent={parent} />
      ))}
    </OutlinedSection>
  );
}
