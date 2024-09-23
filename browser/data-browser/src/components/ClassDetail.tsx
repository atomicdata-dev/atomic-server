import React from 'react';
import { Resource, useResource } from '@tomic/react';
import { Detail } from './Detail';
import { getIconForClass } from '../helpers/iconMap';
import { InlineFormattedResourceList } from './InlineFormattedResourceList';
import { AtomicLink } from './AtomicLink';

type ClassDetailProps = {
  resource: Resource;
};

/** Renders the is-a Class for some resource */
export const ClassDetail: React.FC<ClassDetailProps> = ({ resource }) => {
  if (resource.getClasses().length === 0) {
    return null;
  }

  return (
    <Detail>
      <InlineFormattedResourceList
        subjects={resource.getClasses()}
        RenderComp={ClassItem}
      />
    </Detail>
  );
};

interface ClassItemProps {
  subject: string;
}

const ClassItem = ({ subject }: ClassItemProps): JSX.Element => {
  const classResource = useResource(subject);
  const Icon = getIconForClass(subject);

  return (
    <Detail>
      <Icon />
      <AtomicLink subject={subject}>{classResource.title}</AtomicLink>
    </Detail>
  );
};
