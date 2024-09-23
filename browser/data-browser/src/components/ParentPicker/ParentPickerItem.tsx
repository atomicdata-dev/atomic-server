import {
  core,
  dataBrowser,
  Resource,
  server,
  useArray,
  useCollection,
  useResource,
  useStore,
} from '@tomic/react';
import { Details } from '../Details';
import { useEffect, useState } from 'react';
import { getIconForClass } from '../../helpers/iconMap';
import { styled } from 'styled-components';

const shouldBeRendered = (resource: Resource) =>
  resource.hasClasses(dataBrowser.classes.folder) ||
  resource.hasClasses(server.classes.drive);

interface ParentPickerItemProps {
  subject: string;
  selectedValue: string | undefined;
  inialOpen?: boolean;
  onClick: (subject: string) => void;
}

export const ParentPickerItem: React.FC<ParentPickerItemProps> = ({
  subject,
  ...props
}) => {
  const resource = useResource(subject);

  if (
    !resource.hasClasses(dataBrowser.classes.folder) &&
    !resource.hasClasses(server.classes.drive)
  ) {
    return null;
  }

  return <InnerItem subject={subject} {...props} />;
};

const InnerItem = ({
  subject,
  selectedValue,
  inialOpen,
  onClick,
}: ParentPickerItemProps) => {
  const store = useStore();
  const { collection } = useCollection({
    property: core.properties.parent,
    value: subject,
  });

  const [children, setChildren] = useState<string[]>([]);

  useEffect(() => {
    collection.getAllMembers().then(async (members: string[]) => {
      const resources = await Promise.all(
        members.map(s => store.getResource(s)),
      );
      const filtered = resources.filter(shouldBeRendered);

      setChildren(filtered.map(r => r.subject));
    });
  }, [collection]);

  if (children.length === 0) {
    return (
      <Title
        indented
        subject={subject}
        onClick={onClick}
        selected={selectedValue === subject}
      />
    );
  }

  return (
    <Details
      initialState={inialOpen}
      open={inialOpen}
      title={
        <Title
          subject={subject}
          selected={selectedValue === subject}
          onClick={onClick}
        />
      }
    >
      {children.map(child => (
        <ParentPickerItem
          key={child}
          subject={child}
          selectedValue={selectedValue}
          onClick={onClick}
        />
      ))}
    </Details>
  );
};

interface TitleProps extends Omit<ParentPickerItemProps, 'selectedValue'> {
  indented?: boolean;
  selected?: boolean;
}

const Title = ({
  subject,
  indented,
  selected,
  onClick,
}: TitleProps): React.JSX.Element => {
  const resource = useResource(subject);
  const [isA] = useArray(resource, core.properties.isA);

  const Icon = getIconForClass(isA[0]);

  return (
    <FolderButton
      selected={selected}
      indented={indented}
      onClick={() => onClick(subject)}
    >
      <Icon />
      {resource.title}
    </FolderButton>
  );
};

const FolderButton = styled.button<{ indented?: boolean; selected?: boolean }>`
  display: flex;
  align-items: center;
  gap: 1ch;
  background-color: ${p => (p.selected ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => (p.selected ? p.theme.colors.main : p.theme.colors.textLight)};
  cursor: pointer;
  border: none;
  padding: 0.3rem 0.5rem;
  margin-inline-start: ${p => (p.indented ? '2rem' : '0')};
  border-radius: ${p => p.theme.radius};
  user-select: none;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
    color: ${p => (p.selected ? p.theme.colors.main : p.theme.colors.text)};
  }
`;
