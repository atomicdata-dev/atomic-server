import {
  dataBrowser,
  urls,
  useResource,
  useString,
  type Resource,
} from '@tomic/react';
import React, { useEffect, useRef } from 'react';
import { styled, css } from 'styled-components';
import { getIconForClass } from '../../../views/FolderPage/iconMap';

interface ResultLineProps {
  selected: boolean;
  onMouseOver: () => void;
  onClick: () => void;
}

interface ResourceResultLineProps extends ResultLineProps {
  subject: string;
}

export function ResultLine({
  selected,
  children,
  onMouseOver,
  onClick,
}: React.PropsWithChildren<ResultLineProps>): JSX.Element {
  const ref = useRef<HTMLLIElement>(null);

  useEffect(() => {
    if (selected) {
      ref.current?.scrollIntoView({ block: 'nearest' });
    }
  }, [selected]);

  return (
    <ListItem
      selected={selected}
      ref={ref}
      tabIndex={-1}
      onMouseMove={() => onMouseOver()}
      onClick={onClick}
    >
      {children}
    </ListItem>
  );
}

export function ResourceResultLine({
  subject,
  ...props
}: ResourceResultLineProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, urls.properties.description);

  return (
    <ResultLine {...props}>
      <Icon resource={resource} />
      {resource.title}
      {description && <Description> - {description.slice(0, 70)}</Description>}
    </ResultLine>
  );
}

type IconProps = {
  resource: Resource;
};

function Icon({ resource }: IconProps): React.ReactElement {
  const IconComp = getIconForClass(resource.getClasses()[0] ?? '');

  if (resource.hasClasses(dataBrowser.classes.tag)) {
    const emoji = resource.get(dataBrowser.properties.emoji);

    return emoji ? <span>{emoji}</span> : <IconComp />;
  }

  return <IconComp />;
}

const Description = styled.span`
  white-space: nowrap;
  color: ${({ theme }) => theme.colors.textLight};
`;

export const ListItem = styled.li<{ selected: boolean }>`
  padding: 0.5rem;
  list-style: none;
  margin: 0;
  padding-left: ${({ theme }) => theme.margin}rem;
  border-bottom: 1px solid ${({ theme }) => theme.colors.bg2};
  min-width: 100%;
  width: 100%;
  text-overflow: ellipsis;
  white-space: nowrap;
  overflow: hidden;
  display: flex;
  align-items: center;
  gap: 0.7ch;

  cursor: pointer;

  ${p =>
    p.selected &&
    css`
      box-shadow: inset 0 0 0px 1px ${({ theme }) => theme.colors.main};
      color: ${({ theme }) => theme.colors.main};
    `}

  svg {
    color: ${({ selected, theme }) =>
      selected ? theme.colors.main : theme.colors.textLight};
    min-width: 1rem;
    height: 1rem;
  }
`;
