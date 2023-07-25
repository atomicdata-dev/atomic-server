import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useString, useResource, useTitle, urls, useArray } from '@tomic/react';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import { SideBarItem } from '../SideBarItem';
import { AtomicLink } from '../../AtomicLink';
import styled from 'styled-components';
import { Details } from '../../Details';
import { FloatingActions, floatingHoverStyles } from './FloatingActions';
import { ErrorLook } from '../../ErrorLook';
import { LoaderInline } from '../../Loader';
import { getIconForClass } from '../../../views/FolderPage/iconMap';

interface ResourceSideBarProps {
  subject: string;
  ancestry: string[];
  /** When a SideBar item is clicked, we should close the SideBar (on mobile devices) */
  handleClose?: () => unknown;
}

/** Renders a Resource as a nav item for in the sidebar. */
export function ResourceSideBar({
  subject,
  ancestry,
  handleClose,
}: ResourceSideBarProps): JSX.Element {
  const spanRef = useRef<HTMLSpanElement>(null);
  const resource = useResource(subject, { allowIncomplete: true });
  const [currentUrl] = useCurrentSubject();

  const [title] = useTitle(resource);
  const [description] = useString(resource, urls.properties.description);

  const active = currentUrl === subject;
  const [open, setOpen] = useState(active);

  const [subResources] = useArray(resource, urls.properties.subResources);
  const hasSubResources = subResources.length > 0;

  const [classType] = useString(resource, urls.properties.isA);
  const Icon = getIconForClass(classType!);

  useEffect(() => {
    if (ancestry.includes(subject) && ancestry[0] !== subject) {
      setOpen(true);
    }
  }, [ancestry]);

  const TitleComp = useMemo(
    () => (
      <ActionWrapper>
        <Title subject={subject} clean active={active}>
          <SideBarItem
            onClick={handleClose}
            disabled={active}
            resource={subject}
            title={description}
            ref={spanRef}
          >
            <TextWrapper>
              <Icon />
              {title}
            </TextWrapper>
          </SideBarItem>
        </Title>
        <FloatingActions subject={subject} />
      </ActionWrapper>
    ),
    [subject, active, handleClose, description, title],
  );

  if (resource.loading) {
    return (
      <SideBarItem
        onClick={handleClose}
        disabled={active}
        resource={subject}
        title={`${subject} is loading...`}
      >
        <LoaderInline />
      </SideBarItem>
    );
  }

  if (resource.error) {
    return (
      <SideBarItem
        onClick={handleClose}
        disabled={active}
        resource={subject}
        ref={spanRef}
      >
        <ErrorLook about={subject} title={resource.error.message}>
          {subject}
        </ErrorLook>
      </SideBarItem>
    );
  }

  return (
    <Details
      initialState={open}
      open={open}
      disabled={!hasSubResources}
      onStateToggle={setOpen}
      data-test='resource-sidebar'
      title={TitleComp}
    >
      {hasSubResources &&
        subResources.map(child => (
          <ResourceSideBar subject={child} key={child} ancestry={ancestry} />
        ))}
    </Details>
  );
}

const ActionWrapper = styled.div`
  position: relative;
  display: flex;
  width: 100%;
  margin-left: -0.7rem;
  ${floatingHoverStyles}
`;

interface TitleProps {
  active: boolean;
}

const Title = styled(AtomicLink)<TitleProps>`
  flex: 1;
  overflow: hidden;
  white-space: nowrap;
`;

const TextWrapper = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;

  svg {
    /* color: ${p => p.theme.colors.text}; */
    font-size: 0.8em;
  }
`;
