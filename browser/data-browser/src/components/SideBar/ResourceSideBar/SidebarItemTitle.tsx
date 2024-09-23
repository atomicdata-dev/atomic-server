import { forwardRef } from 'react';
import { styled, css, keyframes } from 'styled-components';
import { SideBarItem } from '../SideBarItem';
import { FloatingActions, floatingHoverStyles } from './FloatingActions';
import { getIconForClass } from '../../../helpers/iconMap';
import { useResource, useArray, core, useString } from '@tomic/react';
import { SyntheticListenerMap } from '@dnd-kit/core/dist/hooks/utilities';
import { DraggableAttributes } from '@dnd-kit/core';
import { StyledLink, TextWrapper } from './shared';
import {
  SIDEBAR_TRANSITION_TAG,
  getTransitionName,
} from '../../../helpers/transitionName';
import { useSettings } from '../../../helpers/AppSettings';
import { IconButton } from '../../IconButton/IconButton';
import { FaGripVertical } from 'react-icons/fa6';
import { UnsavedIndicator } from '../../UnsavedIndicator';

interface SidebarItemTitleProps {
  subject: string;
  active?: boolean;
  listeners?: SyntheticListenerMap;
  attributes?: DraggableAttributes;
  hideActionButtons?: boolean;
  isDragging?: boolean;
  onClick?: () => unknown;
}

export const SidebarItemTitle = forwardRef<
  HTMLAnchorElement,
  SidebarItemTitleProps
>(
  (
    {
      subject,
      active,
      listeners,
      attributes,
      hideActionButtons,
      isDragging,
      onClick,
    },
    ref,
  ): React.JSX.Element => {
    const resource = useResource(subject);
    const { sidebarKeyboardDndEnabled } = useSettings();
    const [classType] = useArray(resource, core.properties.isA);
    const [description] = useString(resource, core.properties.description);
    const Icon = getIconForClass(classType[0]!);

    return (
      <ActionWrapper
        isDragging={isDragging}
        data-sidebar-id={getTransitionName(SIDEBAR_TRANSITION_TAG, subject)}
      >
        {sidebarKeyboardDndEnabled ? (
          <StyledLink subject={subject} clean ref={ref}>
            <SideBarItem
              onClick={onClick}
              disabled={active}
              resource={subject}
              title={description}
            >
              <TextWrapper>
                <StyledIconButton
                  title={`Rearange ${resource.title}`}
                  {...(listeners ?? {})}
                  {...(attributes ?? {})}
                >
                  <Icon />
                  <FaGripVertical />
                </StyledIconButton>
                {resource.title}
                <UnsavedIndicator resource={resource} />
              </TextWrapper>
            </SideBarItem>
          </StyledLink>
        ) : (
          <StyledLink
            subject={subject}
            clean
            ref={ref}
            {...(listeners ?? {})}
            {...(attributes ?? {})}
          >
            <SideBarItem
              onClick={onClick}
              disabled={active}
              resource={subject}
              title={description}
            >
              <TextWrapper>
                <Icon />
                {resource.title}
                <UnsavedIndicator resource={resource} />
              </TextWrapper>
            </SideBarItem>
          </StyledLink>
        )}
        {!hideActionButtons && <FloatingActions subject={subject} />}
      </ActionWrapper>
    );
  },
);

SidebarItemTitle.displayName = 'SidebarItemTitle';

const lift = keyframes`
  from {
    box-shadow: var(--aw-box-shadow-start);
    scale: 0.9;
  } to {
    box-shadow: var(--aw-box-shadow-end);
    scale: 1;
  }
`;

const StyledIconButton = styled(IconButton)`
  --button-padding: 0;
`;

const ActionWrapper = styled.div<{ isDragging?: boolean }>`
  --aw-box-shadow-start: 0 0 0 0px rgba(0, 0, 0, 0.1);
  --aw-box-shadow-end: 0 0 0 1px ${p => p.theme.colors.main},
    ${p => p.theme.boxShadowSoft};

  display: flex;
  width: 100%;
  margin-left: -0.7rem;
  ${floatingHoverStyles}
  border-radius: ${p => p.theme.radius};
  ${p =>
    p.isDragging &&
    css`
      animation: ${lift} 0.2s ease-in-out forwards;
      opacity: 0.9;
    `}

  ${StyledIconButton} svg:last-of-type {
    display: none;
    visibility: hidden;
  }

  &:focus-within,
  &:hover {
    ${StyledIconButton} svg:first-of-type {
      display: none;
      visibility: hidden;
    }
    ${StyledIconButton} svg:last-of-type {
      display: block;
      visibility: visible;
      cursor: grab;
    }
  }
`;
