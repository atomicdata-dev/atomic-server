import { Resource, useCanWrite, useTitle } from '@tomic/react';
import React, { useEffect, useRef, useState } from 'react';
import { useHotkeys } from 'react-hotkeys-hook';
import { FaEdit } from 'react-icons/fa';
import styled, { css } from 'styled-components';
import { transitionName } from '../helpers/transitionName';
import { ViewTransitionProps } from '../helpers/ViewTransitionProps';

export interface EditableTitleProps {
  resource: Resource;
  /** Uses `name` by default */
  parentRef?: React.RefObject<HTMLInputElement>;
  id?: string;
  className?: string;
}

const opts = {
  commit: true,
  validate: false,
};

export function EditableTitle({
  resource,
  parentRef,
  id,
  className,
  ...props
}: EditableTitleProps): JSX.Element {
  const [text, setText] = useTitle(resource, Infinity, opts);
  const [isEditing, setIsEditing] = useState(false);
  const innerRef = useRef<HTMLInputElement>(null);
  const ref = parentRef || innerRef;

  const [canEdit] = useCanWrite(resource);

  useHotkeys(
    'enter',
    () => {
      setIsEditing(false);
    },
    { enableOnTags: ['INPUT'] },
  );

  useHotkeys(
    'esc',
    () => {
      setIsEditing(false);
    },
    { enableOnTags: ['INPUT'] },
  );

  function handleClick() {
    setIsEditing(true);
  }

  const placeholder = canEdit ? 'set a title' : 'Untitled';

  useEffect(() => {
    ref.current?.focus();
    ref.current?.select();
  }, [isEditing]);

  return canEdit && isEditing ? (
    <TitleInput
      ref={ref}
      data-test='editable-title'
      {...props}
      onFocus={handleClick}
      placeholder={placeholder}
      onChange={e => setText(e.target.value)}
      value={text || ''}
      onBlur={() => setIsEditing(false)}
      className={className}
    />
  ) : (
    <Title
      id={id}
      canEdit={!!canEdit}
      title={canEdit ? 'Edit title' : 'View title'}
      data-test='editable-title'
      onClick={handleClick}
      subtle={!!canEdit && !text}
      subject={resource.getSubject()}
      className={className}
    >
      <>
        {text || placeholder}
        {canEdit && <Icon />}
      </>
    </Title>
  );
}

const TitleShared = css`
  line-height: 1.1;
`;

interface TitleProps {
  subtle: boolean;
  canEdit: boolean;
}

const Title = styled.h1<TitleProps & ViewTransitionProps>`
  ${TitleShared}
  display: flex;
  align-items: center;
  gap: ${p => p.theme.margin}rem;
  justify-content: space-between;
  cursor: pointer;
  cursor: ${props => (props.canEdit ? 'pointer' : 'initial')};
  opacity: ${props => (props.subtle ? 0.5 : 1)};

  ${props => transitionName('page-title', props.subject)};
`;

const TitleInput = styled.input`
  ${TitleShared}
  margin-bottom: ${props => props.theme.margin}rem;
  font-size: ${p => p.theme.fontSizeH1}rem;
  color: ${p => p.theme.colors.text};
  border: none;
  font-weight: bold;
  display: block;
  padding: 0;
  margin-top: 0;
  outline: none;
  background-color: transparent;
  margin-bottom: ${p => p.theme.margin}rem;
  font-family: ${p => p.theme.fontFamilyHeader};
  word-wrap: break-word;
  word-break: break-all;
  overflow: visible;

  &:focus {
    outline: none;
  }
`;

const Icon = styled(FaEdit)`
  opacity: 0;
  font-size: 0.8em;
  ${Title}:hover & {
    opacity: 0.5;

    &:hover {
      opacity: 1;
    }
  }
`;
