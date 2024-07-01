import { urls, useResource, useString, useTitle } from '@tomic/react';
import { lighten, setLightness, setSaturation } from 'polished';
import * as RadixPopover from '@radix-ui/react-popover';
import { useCallback, useMemo, useState } from 'react';
import { styled } from 'styled-components';
import { transition } from '../../helpers/transition';
import { Popover } from '../Popover';
import { PalettePicker } from '../PalettePicker';
import { Button } from '../Button';
import { Column, Row } from '../Row';
import { FaTrash } from 'react-icons/fa';
import { fadeIn } from '../../helpers/commonAnimations';
import { tagColours } from './tagColours';

interface TagProps {
  subject: string;
}

const useTagData = (subject: string) => {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [color, setColor] = useString(resource, urls.properties.color, {
    commit: true,
  });
  const [emoji] = useString(resource, urls.properties.emoji);

  const text = emoji ? `${emoji} ${title}` : title;

  return useMemo(
    () => ({
      color: color ?? '#FFFFFF',
      setColor,
      text,
    }),
    [color, setColor, text],
  );
};

export function Tag({
  subject,
  children,
}: React.PropsWithChildren<TagProps>): JSX.Element {
  const { color, text } = useTagData(subject);

  return (
    <TagWrapper color={color}>
      {text}
      {children}
    </TagWrapper>
  );
}

interface TagWrapperProps {
  color: string;
}

const TagWrapper = styled.span<TagWrapperProps>`
  --tag-dark-color: ${props => setLightness(0.11, props.color)};
  --tag-mid-color: ${props => setLightness(0.4, props.color)};
  --tag-light-color: ${props =>
    setSaturation(0.5, setLightness(0.9, props.color))};
  display: inline-flex;
  gap: 1ch;
  align-items: center;
  padding-inline: 0.5em;
  padding-block: 0.4em;
  border-radius: 1em;
  border: 1px solid var(--tag-mid-color);
  color: ${p =>
    p.theme.darkMode ? 'var(--tag-light-color)' : 'var(--tag-dark-color)'};
  line-height: 1;
  text-align: center;
  min-width: 3rem;
  background-color: ${p =>
    p.theme.darkMode ? 'var(--tag-dark-color)' : 'var(--tag-light-color)'};

  &.selected-tag {
    text-decoration: underline;
  }
`;

interface SelectableTagProps extends TagProps {
  onClick: (subject: string) => void;
  selected: boolean;
}

export function SelectableTag({
  onClick,
  selected,
  subject,
}: SelectableTagProps): JSX.Element {
  const { color, text } = useTagData(subject);

  const handleClick: React.MouseEventHandler = useCallback(
    e => {
      e.preventDefault();
      e.stopPropagation();
      onClick(subject);
    },
    [onClick],
  );

  const className = selected ? 'selected-tag' : '';

  return (
    <TagWrapperButton
      color={color}
      as='button'
      onClick={handleClick}
      className={className}
      tabIndex={-1}
    >
      {text}
    </TagWrapperButton>
  );
}

interface EditableTagProps extends TagProps {
  onDelete: (subject: string) => void;
}

export function EditableTag({
  subject,
  onDelete,
}: EditableTagProps): JSX.Element {
  const { color, setColor, text } = useTagData(subject);
  const [open, setOpen] = useState(false);

  const handleColorChange = useCallback(
    (pickedColor: string) => {
      setColor(pickedColor);
      setOpen(false);
    },
    [setColor, setOpen],
  );

  return (
    <Popover
      modal
      open={open}
      onOpenChange={setOpen}
      Trigger={
        <TagWrapperButton color={color!} as={RadixPopover.Trigger}>
          {text}
        </TagWrapperButton>
      }
    >
      <PopoverContent>
        <Column>
          <PalettePicker palette={tagColours} onChange={handleColorChange} />
          <DeleteButton onClick={() => onDelete(subject)}>
            <Row gap='0.5rem'>
              <FaTrash />
              Delete
            </Row>
          </DeleteButton>
        </Column>
      </PopoverContent>
    </Popover>
  );
}

const TagWrapperButton = styled(TagWrapper)`
  cursor: pointer;
  user-select: none;

  transition: ${transition('filter', 'box-shadow')};
  animation: ${fadeIn} 0.2s ease-in-out;
  &:hover,
  &:focus,
  &.selected-tag {
    --shadow-color: ${({ theme }) =>
      theme.darkMode ? 'var(--dark-color)' : 'var(--light-color)'};
    filter: brightness(1.05);
    box-shadow: 0 1px 20px 0px var(--shadow-color);
  }
`;

const PopoverContent = styled.div`
  padding: 1rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};
  max-width: 20rem;
`;

const DeleteButton = styled(Button)`
  background-color: ${p => p.theme.colors.alert};
  border: none;

  &:hover,
  &:focus {
    background-color: ${p => lighten(0.1, p.theme.colors.alert)} !important;
  }
`;
