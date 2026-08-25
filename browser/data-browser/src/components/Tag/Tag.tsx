import { core, urls, useResource, useString, useTitle } from '@tomic/react';
import { lighten, setLightness, setSaturation, transparentize } from 'polished';
import * as RadixPopover from '@radix-ui/react-popover';
import { useCallback, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { transition } from '../../helpers/transition';
import { Popover } from '../Popover';
import { PalettePicker } from '../PalettePicker';
import { Button } from '../Button';
import { Column, Row } from '../Row';
import { FaTrash } from 'react-icons/fa6';
import { fadeIn } from '../../helpers/commonAnimations';
import { tagColours } from './tagColours';
import { InputStyled, InputWrapper } from '../forms/InputStyles';
import { stringToSlug } from '../../helpers/stringToSlug';
import { useDraftString } from '../../helpers/useDraftString';

interface TagProps {
  subject: string;
  selected?: boolean;
}

/** The tag's raw color + display text, for consumers that render their own
 *  UI around a tag instead of the pill (e.g. a kanban column header). */
export const useTagData = (subject: string) => {
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
  selected,
  children,
}: React.PropsWithChildren<TagProps>): JSX.Element {
  const { color, text } = useTagData(subject);
  const className = selected ? 'selected-tag' : '';

  return (
    <TagWrapper color={color} className={className}>
      {text}
      {children}
    </TagWrapper>
  );
}

interface TagWrapperProps {
  color: string;
}

const TagWrapper = styled.span<TagWrapperProps>`
  --tag-dark-color: ${p => setLightness(0.11, p.color)};
  --tag-mid-color: ${p => setLightness(0.4, p.color)};
  --tag-light-color: ${p => setSaturation(0.5, setLightness(0.9, p.color))};
  --tag-shadow-color: ${p =>
    transparentize(
      p.theme.darkMode ? 0.2 : 0.5,
      setLightness(p.theme.darkMode ? 0.7 : 0.4, p.color),
    )};
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
    box-shadow: 0 0px 10px 0px var(--tag-shadow-color);
  }
`;

interface SelectableTagProps extends TagProps {
  onClick: (subject: string) => void;
  selected: boolean;
}

export function TagButton({
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
    [onClick, subject],
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
          <TagNameInput subject={subject} />
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

/**
 * Renames the tag. Writes `name` (free text) and keeps `shortname` in step as
 * its slug — the class requires the slug, while `useTitle` displays the name.
 *
 * Renaming rather than replacing matters wherever the tag is referenced: every
 * resource pointing at it (a table cell, a submitted form answer) re-reads the
 * new label, instead of being stranded with a copy of the old text.
 */
function TagNameInput({ subject }: { subject: string }): JSX.Element {
  const resource = useResource(subject);
  const [name, setName] = useString(resource, core.properties.name, {
    commit: true,
  });
  const [, setShortname] = useString(resource, core.properties.shortname, {
    commit: true,
  });

  const commit = useCallback(
    (value: string) => {
      setName(value);
      setShortname(stringToSlug(value));
    },
    [setName, setShortname],
  );

  // Dismissing the popover unmounts this input, so the draft has to survive
  // that — see `useDraftString`.
  const draft = useDraftString(name, commit, subject);

  return (
    <InputWrapper>
      <InputStyled
        data-testid='tag-name-input'
        aria-label='Tag name'
        value={draft.value}
        onChange={e => draft.onChange(e.target.value)}
      />
    </InputWrapper>
  );
}

const TagWrapperButton = styled(TagWrapper)`
  cursor: pointer;
  user-select: none;

  transition: ${transition('filter', 'box-shadow', 'transform')};
  animation: ${fadeIn} 0.2s ease-in-out;
  &:hover,
  &:focus,
  &.selected-tag {
    --shadow-color: ${({ theme }) =>
      theme.darkMode ? 'var(--dark-color)' : 'var(--light-color)'};
    filter: brightness(1.05);
    transform: scale(1.1);
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
