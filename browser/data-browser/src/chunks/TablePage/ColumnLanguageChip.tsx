import { useContext, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaCheck, FaLanguage, FaTableColumns } from 'react-icons/fa6';
import { DropdownMenu, type DropdownItem } from '@components/Dropdown';
import type {
  DropdownTriggerComponent,
  DropdownTriggerProps,
} from '@components/Dropdown/DropdownTrigger';
import { EditLanguagesDialog } from '@components/EditLanguagesDialog';
import { useSettings } from '../../helpers/AppSettings';
import { useDeclaredLanguages } from '../../hooks/useDeclaredLanguages';
import { TablePageContext } from './tablePageContext';

interface ColumnLanguageChipProps {
  propertySubject: string;
  /** Set on a split column: the fixed language this column shows. */
  languageTag?: string;
}

/**
 * The language badge in a LocalizedText column header — makes the language
 * the column is showing visible at a glance. Clicking it opens the language
 * controls: switch the content language, split/unsplit per-language columns,
 * and edit the drive's declared language set.
 */
export function ColumnLanguageChip({
  propertySubject,
  languageTag,
}: ColumnLanguageChipProps): JSX.Element {
  const { contentLanguage, setContentLanguage } = useSettings();
  const declared = useDeclaredLanguages();
  const { splitLanguageSubjects, toggleSplitLanguages } =
    useContext(TablePageContext);
  const [showLanguagesDialog, setShowLanguagesDialog] = useState(false);

  const isSplit = splitLanguageSubjects.includes(propertySubject);
  const displayTag = languageTag ?? contentLanguage;

  const Trigger = useMemo(() => buildChipTrigger(displayTag), [displayTag]);

  const items = useMemo((): DropdownItem[] => {
    const options = Array.from(new Set([...(declared ?? []), contentLanguage]));

    return [
      ...options.map(tag => ({
        id: `language-${tag}`,
        label: `Language: ${tag}`,
        onClick: () => setContentLanguage(tag),
        icon: tag === contentLanguage ? <FaCheck /> : <FaLanguage />,
      })),
      {
        id: 'split-languages',
        label: isSplit ? 'Unsplit language columns' : 'Split by language',
        onClick: () => toggleSplitLanguages(propertySubject),
        icon: <FaTableColumns />,
      },
      {
        id: 'edit-languages',
        label: 'Edit languages…',
        onClick: () => setShowLanguagesDialog(true),
        icon: <FaLanguage />,
      },
    ];
  }, [
    declared,
    contentLanguage,
    setContentLanguage,
    isSplit,
    toggleSplitLanguages,
    propertySubject,
  ]);

  return (
    <>
      <DropdownMenu Trigger={Trigger} items={items} />
      <EditLanguagesDialog
        show={showLanguagesDialog}
        bindShow={setShowLanguagesDialog}
      />
    </>
  );
}

const buildChipTrigger = (label: string): DropdownTriggerComponent => {
  const Comp = ({
    onClick,
    menuId,
    isActive,
    ref,
    id,
  }: DropdownTriggerProps) => (
    <ChipButton
      id={id}
      aria-controls={menuId}
      aria-expanded={isActive}
      aria-haspopup='menu'
      onClick={onClick}
      ref={ref}
      title='Content language'
    >
      {label}
    </ChipButton>
  );

  Comp.DisplayName = /* @wc-ignore */ 'LanguageChipTrigger';

  return Comp;
};

const ChipButton = styled.button`
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.textLight};
  font-family: monospace;
  font-size: 0.75rem;
  padding: 0.1rem 0.35rem;
  cursor: pointer;

  &:hover,
  &[aria-expanded='true'] {
    background-color: ${p => p.theme.colors.bg2};
    color: ${p => p.theme.colors.text};
  }
`;
