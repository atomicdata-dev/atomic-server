import { MdTextFormat } from 'react-icons/md';
import { styled } from 'styled-components';
import { IconButton } from '@components/IconButton/IconButton';
import { useLocalStorage } from '@hooks/useLocalStorage';

const SHOW_TOOLBAR_KEY = 'atomic.rte.showToolbar';

/**
 * Whether the formatting toolbar above the document editor is shown. Hidden by
 * default; the choice is remembered per browser and applies to every document
 * and meeting. Kept out of the editor chunk so pages can use it without
 * loading the editor.
 */
export function useFormattingToolbarVisible(): [
  boolean,
  (visible: boolean) => void,
] {
  return useLocalStorage(SHOW_TOOLBAR_KEY, false);
}

/** Icon button that toggles the formatting toolbar. Place it next to a title. */
export function FormattingToolbarToggle(): React.JSX.Element {
  const [visible, setVisible] = useFormattingToolbarVisible();

  return (
    <ToggleWrapper>
      <IconButton
        title={visible ? 'Hide formatting toolbar' : 'Show formatting toolbar'}
        aria-pressed={visible}
        size='1.2rem'
        color={visible ? 'main' : 'textLight'}
        onClick={() => setVisible(!visible)}
      >
        <MdTextFormat />
      </IconButton>
    </ToggleWrapper>
  );
}

/**
 * A title with the toolbar toggle to its right. When the title leaves no room
 * (narrow phones), the toggle wraps onto its own right-aligned row.
 */
export const TitleRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  column-gap: ${p => p.theme.size(2)};

  & > :first-child {
    flex: 1 1 14rem;
    min-width: 0;
  }
`;

const ToggleWrapper = styled.div`
  flex: none;
  margin-left: auto;

  @media print {
    display: none;
  }
`;
