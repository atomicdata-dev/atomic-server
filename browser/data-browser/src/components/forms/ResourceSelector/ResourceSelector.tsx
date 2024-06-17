import { useState, useMemo, memo } from 'react';
import { Dialog, useDialog } from '../../Dialog';
import { useDialogTreeContext } from '../../Dialog/dialogContext';
import { useSettings } from '../../../helpers/AppSettings';
import { css, styled } from 'styled-components';
import { NewFormDialog } from '../NewForm/NewFormDialog';
import { SearchBox } from '../SearchBox';
import { FaTrash } from 'react-icons/fa';
import { ErrorChip } from '../ErrorChip';
import { urls } from '@tomic/react';
import { SearchBoxButton } from '../SearchBox/SearchBoxButton';

export interface ResourceSelectorProps {
  /**
   * This callback is called when the Subject Changes. You can pass an Error
   * Handler as the second argument to set an error message. Take the second
   * argument of a `useString` hook and pass the setString part to this property
   */
  setSubject: (subject: string | undefined) => void;
  /** The value (URL of the Resource that is selected) */
  value?: string;
  /**
   * Whether a certain type of Class is required here. Pass the URL of the
   * class. Is used for constructing a list of options.
   */
  isA?: string;
  /** Only let the user select the following resources */
  allowsOnly?: string[];
  /** If true, the form will show an error if it is left empty. */
  required?: boolean;
  /** A function to remove this item. Only relevant in arrays. */
  handleRemove?: () => void;
  error?: Error;
  disabled?: boolean;
  autoFocus?: boolean;
  /** Is used when a new item is created using the ResourceSelector */
  parent?: string;
  hideCreateOption?: boolean;
  hideClearButton?: boolean;

  /** If true, this is the first item in a list, default=true*/
  first?: boolean;
  /** If true, this is the last item in a list, default=true*/
  last?: boolean;

  /** Some react node that is displayed in front of the text inside the input wrapper*/
  prefix?: React.ReactNode;
}

/**
 * Form field for selecting a single resource. Needs external subject &
 * setSubject properties
 */
export const ResourceSelector = memo(function ResourceSelector({
  required,
  setSubject,
  value,
  handleRemove,
  error,
  isA,
  disabled,
  parent,
  hideClearButton,
  hideCreateOption,
  first = true,
  last = true,
  prefix,
  allowsOnly,
}: ResourceSelectorProps): JSX.Element {
  const [dialogProps, showDialog, closeDialog, isDialogOpen] = useDialog();
  const [initialNewTitle, setInitialNewTitle] = useState('');
  const { drive } = useSettings();

  const { inDialog } = useDialogTreeContext();

  const handleCreateItem = useMemo(() => {
    if (hideCreateOption || !isA) {
      return undefined;
    }

    return (name: string) => {
      setInitialNewTitle(name);
      showDialog();
    };
  }, [hideCreateOption, setSubject, showDialog, isA]);

  return (
    <Wrapper first={first} last={last}>
      <StyledSearchBox
        prefix={prefix}
        value={value}
        onChange={setSubject}
        isA={isA}
        required={required}
        disabled={disabled}
        hideClearButton={hideClearButton}
        allowsOnly={allowsOnly}
        onCreateItem={handleCreateItem}
      >
        {handleRemove && !disabled && (
          <SearchBoxButton onClick={handleRemove} title='Remove' type='button'>
            <FaTrash />
          </SearchBoxButton>
        )}
      </StyledSearchBox>
      {error && <PositionedErrorChip>{error.message}</PositionedErrorChip>}
      {!inDialog && isA && (
        <Dialog {...dialogProps}>
          {isDialogOpen && (
            <NewFormDialog
              parent={parent || drive}
              classSubject={isA}
              closeDialog={closeDialog}
              initialProps={{
                [urls.properties.shortname]: initialNewTitle,
              }}
              onSave={setSubject}
            />
          )}
        </Dialog>
      )}
    </Wrapper>
  );
});

// We need Wrapper to be able to target this component.
const StyledSearchBox = styled(SearchBox)``;

const Wrapper = styled.div<{ first?: boolean; last?: boolean }>`
  --top-radius: ${p => (p.first ? p.theme.radius : 0)};
  --bottom-radius: ${p => (p.last ? p.theme.radius : 0)};

  flex: 1;
  max-width: 100%;
  position: relative;
  ${StyledSearchBox} {
    border-radius: 0;
  }

  & ${StyledSearchBox} {
    border-top-left-radius: var(--top-radius);
    border-top-right-radius: var(--top-radius);
    border-bottom-left-radius: var(--bottom-radius);
    border-bottom-right-radius: var(--bottom-radius);

    ${p =>
      !p.last &&
      css`
        border-bottom: none;
      `}
  }
`;

const PositionedErrorChip = styled(ErrorChip)`
  position: absolute;
  top: 2rem;
  z-index: 100;
`;
