import { useState, useMemo, memo } from 'react';
import { Dialog, useDialog } from '../../Dialog';
import { useDialogTreeContext } from '../../Dialog/dialogContext';
import { useSettings } from '../../../helpers/AppSettings';
import { css, styled } from 'styled-components';
import { NewFormDialog } from '../NewForm/NewFormDialog';
import { SearchBox } from '../SearchBox';
import { FaTrash } from 'react-icons/fa';
import { SearchBoxButton } from '../SearchBox/SearchBoxButton';
import { useTitlePropOfClass } from './useTitlePropOfClass';
import {
  checkForInitialRequiredValue,
  useValidation,
} from '../formValidation/useValidation';

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

  /** Callback function to be called when the input loses focus */
  onBlur?: () => void;
}

const INVALID_RESOURCE_ERROR = 'Invalid Resource';

/**
 * Form field for selecting a single resource. Needs external subject &
 * setSubject properties
 */
export const ResourceSelector = memo(function ResourceSelector({
  required,
  setSubject,
  value,
  handleRemove,
  isA,
  disabled,
  parent,
  hideClearButton,
  hideCreateOption,
  first = true,
  last = true,
  prefix,
  allowsOnly,
  onBlur,
}: ResourceSelectorProps): JSX.Element {
  const [pickedSubject, setPickedSubject] = useState<string | undefined>();
  const [dialogProps, showDialog, closeDialog, isDialogOpen] = useDialog({
    onSuccess: () => {
      setSubject(pickedSubject);
    },
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, required),
  );

  const [initialNewTitle, setInitialNewTitle] = useState('');
  const { titleProp } = useTitlePropOfClass(isA);

  const { drive } = useSettings();

  const { inDialog } = useDialogTreeContext();

  const handleCreateItem = useMemo(() => {
    if (hideCreateOption || !isA) {
      return undefined;
    }

    return (name: string | undefined) => {
      if (name !== undefined) {
        setInitialNewTitle(name);
      }

      showDialog();
    };
  }, [hideCreateOption, showDialog, isA]);

  const handleSaveClick = (subject: string) => {
    setPickedSubject(subject);
    closeDialog(true);
    setError(undefined);
  };

  const handleResourceError = (hasError: boolean) => {
    if (hasError) {
      setError(INVALID_RESOURCE_ERROR);
    } else {
      if (error === INVALID_RESOURCE_ERROR) {
        setError(undefined);
      }
    }
  };

  const handleBlur = () => {
    setTouched();
    onBlur?.();
  };

  const handleSubjectChange = (subject: string | undefined) => {
    setSubject(subject);

    if (required) {
      setError(subject ? undefined : 'Required');
    }
  };

  return (
    <Wrapper first={first} last={last}>
      <StyledSearchBox
        prefix={prefix}
        value={value}
        isA={isA}
        required={required}
        disabled={disabled}
        hideClearButton={hideClearButton}
        allowsOnly={allowsOnly}
        visualError={error}
        onChange={handleSubjectChange}
        onCreateItem={!inDialog ? handleCreateItem : undefined}
        onClose={handleBlur}
        onResourceError={handleResourceError}
      >
        {handleRemove && !disabled && (
          <SearchBoxButton onClick={handleRemove} title='Remove' type='button'>
            <FaTrash />
          </SearchBoxButton>
        )}
      </StyledSearchBox>
      {!inDialog && isA && (
        <Dialog {...dialogProps} width='50rem'>
          {isDialogOpen && (
            <NewFormDialog
              parent={parent || drive}
              classSubject={isA}
              onCancel={() => closeDialog(false)}
              initialProps={
                titleProp
                  ? {
                      [titleProp]: initialNewTitle,
                    }
                  : undefined
              }
              onSaveClick={handleSaveClick}
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
