import { Resource } from '@tomic/react';
import type { JSX, ReactNode } from 'react';
import { FaLink } from 'react-icons/fa6';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import { useDialog } from '@components/Dialog';
import { TagListEditor } from './TagListEditor';
import { LinkedOptions } from './LinkedOptions';
import { LinkOptionsDialog } from './LinkOptionsDialog';
import { useOptionsSource } from './optionsSource';

interface LinkableTagListProps {
  field: Resource;
  /** The SelectProperty the field maps to. */
  property: Resource;
  label: string;
  addLabel: string;
  removeLabel: string;
  itemTestId?: string;
  /** See {@link TagListEditor} — only used while the options are the
   * question's own. */
  leading?: (tagSubject: string) => ReactNode;
  belowInput?: (tagSubject: string) => ReactNode;
}

/**
 * A choice question's options, in either of the two states they can be in:
 * the question's own editable list ({@link TagListEditor}), or a link to
 * another table's column ({@link LinkedOptions}). The button beside the label
 * moves between them.
 */
export function LinkableTagList({
  field,
  property,
  label,
  addLabel,
  removeLabel,
  itemTestId,
  leading,
  belowInput,
}: LinkableTagListProps): JSX.Element {
  const [source, setSource] = useOptionsSource(field);
  const [dialogProps, showDialog, closeDialog, isDialogOpen] = useDialog();

  const linkButton = (
    <IconButton
      variant={IconButtonVariant.Outline}
      color='textLight'
      type='button'
      size='0.7rem'
      title={source ? 'Change the linked table' : 'Link options to a table'}
      data-testid='link-options-button'
      onClick={showDialog}
    >
      <FaLink />
    </IconButton>
  );

  return (
    <>
      {source ? (
        <LinkedOptions
          property={property}
          source={source}
          label={label}
          labelAction={linkButton}
          onUnlink={() => setSource(undefined)}
        />
      ) : (
        <TagListEditor
          property={property}
          label={label}
          addLabel={addLabel}
          removeLabel={removeLabel}
          itemTestId={itemTestId}
          labelAction={linkButton}
          leading={leading}
          belowInput={belowInput}
        />
      )}
      {/* Mounted only while open: the dialog seeds its pickers from the
          current source when it mounts. */}
      {isDialogOpen && (
        <LinkOptionsDialog
          field={field}
          property={property}
          dialogProps={dialogProps}
          close={closeDialog}
        />
      )}
    </>
  );
}
