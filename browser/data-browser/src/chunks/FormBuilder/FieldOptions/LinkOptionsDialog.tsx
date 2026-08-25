import {
  core,
  dataBrowser,
  Resource,
  useArray,
  useResource,
  useResources,
  useStore,
  useTitle,
} from '@tomic/react';
import { useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { Button } from '@components/Button';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  type InternalDialogProps,
} from '@components/Dialog';
import Field from '@components/forms/Field';
import { RadioInput } from '@components/forms/RadioInput';
import { ResourceSelector } from '@components/forms/ResourceSelector';
import { Column } from '@components/Row';
import { WarningBlock } from '@components/WarningBlock';
import {
  applyOptionsSource,
  sourceColumn,
  useOptionsSource,
} from './optionsSource';

interface LinkOptionsDialogProps {
  /** The FormField whose `optionsSource` this writes. */
  field: Resource;
  /** The Property the field maps to — rewired to match the picked column. */
  property: Resource;
  dialogProps: InternalDialogProps;
  close: (success?: boolean) => void;
}

/**
 * Picks the table (and the column of it) a choice question borrows its
 * options from.
 *
 * One picker covers both sourcing modes, because "which column" already
 * decides which one applies: a **select column** has a fixed set of tags, so
 * those become the options; any other column has a value per row, so the
 * *rows* become the options and that column labels them. See
 * `OptionsSourceMode`.
 */
export function LinkOptionsDialog({
  field,
  property,
  dialogProps,
  close,
}: LinkOptionsDialogProps): JSX.Element {
  const store = useStore();
  const [source, setSource] = useOptionsSource(field);

  const [tableSubject, setTableSubject] = useState<string | undefined>(
    source?.table,
  );
  const [columnSubject, setColumnSubject] = useState<string | undefined>(
    source && sourceColumn(source),
  );
  const [saving, setSaving] = useState(false);

  const table = useResource(tableSubject);
  const rowClass = useResource(
    table.get(core.properties.classtype) as string | undefined,
  );

  const [required] = useArray(rowClass, core.properties.requires);
  const [recommended] = useArray(rowClass, core.properties.recommends);

  // A question cannot source from the column it writes to — that would just be
  // its own options, one indirection later.
  const columnSubjects = useMemo(
    () => [...required, ...recommended].filter(s => s !== property.subject),
    [required, recommended, property.subject],
  );
  const columns = useResources(columnSubjects);

  // Picking another table invalidates the column choice — derived rather than
  // reset in an effect, so there is no render where the two disagree.
  const picked =
    columnSubject && columnSubjects.includes(columnSubject)
      ? columnSubject
      : undefined;
  const column = picked ? columns.get(picked) : undefined;
  const isTagColumn =
    column?.hasClasses(dataBrowser.classes.selectProperty) ?? false;

  const save = async () => {
    if (!column) return;

    setSaving(true);

    try {
      setSource(await applyOptionsSource(store, property, table, column));
      close(true);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog {...dialogProps}>
      <DialogTitle>
        <h2>Link options to a table</h2>
      </DialogTitle>
      <DialogContent>
        <Column gap='1rem'>
          <Field
            label='Table'
            helper='The table these options come from.'
            helperAlwaysVisible
          >
            <ResourceSelector
              isA={dataBrowser.classes.table}
              value={tableSubject}
              setSubject={setTableSubject}
              hideCreateOption
            />
          </Field>

          {tableSubject && (
            <Field
              label='Column'
              helper='A select column contributes its tags. Any other column turns each row into an option, labelled by that column.'
              helperAlwaysVisible
              multiInput
            >
              {columnSubjects.length === 0 ? (
                <Explainer>This table has no columns to link to.</Explainer>
              ) : (
                <Column gap='0.5rem'>
                  {columnSubjects.map(subject => (
                    <ColumnChoice
                      key={subject}
                      subject={subject}
                      checked={subject === picked}
                      onPick={() => setColumnSubject(subject)}
                    />
                  ))}
                </Column>
              )}
            </Field>
          )}

          {column && !isTagColumn && (
            <WarningBlock>
              <WarningBlock.Title>This publishes the rows</WarningBlock.Title>
              Everyone who opens this form sees every row of{' '}
              <strong>{table.title}</strong> as an option. Only link a table
              whose contents you are happy to make public.
            </WarningBlock>
          )}
        </Column>
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => close(false)}>
          Cancel
        </Button>
        <Button
          onClick={save}
          disabled={!column || saving}
          data-testid='link-options-confirm'
        >
          Link options
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function ColumnChoice({
  subject,
  checked,
  onPick,
}: {
  subject: string;
  checked: boolean;
  onPick: () => void;
}): JSX.Element {
  const column = useResource(subject);
  const [title] = useTitle(column);
  const isTagColumn = column.hasClasses(dataBrowser.classes.selectProperty);

  return (
    <RadioInput
      name='options-source-column'
      value={subject}
      checked={checked}
      onChange={onPick}
      data-testid='link-options-column'
    >
      <Column gap='0.1rem'>
        <span>{title}</span>
        <Explainer>
          {isTagColumn
            ? 'Use its tags as the options'
            : 'Use each row, labelled by this column'}
        </Explainer>
      </Column>
    </RadioInput>
  );
}

const Explainer = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
`;
