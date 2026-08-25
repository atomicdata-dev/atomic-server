import { Resource, useResource, useTitle } from '@tomic/react';
import { useEffect, type JSX, type ReactNode } from 'react';
import { styled } from 'styled-components';
import { FaLinkSlash } from 'react-icons/fa6';
import toast from 'react-hot-toast';
import { Button } from '@components/Button';
import Field from '@components/forms/Field';
import { Column, Row } from '@components/Row';
import {
  clearOptionsSource,
  optionsSourceMode,
  sourceColumn,
  syncMirroredTags,
  type OptionsSource,
} from './optionsSource';

interface LinkedOptionsProps {
  /** The Property the field maps to — put back in charge of its own options
   * when the link is removed. */
  property: Resource;
  source: OptionsSource;
  label: string;
  /** The link button, rendered beside the label — same slot it occupies when
   * the options are the question's own. */
  labelAction: ReactNode;
  onUnlink: () => void;
}

/**
 * Replaces the option list of a choice question whose options come from
 * another table: there is nothing to edit here, because editing happens over
 * there.
 */
export function LinkedOptions({
  property,
  source,
  label,
  labelAction,
  onUnlink,
}: LinkedOptionsProps): JSX.Element {
  const table = useResource(source.table);
  const column = useResource(sourceColumn(source));
  const [tableTitle] = useTitle(table);
  const [columnTitle] = useTitle(column);

  const mode = optionsSourceMode(source);

  // The published list always comes from the source, but the response column
  // carries a snapshot of it (see `applyOptionsSource`). Refresh it whenever
  // this panel opens, so a tag added over there shows up in the table too.
  useEffect(() => {
    if (mode !== 'tags' || column.loading || property.loading) {
      return;
    }

    syncMirroredTags(property, column).catch(() => {
      // A read-only source column is a legitimate state; the published
      // options still resolve from it.
    });
  }, [mode, property, column]);

  const unlink = async () => {
    try {
      await clearOptionsSource(property);
      onUnlink();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Field label={label} labelAction={labelAction}>
      <LinkedBox gap='0.6rem'>
        <span data-testid='linked-options-summary'>
          Linked to <strong>{columnTitle}</strong> in{' '}
          <strong>{tableTitle}</strong>
        </span>
        <Explainer>
          {mode === 'tags'
            ? 'The options are that column’s tags. Add or rename them on the table.'
            : 'Every row of that table is an option, so answers link back to the row. The list follows the table.'}
        </Explainer>
        <Row>
          <Button subtle type='button' onClick={unlink}>
            <FaLinkSlash /> Unlink
          </Button>
        </Row>
      </LinkedBox>
    </Field>
  );
}

const LinkedBox = styled(Column)`
  background-color: ${p => p.theme.colors.bg1};
  border-radius: ${p => p.theme.radius};
  padding: 0.7rem;
`;

const Explainer = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
`;
