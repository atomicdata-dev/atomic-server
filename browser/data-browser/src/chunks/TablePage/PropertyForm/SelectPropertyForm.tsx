import {
  Datatype,
  Resource,
  core,
  dataBrowser,
  getEffectiveConstraint,
  setClassConstraint,
  useArray,
  useEffectiveConstraint,
  useResource,
  useStore,
} from '@tomic/react';
import { useCallback, useContext, useEffect, type JSX } from 'react';
import { Row } from '@components/Row';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';
import { CreateTagRow, EditableTag } from '@components/Tag';
import { isContentAddressed } from '@helpers/propertyIdentity';
import { TablePageContext } from '../tablePageContext';
import { optionSubjects } from '../useColumnConstraint';

const valueOpts = {
  commit: false,
  validate: false,
};

function removeFromArray<T>(array: T[], item: T) {
  return array.filter(i => i !== item);
}

/**
 * The options of a select column. While the column is being created the
 * options only live on the draft (they become Tags and a class `enum` on
 * confirm). For an existing column they are the table class's `enum`, and
 * every change is saved to the class straight away, like the Tags themselves.
 */
export function SelectPropertyForm({
  resource,
  existingProperty,
}: PropertyCategoryFormProps): JSX.Element {
  const isDraft = !existingProperty;
  const store = useStore();
  const { tableClassSubject } = useContext(TablePageContext);
  const tableClass = useResource(tableClassSubject);

  const [draftOptions, setDraftOptions] = useArray(
    resource,
    core.properties.allowsOnly,
    valueOpts,
  );
  const constraint = useEffectiveConstraint(
    [tableClassSubject],
    isDraft ? undefined : resource.subject,
  );
  const options = isDraft ? draftOptions : optionSubjects(constraint);

  // The list as it is when a handler runs. A closure over the rendered list
  // makes several tags added in a row each start from the same stale one.
  const readOptions = useCallback(
    (): string[] =>
      isDraft
        ? ((resource.get(core.properties.allowsOnly) ?? []) as string[])
        : optionSubjects(
            getEffectiveConstraint(
              store,
              [tableClassSubject],
              resource.subject,
            ),
          ),
    [isDraft, resource, store, tableClassSubject],
  );

  const setOptions = useCallback(
    async (next: string[]) => {
      if (isDraft) {
        await setDraftOptions(next);

        return;
      }

      await setClassConstraint(tableClass, resource.subject, {
        enum: next.length > 0 ? next : undefined,
      });
      await tableClass.save();

      // A legacy property keeps its own list in step, for readers that
      // predate the class map. A content-addressed one is immutable.
      if (!isContentAddressed(resource.subject)) {
        await setDraftOptions(next);
        await resource.save();
      }
    },
    [resource, isDraft, tableClass, setDraftOptions],
  );

  const handleNewTag = useCallback(
    async (tag: Resource) => {
      // On a draft (new column) the tags are only seeds: the property does not
      // exist yet, and its tags are created under its final ID on confirm.
      if (!isDraft) {
        await tag.save();
      }

      await setOptions([...readOptions(), tag.subject]);
    },
    [readOptions, setOptions, isDraft],
  );

  const handleDeleteTag = useCallback(
    async (subject: string) => {
      await setOptions(removeFromArray(readOptions(), subject));

      if (!isDraft) {
        const tag = store.getResourceLoading(subject);
        tag.destroy();
      }
    },
    [store, isDraft, setOptions, readOptions],
  );

  useEffect(() => {
    // An existing select column already is one, and its Property is immutable.
    if (!isDraft) {
      return;
    }

    resource.addClasses(dataBrowser.classes.selectProperty);

    resource.set(core.properties.datatype, Datatype.RESOURCEARRAY);
    resource.set(core.properties.classtype, dataBrowser.classes.tag);
  }, []);

  return (
    <>
      <Row wrapItems>
        {options.map(tag => (
          <EditableTag subject={tag} key={tag} onDelete={handleDeleteTag} />
        ))}
      </Row>
      <CreateTagRow parent={resource.subject} onNewTag={handleNewTag} />
    </>
  );
}
