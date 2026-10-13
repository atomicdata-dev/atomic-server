import {
  Core,
  Resource,
  core,
  dataBrowser,
  urls,
  useArray,
  useProperty,
  useStore,
} from '@tomic/react';
import { FC, useEffect, useState } from 'react';
import { TabPanel, Tabs } from '../../../components/Tabs';
import { Column, Row } from '../../../components/Row';
import { LabelText } from '../LabelText';
import InputResourceArray from '../../../components/forms/InputResourceArray';
import { CreateTagRow, EditableTag, Tag } from '../../../components/Tag';
import { useEnumHandlers } from './useEnumHandlers';
import { filterAllowsOnly } from './filterAllowsOnly';

interface EnumFormPartProps {
  resource: Resource<Core.Property>;
  ontology: Resource<Core.Ontology>;
}

const tabs = [
  {
    label: 'Enum',
    value: 'enum',
  },
  {
    label: 'Custom',
    value: 'custom',
  },
];

export const EnumFormPart: FC<EnumFormPartProps> = ({ resource, ontology }) => {
  const allowsOnlyProp = useProperty(urls.properties.allowsOnly);

  return (
    <Tabs label='ResourceArray Types' tabs={tabs}>
      <>
        <TabPanel value='enum'>
          <TagPanel resource={resource} ontology={ontology} />
        </TabPanel>
        <TabPanel value='custom'>
          <Column>
            <LabelText>Allows Only</LabelText>
            <InputResourceArray resource={resource} property={allowsOnlyProp} />
          </Column>
        </TabPanel>
      </>
    </Tabs>
  );
};

interface TagPanelProps {
  resource: Resource<Core.Property>;
  ontology: Resource<Core.Ontology>;
}

const TagPanel: FC<TagPanelProps> = ({ resource, ontology }) => {
  const store = useStore();
  const [tags, setTags] = useState<string[]>([]);

  const [allowsOnly, setAllowsOnly] = useArray(
    resource,
    core.properties.allowsOnly,
    { commit: true },
  );
  const { addTag, removeTag } = useEnumHandlers(resource, ontology);

  useEffect(() => {
    // We filter out anything that is not a tag.
    filterAllowsOnly(resource, dataBrowser.classes.tag, store).then(
      filteredTags => {
        setTags(filteredTags ?? []);

        if (
          filteredTags === undefined ||
          filteredTags.length === allowsOnly.length
        ) {
          return;
        }

        setAllowsOnly(filteredTags);
      },
    );
  }, [resource, allowsOnly, setAllowsOnly]);

  return (
    <TagOptionsEditor
      tags={tags}
      parent={ontology.subject}
      onAdd={addTag}
      onRemove={removeTag}
    />
  );
};

interface TagOptionsEditorProps {
  tags: string[];
  /** The resource new tags are created under. */
  parent: string;
  onAdd: (tag: Resource) => void;
  onRemove: (subject: string) => void;
  disabled?: boolean;
}

/** The tags a value may be picked from, with a row to add more. */
export const TagOptionsEditor: FC<TagOptionsEditorProps> = ({
  tags,
  parent,
  onAdd,
  onRemove,
  disabled,
}) => (
  <Column>
    <p>Only allow its value to be selected from the following tags:</p>
    <Row wrapItems>
      {tags.map(tag =>
        disabled ? (
          <Tag subject={tag} key={tag} />
        ) : (
          <EditableTag subject={tag} key={tag} onDelete={onRemove} />
        ),
      )}
    </Row>
    {!disabled && <CreateTagRow parent={parent} onNewTag={onAdd} />}
  </Column>
);
