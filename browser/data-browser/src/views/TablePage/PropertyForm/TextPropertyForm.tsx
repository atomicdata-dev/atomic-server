import { Datatype, urls, useStore } from '@tomic/react';
import React, { useState } from 'react';
import { RadioGroup, RadioInput } from '../../../components/forms/RadioInput';
import { FormGroupHeading } from './FormGroupHeading';
import { TableRangeInput } from './Inputs/TableRangeInput';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export const TextPropertyForm = ({
  resource,
}: PropertyCategoryFormProps): JSX.Element => {
  const store = useStore();
  const [textFormat, setTextFormat] = useState<Datatype>(Datatype.STRING);

  const handleTextFormatChange = async (
    e: React.ChangeEvent<HTMLInputElement>,
  ) => {
    setTextFormat(e.target.value as Datatype);

    await resource.set(urls.properties.datatype, e.target.value, store, false);
    await resource.save(store);
  };

  return (
    <>
      <FormGroupHeading>Text Format:</FormGroupHeading>
      <RadioGroup>
        <RadioInput
          name='text-format'
          value={Datatype.STRING}
          checked={textFormat === Datatype.STRING}
          onChange={handleTextFormatChange}
        >
          Plain text
        </RadioInput>
        <RadioInput
          name='text-format'
          value={Datatype.MARKDOWN}
          checked={textFormat === Datatype.MARKDOWN}
          onChange={handleTextFormatChange}
        >
          Rich text
        </RadioInput>
        <RadioInput
          name='text-format'
          value={Datatype.SLUG}
          checked={textFormat === Datatype.SLUG}
          onChange={handleTextFormatChange}
        >
          Slug
        </RadioInput>
      </RadioGroup>
      <FormGroupHeading>Length</FormGroupHeading>
      <TableRangeInput
        resource={resource}
        minProp={urls.properties.constraints.min}
        maxProp={urls.properties.constraints.max}
        constraintClass={urls.classes.constraintProperties.rangeProperty}
      />
    </>
  );
};
