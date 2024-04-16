import { Datatype, core, dataBrowser } from '@tomic/react';
import { useState } from 'react';
import { RadioGroup, RadioInput } from '../../../components/forms/RadioInput';
import { FormGroupHeading } from './FormGroupHeading';
import { TableRangeInput } from './Inputs/TableRangeInput';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export const TextPropertyForm = ({
  resource,
}: PropertyCategoryFormProps): JSX.Element => {
  const [textFormat, setTextFormat] = useState<Datatype>(Datatype.STRING);

  const handleTextFormatChange = async (
    e: React.ChangeEvent<HTMLInputElement>,
  ) => {
    setTextFormat(e.target.value as Datatype);

    await resource.set(core.properties.datatype, e.target.value, false);
    await resource.save();
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
        minProp={dataBrowser.properties.min}
        maxProp={dataBrowser.properties.max}
        constraintClass={dataBrowser.classes.rangeProperty}
      />
    </>
  );
};
