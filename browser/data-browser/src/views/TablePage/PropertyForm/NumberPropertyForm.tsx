import {
  Datatype,
  core,
  dataBrowser,
  urls,
  useNumber,
  useString,
} from '@tomic/react';
import { Suspense, lazy, useEffect } from 'react';
import { RadioGroup, RadioInput } from '../../../components/forms/RadioInput';
import { FormGroupHeading } from './FormGroupHeading';
import { DecimalPlacesInput } from './Inputs/DecimalPlacesInput';
import { TableRangeInput } from './Inputs/TableRangeInput';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

const { numberFormats } = urls.instances;
const CurrencyPicker = lazy(
  () => import('../../../chunks/CurrencyPicker/CurrencyPicker'),
);

export const NumberPropertyForm = ({
  resource,
}: PropertyCategoryFormProps): JSX.Element => {
  const [numberFormatting, setNumberFormatting] = useString(
    resource,
    dataBrowser.properties.numberFormatting,
  );

  const [decimalPlaces] = useNumber(
    resource,
    dataBrowser.properties.decimalPlaces,
  );

  const [_, setDataType] = useString(resource, core.properties.datatype);

  const handleNumberFormatChange = async (
    e: React.ChangeEvent<HTMLInputElement>,
  ) => {
    setNumberFormatting(e.target.value);

    if (e.target.value === numberFormats.currency) {
      await resource.addClasses(dataBrowser.classes.currencyProperty);
      await setDataType(Datatype.FLOAT);
    } else {
      await resource.removeClasses(dataBrowser.classes.currencyProperty);
      resource.removePropVal(dataBrowser.properties.currency);
    }
  };

  useEffect(() => {
    resource.addClasses(dataBrowser.classes.formattedNumber);

    // If decimal places is not set yet we assume it is a new property and should default to float.
    if (decimalPlaces === undefined) {
      resource.set(core.properties.datatype, Datatype.FLOAT);
    }

    if (numberFormatting === undefined) {
      setNumberFormatting(numberFormats.number);
    }
  }, []);

  return (
    <Suspense fallback={<div>loading...</div>}>
      <FormGroupHeading>Number Format</FormGroupHeading>
      <RadioGroup>
        <RadioInput
          name='number-format'
          value={numberFormats.number}
          checked={numberFormatting === numberFormats.number}
          onChange={handleNumberFormatChange}
        >
          Number
        </RadioInput>
        <RadioInput
          name='number-format'
          value={numberFormats.percentage}
          checked={numberFormatting === numberFormats.percentage}
          onChange={handleNumberFormatChange}
        >
          Percentage
        </RadioInput>
        <RadioInput
          name='number-format'
          value={numberFormats.currency}
          checked={numberFormatting === numberFormats.currency}
          onChange={handleNumberFormatChange}
        >
          Currency
        </RadioInput>
      </RadioGroup>
      {resource.hasClasses(dataBrowser.classes.currencyProperty) ? (
        <CurrencyPicker resource={resource} />
      ) : (
        <DecimalPlacesInput resource={resource} />
      )}
      <FormGroupHeading>Range</FormGroupHeading>
      <TableRangeInput
        resource={resource}
        minProp={dataBrowser.properties.min}
        maxProp={dataBrowser.properties.max}
        constraintClass={dataBrowser.classes.rangeProperty}
      />
    </Suspense>
  );
};
