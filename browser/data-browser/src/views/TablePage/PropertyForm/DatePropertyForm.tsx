import { Datatype, core, dataBrowser, urls, useString } from '@tomic/react';
import { Suspense, useEffect, useState } from 'react';
import { Checkbox, CheckboxLabel } from '../../../components/forms/Checkbox';
import { DateFormatPicker } from './Inputs/DateFormatPicker';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export function DatePropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const [includeTime, setIncludeTime] = useState(
    resource.get(core.properties.datatype) === Datatype.TIMESTAMP,
  );
  const [dateFormat, setDateFormat] = useString(
    resource,
    urls.properties.constraints.dateFormat,
    { commit: true },
  );

  useEffect(() => {
    const type = includeTime ? Datatype.TIMESTAMP : Datatype.DATE;

    (async () => {
      await resource.set(core.properties.datatype, type);
      await resource.set(core.properties.isA, [
        dataBrowser.classes.formattedDate,
      ]);

      if (dateFormat === undefined) {
        await resource.set(
          dataBrowser.properties.dateFormat,
          urls.instances.dateFormats.localNumeric,
        );
      }
    })();
  }, [dateFormat, includeTime]);

  return (
    <Suspense>
      <CheckboxLabel>
        <Checkbox onChange={setIncludeTime} checked={includeTime} />
        Include Time
      </CheckboxLabel>

      <DateFormatPicker
        value={dateFormat}
        onChange={setDateFormat}
        withTime={includeTime}
      />
    </Suspense>
  );
}
