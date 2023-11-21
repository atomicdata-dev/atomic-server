import { useStore, urls, useString } from '@tomic/react';
import { Suspense, useEffect, useState } from 'react';
import { Checkbox, CheckboxLabel } from '../../../components/forms/Checkbox';
import { DateFormatPicker } from './Inputs/DateFormatPicker';
import { PropertyCategoryFormProps } from './PropertyCategoryFormProps';

export function DatePropertyForm({
  resource,
}: PropertyCategoryFormProps): JSX.Element {
  const store = useStore();
  const [includeTime, setIncludeTime] = useState(
    resource.get(urls.properties.datatype) === urls.datatypes.timestamp,
  );
  const [dateFormat, setDateFormat] = useString(
    resource,
    urls.properties.constraints.dateFormat,
    { commit: true },
  );

  useEffect(() => {
    const type = includeTime ? urls.datatypes.timestamp : urls.datatypes.date;

    (async () => {
      await resource.set(urls.properties.datatype, type, store);
      await resource.set(
        urls.properties.isA,
        [urls.classes.constraintProperties.formattedDate],
        store,
      );

      if (dateFormat === undefined) {
        await resource.set(
          urls.properties.constraints.dateFormat,
          urls.instances.dateFormats.localNumeric,
          store,
        );
      }
    })();
  }, [dateFormat, store, includeTime]);

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
