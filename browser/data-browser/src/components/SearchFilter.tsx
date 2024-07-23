import { useEffect, useState } from 'react';
import { core, urls, useArray, useProperty, useResource } from '@tomic/react';
import { ResourceSelector } from '../components/forms/ResourceSelector';

/**
 * Shows a Class selector to the user.
 * If a Class is selected, the filters for the required and recommended properties
 * of that Class are shown.
 */
export function ClassFilter({ filters, setFilters }): JSX.Element {
  const [klass, setClass] = useState<string | undefined>(undefined);
  const resource = useResource(klass);
  const [requiredProps] = useArray(resource, urls.properties.requires);
  const [recommendedProps] = useArray(resource, urls.properties.recommends);
  const allProps = [...requiredProps, ...recommendedProps];

  useEffect(() => {
    // Set the filters to the default values of the properties
    setFilters({
      ...filters,
      [core.properties.isA]: klass,
    });
  }, [klass, JSON.stringify(filters)]);

  return (
    <div>
      <ResourceSelector
        setSubject={setClass}
        value={klass}
        classType={core.classes.class}
      />
      {allProps?.map(propertySubject => (
        <PropertyFilter
          key={propertySubject}
          subject={propertySubject}
          filters={filters}
          setFilters={setFilters}
        />
      ))}
    </div>
  );
}

function PropertyFilter({ filters, setFilters, subject }): JSX.Element {
  const prop = useProperty(subject);

  function handleChange(e) {
    setFilters({
      ...filters,
      [prop.shortname]: e.target.value,
    });
  }

  return (
    <div>
      <label>{prop.shortname}</label>
      <input
        type='text'
        value={filters[prop.shortname]}
        onChange={handleChange}
      />
    </div>
  );
}
