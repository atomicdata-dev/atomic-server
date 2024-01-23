import { Resource, useValue } from '@tomic/react';

import { BasicSelect } from './BasicSelect';

interface AtomicSelectInputProps {
  resource: Resource;
  property: string;
  options: {
    value: string;
    label: string;
  }[];
  commit?: boolean;
  onChange?: (value: string) => void;
}

type Props = AtomicSelectInputProps &
  Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'resource'>;

export function AtomicSelectInput({
  resource,
  property,
  options,
  commit = false,
  onChange,
  ...props
}: Props): JSX.Element {
  const [value, setValue] = useValue(resource, property, { commit });

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setValue(e.target.value);
    onChange?.(e.target.value);
  };

  return (
    <BasicSelect {...props} onChange={handleChange} value={value as string}>
      {options.map(option => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </BasicSelect>
  );
}
