import React, { useCallback, useId, useState } from 'react';
import styled from 'styled-components';

export interface ButtonGroupOption {
  label: string;
  icon: React.ReactNode;
  value: string;
  checked?: boolean;
}

export interface ButtonGroupProps {
  options: ButtonGroupOption[];
  name: string;
  onChange: (value: string) => void;
}

export function ButtonGroup({
  options,
  name,
  onChange,
}: ButtonGroupProps): JSX.Element {
  const [selected, setSelected] = useState(
    () => options.find(o => o.checked)?.value,
  );

  const handleChange = useCallback(
    (checked: boolean, value: string) => {
      if (checked) {
        onChange(value);
        setSelected(value);
      }
    },
    [onChange],
  );

  return (
    <Group>
      {options.map(option => (
        <ButtonGroupItem
          {...option}
          key={option.value}
          onChange={handleChange}
          checked={selected === option.value}
          name={name}
        />
      ))}
    </Group>
  );
}

interface ButtonGroupItemProps extends ButtonGroupOption {
  onChange: (checked: boolean, value: string) => void;
  name: string;
}

function ButtonGroupItem({
  onChange,
  icon,
  label,
  name,
  value,
  checked,
}: ButtonGroupItemProps): JSX.Element {
  const id = useId();

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onChange(event.target.checked, value);
  };

  return (
    <Item>
      <Input
        id={id}
        type='radio'
        onChange={handleChange}
        name={name}
        value={value}
        checked={checked}
      />
      <Label htmlFor={id} title={label}>
        {icon}
      </Label>
    </Item>
  );
}

const Group = styled.form`
  display: flex;
  height: 2rem;
  gap: 0.5rem;
`;

const Item = styled.div`
  position: relative;
  width: 2rem;
  aspect-ratio: 1/1;
`;

const Label = styled.label`
  position: absolute;
  inset: 0;
  width: 100%;
  aspect-ratio: 1/1;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: ${p => p.theme.radius};
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;

  transition: background-color 0.1s ease-in-out, color 0.1s ease-in-out;

  input:checked + & {
    background-color: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }

  :hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const Input = styled.input`
  position: absolute;
  inset: 0;
  width: 100%;
  aspect-ratio: 1/1;
  visibility: hidden;
`;
