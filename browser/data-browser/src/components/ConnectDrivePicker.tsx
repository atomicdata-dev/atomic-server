import { useId } from 'react';
import { useResource } from '@tomic/react';
import { styled } from 'styled-components';
import { Card } from './Card';
import { Checkbox } from './forms/Checkbox';

/** The person's drives, each with a checkbox. Used when they let an app in. */
export function ConnectDrivePicker({
  subjects,
  selected,
  onToggle,
}: {
  subjects: string[];
  selected: string[];
  onToggle: (subject: string, on: boolean) => void;
}) {
  return (
    <Card>
      <List>
        {subjects.map(subject => (
          <DriveOption
            key={subject}
            subject={subject}
            checked={selected.includes(subject)}
            onChange={on => onToggle(subject, on)}
          />
        ))}
      </List>
    </Card>
  );
}

function DriveOption({
  subject,
  checked,
  onChange,
}: {
  subject: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) {
  const resource = useResource(subject);
  const id = useId();

  return (
    <Option>
      <Checkbox id={id} checked={checked} onChange={onChange} />
      <label htmlFor={id}>{resource.loading ? '…' : resource.title}</label>
    </Option>
  );
}

const List = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

const Option = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;

  label {
    cursor: pointer;
  }
`;
