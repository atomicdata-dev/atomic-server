import { classes } from '@tomic/react';
import { useMemo } from 'react';
import { FaList, FaTh } from 'react-icons/fa';
import { ButtonGroup } from '../../components/ButtonGroup';

export interface DisplayStyleButtonProps {
  displayStyle: string | undefined;
  onClick: (displayStyle: string) => void;
}

const { grid, list } = classes.displayStyles;

export function DisplayStyleButton({
  displayStyle,
  onClick,
}: DisplayStyleButtonProps): JSX.Element {
  const options = useMemo(
    () => [
      {
        icon: <FaList />,
        label: 'List View',
        value: list,
        checked: displayStyle === list,
      },
      {
        icon: <FaTh />,
        label: 'Grid View',
        value: grid,
        checked: displayStyle === grid,
      },
    ],
    [displayStyle],
  );

  return (
    <ButtonGroup options={options} name='display-style' onChange={onClick} />
  );
}
