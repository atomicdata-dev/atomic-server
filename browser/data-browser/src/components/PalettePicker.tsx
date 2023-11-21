import { styled } from 'styled-components';
import { transition } from '../helpers/transition';
import { Row } from './Row';

interface PalettePickerProps {
  palette: string[];
  onChange: (color: string) => void;
}

export function PalettePicker({
  palette,
  onChange,
}: PalettePickerProps): JSX.Element {
  const createHandleClick = (color: string) => () => onChange(color);

  return (
    <Row wrapItems>
      {palette.map(color => (
        <PaletteButton
          key={color}
          color={color}
          onClick={createHandleClick(color)}
        ></PaletteButton>
      ))}
    </Row>
  );
}

interface PaletteButtonProps {
  color: string;
}

const PaletteButton = styled.button<PaletteButtonProps>`
  background-color: ${({ color }) => color};
  border: none;
  height: 1.5rem;
  aspect-ratio: 1/1;
  border-radius: 50%;
  cursor: pointer;
  transform-origin: center;
  transition: ${transition('transform')};

  &:hover,
  &:focus {
    outline: none;
    transform: scale(1.3);
  }
`;
