import { styled } from 'styled-components';
import { Collapse } from '../Collapse';
import { FaCaretRight } from 'react-icons/fa';
import { transition } from '../../helpers/transition';
import { useState } from 'react';

interface SideBarPanelProps {
  title: string;
}

export function SideBarPanel({
  children,
  title,
}: React.PropsWithChildren<SideBarPanelProps>): JSX.Element {
  const [open, setOpen] = useState(true);

  return (
    <Wrapper>
      <DeviderButton onClick={() => setOpen(prev => !prev)}>
        <PanelDevider>
          <Arrow $open={open} />
          {title}
        </PanelDevider>
      </DeviderButton>
      <Collapse open={open}>{children}</Collapse>
    </Wrapper>
  );
}

export const PanelDevider = styled.h2`
  font-size: inherit;
  font-weight: normal;
  font-family: inherit;
  width: 100%;
  display: flex;
  align-items: center;
  gap: 1ch;
  color: ${p => p.theme.colors.text};

  margin-bottom: 0;

  &::before,
  &::after {
    content: '';
    flex: 1;
    border-top: 1px solid ${p => p.theme.colors.bg2};
  }

  cursor: pointer;
  &:hover,
  &:focus {
    &::before,
    &::after {
      border-color: ${p => p.theme.colors.text};
    }
  }
`;

const DeviderButton = styled.button`
  background: none;
  border: none;
  margin: 0;
  padding: 0;
`;

const Arrow = styled(FaCaretRight)<{ $open: boolean }>`
  transform: rotate(${p => (p.$open ? '90deg' : '0deg')});
  ${transition('transform')}
`;

const Wrapper = styled.div`
  width: 100%;
  max-height: fit-content;
  display: flex;
  flex-direction: column;
`;
