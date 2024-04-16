import { PropsWithChildren } from 'react';
import { FaTimes } from 'react-icons/fa';
import { styled } from 'styled-components';
import { IconButton } from '../../IconButton/IconButton';
import { Row } from '../../Row';

interface SelectedFileLayoutProps {
  title: string;
  helperText?: string;
  disabled?: boolean;
  onClear: () => void;
}

export function SelectedFileLayout({
  title,
  helperText,
  disabled,
  children,
  onClear,
}: PropsWithChildren<SelectedFileLayoutProps>): React.JSX.Element {
  return (
    <Wrapper>
      <Row>
        <Title>{title}</Title>
        {!disabled && (
          <IconButton title='clear' onClick={onClear}>
            <FaTimes />
          </IconButton>
        )}
      </Row>
      <PreviewWrapper>{children}</PreviewWrapper>
      {helperText && <Helper>{helperText}</Helper>}
    </Wrapper>
  );
}

const Title = styled.span`
  flex: 1;
`;

const Wrapper = styled.div`
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  width: min(100%, 20rem);
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const PreviewWrapper = styled.div`
  aspect-ratio: 1 / 1;
  width: 100%;
  display: grid;
  overflow: hidden;
  border-radius: ${p => p.theme.radius};
`;

const Helper = styled.p`
  color: ${p => p.theme.colors.textLight};
  margin: 0;
`;
