import { PropsWithChildren } from 'react';
import { Row } from '../../components/Row';
import { styled } from 'styled-components';

interface ButtonSectionProps {
  title: string;
}

export function ButtonSection({
  title,
  children,
}: PropsWithChildren<ButtonSectionProps>): JSX.Element {
  return (
    <>
      <Heading>{title}</Heading>
      <Row wrapItems>{children}</Row>
    </>
  );
}

const Heading = styled.h2`
  display: flex;
  align-items: center;
  font-size: 1rem;
  gap: 1ch;
  width: 100%;
  color: ${({ theme }) => theme.colors.textLight};
  font-weight: normal;
  margin: 0;
  font-family: ${({ theme }) => theme.fontFamily};

  /* &::before,
  &::after {
    content: '';
    border-bottom: 1px solid ${({ theme }) => theme.colors.bg2};
    flex: 1;
  } */

  /* &::before {
    width: 1rem;
  }

  &::after {
  } */
`;
