import { PropsWithChildren } from 'react';
import { Row } from './Row';
import { styled } from 'styled-components';

interface OutlinedSectionProps {
  title: string;
}

export function OutlinedSection({
  title,
  children,
}: PropsWithChildren<OutlinedSectionProps>): JSX.Element {
  return (
    <SectionWrapper>
      <Heading>{title}</Heading>
      <Row wrapItems>{children}</Row>
    </SectionWrapper>
  );
}

const SectionWrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size()};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.size(6)};
  position: relative;
  margin-block-start: 0.5rem;
`;

const Heading = styled.h2`
  display: flex;
  align-items: center;
  font-size: 1rem;
  gap: 1ch;
  width: fit-content;
  padding-inline: ${p => p.theme.size()};
  color: ${p => p.theme.colors.textLight};
  font-weight: normal;
  margin: 0;
  background-color: ${p => p.theme.colors.bgBody};
  position: absolute;
  top: -0.5rem;
  left: ${p => p.theme.size()};
`;
