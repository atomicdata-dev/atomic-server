import type { ResourceInlineInstanceProps } from './ResourceInline';
import { Tag } from '../TablePage/PropertyForm/Tag';
import { styled } from 'styled-components';

export function TagInline({
  subject,
}: ResourceInlineInstanceProps): JSX.Element {
  return (
    <TagWrapper>
      <Tag subject={subject} />
    </TagWrapper>
  );
}

const TagWrapper = styled.span`
  display: inline-block;
  padding-block: 2px;
`;
