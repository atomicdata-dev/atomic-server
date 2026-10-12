import type { JSX } from 'react';
import { styled } from 'styled-components';

interface AnswerListProps {
  answers: Array<string | number>;
  fieldType: string;
  /** Total answered — may exceed `answers.length` (server caps the sample). */
  answered: number;
}

/** Scrollable list of free-text / date answers. */
export function AnswerList({
  answers,
  fieldType,
  answered,
}: AnswerListProps): JSX.Element {
  return (
    <div>
      <List>
        {answers.map((answer, index) => (
          // Answers aren't unique; position is the only stable identity.
          // eslint-disable-next-line react/no-array-index-key
          <Item key={index}>{formatAnswer(answer, fieldType)}</Item>
        ))}
      </List>
      {answered > answers.length && (
        <TruncationNote>Showing first {answers.length} answers</TruncationNote>
      )}
    </div>
  );
}

function formatAnswer(answer: string | number, fieldType: string): string {
  if (fieldType === 'datetime' && typeof answer === 'number') {
    return new Date(answer).toLocaleString();
  }

  if (fieldType === 'date' && typeof answer === 'string') {
    const date = new Date(answer);

    if (!Number.isNaN(date.getTime())) {
      return date.toLocaleDateString();
    }
  }

  return `${answer}`;
}

const List = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 16rem;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
`;

const Item = styled.li`
  background: ${p => p.theme.colors.bg1};
  border-radius: ${p => p.theme.radius};
  padding: 0.4rem 0.6rem;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.text};
  overflow-wrap: anywhere;
  white-space: pre-wrap;
`;

const TruncationNote = styled.div`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  margin-top: 0.4rem;
`;
