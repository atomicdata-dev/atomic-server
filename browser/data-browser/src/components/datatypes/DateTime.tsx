import React from 'react';

type Props = {
  date: Date;
};

/** Renders a Date value */
export function DateTime({ date }: Props): JSX.Element {
  return (
    <time dateTime={date.toISOString()}>
      {date.toLocaleDateString()} at {date.toLocaleTimeString()}
    </time>
  );
}
