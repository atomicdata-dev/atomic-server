import { type JSX } from 'react';
import { useResource, dataBrowser, core } from '@tomic/react';
import { styled, css } from 'styled-components';

import Markdown from '../components/datatypes/Markdown';
import ResourceCard from './Card/ResourceCard';

interface ElementShowProps {
  subject: string;
}

export function ElementShow({ subject }: ElementShowProps): JSX.Element {
  const resource = useResource(subject);

  if (resource.hasClasses(dataBrowser.classes.paragraph)) {
    return (
      <ElementWrapper>
        <Markdown text={resource.get(core.properties.description) ?? ''} />
      </ElementWrapper>
    );
  }

  return (
    <ElementWrapper>
      <ResourceCard subject={subject} />
    </ElementWrapper>
  );
}

const ElementFocusStyle = css`
  border-radius: 5px;
  outline: none;
`;

const ElementTextStyle = css`
  line-height: 1.4rem;
  font-family: ${p => p.theme.fontFamily};
  font-size: ${p => p.theme.fontSizeBody}rem;
`;

const ElementWrapper = styled.div<ElementViewProps>`
  position: relative;
  display: block;
  width: 100%;
  border: none;
  resize: none;
  padding: 0.5rem;
  padding-left: 0rem;
  cursor: text;
  /* Maintain enters / newlines */
  white-space: pre-line;
  display: flex;
  flex-direction: column;
  /* Equal to the height of a line */
  min-height: 2.7rem;

  ${p => p.active && p.canDrag && ElementFocusStyle}

  ${ElementTextStyle}

  &:focus-visible {
    ${ElementFocusStyle}
  }
`;

interface ElementViewProps {
  active?: boolean;
  canDrag?: boolean;
}
