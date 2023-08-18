import * as React from 'react';
import { useState } from 'react';
import {
  properties,
  classes,
  useArray,
  useCanWrite,
  useResource,
  useServerSearch,
  useString,
} from '@tomic/react';
import { styled, css } from 'styled-components';
import { useHotkeys } from 'react-hotkeys-hook';

import { ResourceInline } from './ResourceInline';
import Markdown from '../components/datatypes/Markdown';
import ResourceCard from './Card/ResourceCard';
import { shortcuts } from '../components/HotKeyWrapper';
import { ErrorLook } from '../components/ErrorLook';

interface ElementShowProps {
  subject: string;
}

/** Shared between all elements */
export interface ElementEditPropsBase {
  /** Removes element from the Array */
  deleteElement: (i: number) => void;
  /** Position of the active Element */
  current?: number;
  /** Sets the position of the active Element */
  setCurrent: (i: number) => void;
  /** Changes the subject of a specific item in the array */
  setElementSubject: (i: number, subject: string) => void;
  /** Show a drag icon */
  canDrag: boolean;
}

interface ElementEditProps extends ElementEditPropsBase {
  subject: string;
  /** Position in the array of Elements */
  index?: number;
  active: boolean;
}

const searchChar = '/';
const helpChar = '?';
const linkChar = '[';
const headerChar = '#';

/** An element is a section inside document, such as a Paragraph, Header or Image */
export function ElementEdit({
  subject,
  deleteElement,
  index,
  setCurrent,
  setElementSubject: setElement,
  active,
  canDrag,
}: ElementEditProps): JSX.Element {
  const resource = useResource(subject, {
    // Prevents a race condition, see https://github.com/atomicdata-dev/atomic-data-browser/issues/189
    newResource: true,
  });
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [text, setText] = useString(resource, properties.description, {
    commit: true,
    handleValidationError: setErr,
    validate: false,
  });
  const [klass] = useArray(resource, properties.isA);
  const ref = React.useRef<HTMLTextAreaElement>(null);
  const [canWrite, canWriteErr] = useCanWrite(resource);

  /** If it is not a text element */
  const isAResource =
    klass.length > 0 && !klass.includes(classes.elements.paragraph);

  function handleOnChange(e: React.ChangeEvent<HTMLTextAreaElement>) {
    handleResize();
    setErr(undefined);
    setText(e.target.value);
  }

  /** Let the textarea grow */
  function handleResize() {
    if (ref.current?.style) {
      ref.current.style.height = '0';
      ref.current.style.height = ref.current.scrollHeight + 'px';
    }
  }

  /** Resize the text area when the text changes, or it is set to active */
  React.useEffect((): void => {
    handleResize();
  }, [ref, text, active]);

  /** Auto focus on select, move cursor to end */
  React.useEffect(() => {
    ref?.current?.focus();
    text && ref?.current?.setSelectionRange(text?.length, text?.length);
  }, [active]);

  /** Delete this element */
  useHotkeys(
    'backspace',
    e => {
      const isEmpty = text === '' || text === undefined;

      if ((active && isEmpty) || (active && isAResource)) {
        e.preventDefault();
        deleteElement(index!);
      }
    },
    // no keybaord events captured by ContentEditable
    {
      enableOnTags: ['TEXTAREA'],
      enabled: active,
    },
    [index, text, active],
  );

  useHotkeys(
    shortcuts.deleteLine,
    e => {
      if (active) {
        e.preventDefault();
        deleteElement(index!);
      }
    },
    {
      enableOnTags: ['TEXTAREA'],
      enabled: active,
    },
    [index, active],
  );

  function Err() {
    if (err?.message) {
      return <ErrorLook>{err.message}</ErrorLook>;
    } else if (active && !canWrite && canWriteErr) {
      return <ErrorLook>{canWriteErr}</ErrorLook>;
    } else {
      return null;
    }
  }

  if (isAResource) {
    return (
      <ElementWrapper
        canDrag={canDrag}
        tabIndex={0}
        className='element'
        active={active}
        onFocus={() => setCurrent(index!)}
        onBlur={() => setCurrent(-1)}
      >
        <ResourceCard subject={subject} />
        <Err />
      </ElementWrapper>
    );
  }

  if (!active) {
    return (
      <ElementWrapper
        canDrag={canDrag}
        tabIndex={0}
        active={active}
        onFocus={() => setCurrent(index!)}
        onBlur={() => setCurrent(-1)}
      >
        <Markdown text={text || ''} noMargin />
        <Err />
      </ElementWrapper>
    );
  }

  return (
    <ElementWrapper
      canDrag={canDrag}
      active={active}
      onClick={() => index && setCurrent(index)}
    >
      <ElementView
        canDrag={canDrag}
        data-test='element-input'
        className='element'
        active={active}
        ref={ref}
        onChange={handleOnChange}
        onFocus={() => setCurrent(index!)}
        onBlur={() => setCurrent(-1)}
        placeholder={`type something (try ${helpChar} or ${searchChar})`}
        // Not working, I think
        autoFocus={active}
        value={text ? text : ''}
      />
      {text?.startsWith(searchChar) && (
        <SearchWidget
          query={text.substring(1)}
          setElement={(s: string) => index && setElement(index, s)}
        />
      )}
      {text?.startsWith(helpChar) && (
        <HelperWidget
          query={text.substring(1)}
          setElement={(s: string) => index && setElement(index, s)}
        />
      )}
      {text?.startsWith(linkChar) && (
        <WidgetWrapper>
          <p>[link text](https://example.com)</p>
        </WidgetWrapper>
      )}
      {text?.startsWith(headerChar) && (
        <WidgetWrapper>
          <p># Big Header</p>
          <p>## Header</p>
          <p>### Smaller Header</p>
        </WidgetWrapper>
      )}
      <Err />
    </ElementWrapper>
  );
}

export function ElementShow({ subject }: ElementShowProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, properties.description);

  return (
    <ElementWrapper>
      <Markdown text={text || ''} noMargin />
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

  &:focus {
    ${ElementFocusStyle}
  }
`;

interface ElementViewProps {
  active?: boolean;
  canDrag?: boolean;
}

const ElementView = styled.textarea<ElementViewProps>`
  ${ElementTextStyle}
  border: none;
  width: 100%;
  resize: none;
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  padding: 0;
  margin-bottom: 0.5rem;
  &:focus {
    outline: none;
    ${ElementFocusStyle}
  }
`;

interface WidgetProps {
  // Input without the matched string / character
  query: string;
  setElement: (subject: string) => void;
}

/** Allows the user to search for Resources and include these as an Element. */
function SearchWidget({ query, setElement }: WidgetProps) {
  const { results } = useServerSearch(query);
  // The currently selected result
  const [index, setIndex] = useState(0);

  useHotkeys(
    'tab,enter',
    e => {
      e.preventDefault();
      results[index] && setElement(results[index]);
    },
    { enableOnTags: ['TEXTAREA'] },
    [],
  );

  useHotkeys(
    'left',
    e => {
      e.preventDefault();
      let next = index - 1;

      if (next < 0) {
        next = results.length - 1;
      }

      setIndex(index - 1);
    },
    { enableOnTags: ['TEXTAREA'] },
    [index],
  );

  useHotkeys(
    'right',
    e => {
      e.preventDefault();
      let next = index + 1;

      if (next > results.length - 1) {
        next = 0;
      }

      setIndex(index + 1);
    },
    { enableOnTags: ['TEXTAREA'] },
    [index],
  );

  if (query === '') {
    return (
      <WidgetWrapper>
        <p>Search something...</p>
      </WidgetWrapper>
    );
  }

  if (results.length === 0) {
    return (
      <WidgetWrapper>
        <p>No results</p>
      </WidgetWrapper>
    );
  }

  return (
    <WidgetWrapper>
      <p> (press tab to select, left / right to browse)</p>
      <p>
        <ResourceInline subject={results[index]} />
      </p>
    </WidgetWrapper>
  );
}

const WidgetWrapper = styled.div`
  position: absolute;
  top: 100%;
  right: 0;
  left: -1rem;
  border-radius: ${p => p.theme.radius};
  border: solid 1px ${p => p.theme.colors.bg2};
  padding: ${p => p.theme.margin}rem;
  padding-bottom: 0;
  background-color: ${p => p.theme.colors.bg1};
  backdrop-filter: blur(6px);
  opacity: 0.9;
  z-index: 1;
`;

function HelperWidget({ query }: WidgetProps) {
  return (
    <WidgetWrapper>
      {query && <Markdown text={query} />}
      <p>Try typing these:</p>
      <p>
        {'links: '}
        <code>[clickable link](https://example.com)</code>
      </p>
      <p>
        {'styling:'}
        <code>**bold** and _cursive_</code>
      </p>
      <p>
        {'headings:'}
        <code>## Header</code>
      </p>
    </WidgetWrapper>
  );
}
